package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/go-sql-driver/mysql"
)

const (
	mariadbSocketPath = "/run/mysqld/mysqld.sock"
	mariadbBackupRoot = "/var/backups/tompanel/databases"
	mysqldumpBinary   = "/usr/bin/mysqldump"
	mariadbClient     = "/usr/bin/mariadb"
)

// mariadbEnvironment carries every privileged effect so tests can verify the
// SQL and command surface without a live MariaDB.
type mariadbEnvironment struct {
	socketPath string
	backupRoot string
	exec       func(ctx context.Context, query string) error
	execAs     func(ctx context.Context, username, password, database, query string) error
	dump       func(ctx context.Context, database, outPath string) error
	restore    func(ctx context.Context, database, inPath string) error
}

func defaultMariaDBEnvironment() mariadbEnvironment {
	socket := mariadbSocketPath
	open := func(username, password, database string) (*sql.DB, error) {
		config := mysql.NewConfig()
		config.Net, config.Addr, config.User, config.Passwd, config.DBName = "unix", socket, username, password, database
		config.AllowNativePasswords = true
		db, err := sql.Open("mysql", config.FormatDSN())
		if err != nil {
			return nil, err
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, err
		}
		return db, nil
	}
	return mariadbEnvironment{
		socketPath: socket,
		backupRoot: mariadbBackupRoot,
		exec: func(ctx context.Context, query string) error {
			db, err := open("root", "", "")
			if err != nil {
				return fmt.Errorf("connect mariadb as administrator: %w", err)
			}
			defer db.Close()
			_, err = db.ExecContext(ctx, query)
			return err
		},
		execAs: func(ctx context.Context, username, password, database, query string) error {
			db, err := open(username, password, database)
			if err != nil {
				return err
			}
			defer db.Close()
			_, err = db.ExecContext(ctx, query)
			return err
		},
		dump: func(ctx context.Context, database, outPath string) error {
			command := exec.CommandContext(ctx, mysqldumpBinary,
				"--no-defaults", "--socket="+socket, "--user=root",
				"--single-transaction", "--routines", "--triggers", database)
			output, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer output.Close()
			command.Stdout = output
			if message, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("mysqldump: %s: %w", strings.TrimSpace(string(message)), err)
			}
			return output.Close()
		},
		restore: func(ctx context.Context, database, inPath string) error {
			input, err := os.Open(inPath)
			if err != nil {
				return err
			}
			defer input.Close()
			command := exec.CommandContext(ctx, mariadbClient,
				"--no-defaults", "--socket="+socket, "--user=root", database)
			command.Stdin = input
			if message, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("mariadb restore: %s: %w", strings.TrimSpace(string(message)), err)
			}
			return nil
		},
	}
}

type mariadbDatabaseInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type mariadbRotateInput struct {
	SiteID         string `json:"site_id"`
	Database       string `json:"database"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	RetireUsername string `json:"retire_username,omitempty"`
}

type mariadbCredentialInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type mariadbRestoreInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Path     string `json:"path"`
}

type mariadbDumpResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type mariadbDropInput struct {
	SiteID    string   `json:"site_id"`
	Database  string   `json:"database"`
	Usernames []string `json:"usernames"`
}

var (
	databaseNamePattern  = regexp.MustCompile(`^tp_[0-9a-f]{16}_[a-z0-9_]{1,16}$`)
	databaseUserPattern  = regexp.MustCompile(`^tp_[0-9a-f]{16}_u[0-9]{1,2}$`)
	siteScopedGrants = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES, LOCK TABLES, CREATE TEMPORARY TABLES"
)

func validateDatabaseOwned(siteID, database string) error {
	if !databases.ValidSiteID(siteID) {
		return errors.New("site id is invalid")
	}
	expected, err := databases.SitePrefix(siteID)
	if err != nil || !strings.HasPrefix(database, expected+"_") || !databaseNamePattern.MatchString(database) {
		return errors.New("database is not owned by this site")
	}
	return nil
}

func validateSiteUser(siteID, username string) error {
	if !databases.ValidSiteID(siteID) {
		return errors.New("site id is invalid")
	}
	expected, err := databases.SitePrefix(siteID)
	if err != nil || !strings.HasPrefix(username, expected+"_") || !databaseUserPattern.MatchString(username) {
		return errors.New("database user is not owned by this site")
	}
	return nil
}

func ensureMariaDBDatabase(ctx context.Context, input mariadbDatabaseInput, env mariadbEnvironment) error {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return err
	}
	if err := validateSiteUser(input.SiteID, input.Username); err != nil {
		return err
	}
	if err := databases.ValidatePassword(input.Password); err != nil {
		return err
	}
	user := mariadbUserSpec(input.Username)
	statements := []string{
		"CREATE DATABASE IF NOT EXISTS " + databases.QuoteIdentifier(input.Database) + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE USER IF NOT EXISTS " + user + " IDENTIFIED BY " + databases.QuoteString(input.Password),
		"ALTER USER " + user + " IDENTIFIED BY " + databases.QuoteString(input.Password),
		"GRANT " + siteScopedGrants + " ON " + databases.QuoteIdentifier(input.Database) + ".* TO " + user,
	}
	for _, statement := range statements {
		if err := env.exec(ctx, statement); err != nil {
			return fmt.Errorf("ensure database: %w", err)
		}
	}
	return nil
}

func rotateMariaDBUser(ctx context.Context, input mariadbRotateInput, env mariadbEnvironment) error {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return err
	}
	if err := validateSiteUser(input.SiteID, input.Username); err != nil {
		return err
	}
	if err := databases.ValidatePassword(input.Password); err != nil {
		return err
	}
	user := mariadbUserSpec(input.Username)
	if err := env.exec(ctx, "CREATE USER IF NOT EXISTS "+user+" IDENTIFIED BY "+databases.QuoteString(input.Password)); err != nil {
		return fmt.Errorf("create replacement user: %w", err)
	}
	if err := env.exec(ctx, "ALTER USER "+user+" IDENTIFIED BY "+databases.QuoteString(input.Password)); err != nil {
		return fmt.Errorf("set replacement password: %w", err)
	}
	if err := env.exec(ctx, "GRANT "+siteScopedGrants+" ON "+databases.QuoteIdentifier(input.Database)+".* TO "+user); err != nil {
		return fmt.Errorf("grant replacement user: %w", err)
	}
	if input.RetireUsername != "" {
		if err := validateSiteUser(input.SiteID, input.RetireUsername); err != nil {
			return err
		}
		if input.RetireUsername == input.Username {
			return errors.New("cannot retire the replacement user itself")
		}
		if err := env.exec(ctx, "DROP USER IF EXISTS "+mariadbUserSpec(input.RetireUsername)); err != nil {
			return fmt.Errorf("retire previous user: %w", err)
		}
	}
	return nil
}

func verifyMariaDBCredential(ctx context.Context, input mariadbCredentialInput, env mariadbEnvironment) error {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return err
	}
	if err := validateSiteUser(input.SiteID, input.Username); err != nil {
		return err
	}
	if err := databases.ValidatePassword(input.Password); err != nil {
		return err
	}
	return env.execAs(ctx, input.Username, input.Password, input.Database, "SELECT 1")
}

func dumpMariaDBDatabase(ctx context.Context, input mariadbDatabaseInput, env mariadbEnvironment) (mariadbDumpResult, error) {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return mariadbDumpResult{}, err
	}
	if err := os.MkdirAll(filepath.Join(env.backupRoot, input.SiteID), 0o750); err != nil {
		return mariadbDumpResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	root, err := os.OpenRoot(env.backupRoot)
	if err != nil {
		return mariadbDumpResult{}, err
	}
	defer root.Close()
	name := fmt.Sprintf("%s-%d.sql", input.Database, time.Now().UTC().Unix())
	relative := filepath.Join(input.SiteID, name)
	temporary := filepath.Join(input.SiteID, "."+name+".partial")
	if err := root.MkdirAll(input.SiteID, 0o750); err != nil {
		return mariadbDumpResult{}, err
	}
	if err := env.dump(ctx, input.Database, filepath.Join(env.backupRoot, temporary)); err != nil {
		_ = root.Remove(temporary)
		return mariadbDumpResult{}, err
	}
	if err := root.Rename(temporary, relative); err != nil {
		_ = root.Remove(temporary)
		return mariadbDumpResult{}, err
	}
	handle, err := root.Open(relative)
	if err != nil {
		return mariadbDumpResult{}, err
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, handle)
	handle.Close()
	if err != nil {
		return mariadbDumpResult{}, err
	}
	return mariadbDumpResult{
		Path:   filepath.Join(env.backupRoot, relative),
		Size:   size,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func restoreMariaDBDatabase(ctx context.Context, input mariadbRestoreInput, env mariadbEnvironment) error {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return err
	}
	if !confinedDatabaseBackup(env.backupRoot, input.SiteID, input.Path) {
		return errors.New("restore payload is invalid")
	}
	if err := env.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+databases.QuoteIdentifier(input.Database)+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		return err
	}
	return env.restore(ctx, input.Database, input.Path)
}

func dropMariaDBDatabase(ctx context.Context, input mariadbDropInput, env mariadbEnvironment) error {
	if err := validateDatabaseOwned(input.SiteID, input.Database); err != nil {
		return err
	}
	for _, username := range input.Usernames {
		if err := validateSiteUser(input.SiteID, username); err != nil {
			return err
		}
	}
	if err := env.exec(ctx, "DROP DATABASE IF EXISTS "+databases.QuoteIdentifier(input.Database)); err != nil {
		return fmt.Errorf("drop database: %w", err)
	}
	for _, username := range input.Usernames {
		if err := env.exec(ctx, "DROP USER IF EXISTS "+mariadbUserSpec(username)); err != nil {
			return fmt.Errorf("drop database user: %w", err)
		}
	}
	return nil
}

func confinedDatabaseBackup(root, siteID, path string) bool {
	want := filepath.Join(root, siteID) + string(os.PathSeparator)
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, want) && strings.HasSuffix(clean, ".sql")
}

// mariadbUserSpec renders a quoted MariaDB account specification.
func mariadbUserSpec(username string) string {
	return databases.QuoteString(username) + "@" + databases.QuoteString("localhost")
}
