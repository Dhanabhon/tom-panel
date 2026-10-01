package databases

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

// PHPMyAdminMode selects how the phpMyAdmin endpoint is exposed.
type PHPMyAdminMode string

const (
	ModePrivate         PHPMyAdminMode = "private"
	ModePublicSubdomain PHPMyAdminMode = "public_subdomain"
	ModePublicPort      PHPMyAdminMode = "public_port"
)

var (
	ErrDatabaseNotFound  = errors.New("database not found")
	ErrBackupNotFound    = errors.New("database backup not found")
	ErrEndpointNotFound  = errors.New("phpmyadmin endpoint not found")
	ErrPortUnavailable   = errors.New("requested port is already in use")
	ErrSuffixTaken       = errors.New("database suffix already exists")
	credentialAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	credentialLength     = 28
	privatePortFirst     = 8100
	privatePortLast      = 8199
)

// Database is one site-scoped MariaDB database.
type Database struct {
	ID               string
	SiteID           string
	Name             string
	Suffix           string
	State            string
	ActiveGeneration int
	PasswordSet      bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Credential is a one-time database credential reveal.
type Credential struct {
	Username string
	Password string
	Database string
}

// Backup records one dump produced by the agent.
type Backup struct {
	ID        string
	Database  string
	Suffix    string
	AgentPath string
	SizeBytes int64
	SHA256    string
	CreatedAt time.Time
}

// Endpoint is the phpMyAdmin exposure configuration of a site.
type Endpoint struct {
	SiteID       string
	Mode         PHPMyAdminMode
	Hostname     string
	Port         int
	BasicAuthSet bool
	BasicUser    string
}

// AppConfigUpdater applies new database credentials to a managed application.
// WordPress wiring arrives with the applications slice; nil disables it.
type AppConfigUpdater func(ctx context.Context, siteID, database, username, password string) error

// Service owns site-scoped MariaDB resources and phpMyAdmin endpoints.
type Service struct {
	store     *store.Store
	now       func() time.Time
	agentCall func(ctx context.Context, operation string, input, output any) error
	appConfig AppConfigUpdater
}

// NewService builds the databases service.
func NewService(database *store.Store, agentCaller func(ctx context.Context, operation string, input, output any) error) *Service {
	call := agentCaller
	if call == nil {
		call = func(context.Context, string, any, any) error {
			return errors.New("privileged agent is unavailable")
		}
	}
	return &Service{store: database, now: time.Now, agentCall: call}
}

// SetAppConfigUpdater installs the managed-application credential hook.
func (s *Service) SetAppConfigUpdater(updater AppConfigUpdater) { s.appConfig = updater }

// AuditEvent records who performed a direct database mutation.
type AuditEvent struct {
	AdminID int64
	Action  string
	Detail  json.RawMessage
}

// WriteAudit records a direct (non-job) database mutation.
func (s *Service) WriteAudit(ctx context.Context, siteID string, audit AuditEvent) error {
	if audit.AdminID < 1 || audit.Action == "" {
		return errors.New("audit administrator and action are required")
	}
	detail := audit.Detail
	if len(detail) == 0 || !json.Valid(detail) {
		detail = json.RawMessage(`{}`)
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(admin_id, action, target_kind, target_id, detail_json, created_at)
			VALUES (?, ?, 'database', ?, ?, ?)`, audit.AdminID, audit.Action, siteID, []byte(detail), s.now().UTC().Unix())
		return err
	})
}

// Create provisions one database plus its first credential generation.
func (s *Service) Create(ctx context.Context, siteID, suffix string) (Database, Credential, error) {
	name, err := DatabaseName(siteID, suffix)
	if err != nil {
		return Database{}, Credential{}, err
	}
	if _, err := s.bySuffix(ctx, siteID, suffix); err == nil {
		return Database{}, Credential{}, ErrSuffixTaken
	} else if !errors.Is(err, ErrDatabaseNotFound) {
		return Database{}, Credential{}, err
	}
	username, err := UserName(siteID, 1)
	if err != nil {
		return Database{}, Credential{}, err
	}
	password, err := generateCredential()
	if err != nil {
		return Database{}, Credential{}, err
	}
	if err := s.agentCall(ctx, "mariadb.ensure_database", struct {
		SiteID   string `json:"site_id"`
		Database string `json:"database"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{siteID, name, username, password}, &struct{}{}); err != nil {
		return Database{}, Credential{}, err
	}
	record, err := s.insertDatabase(ctx, siteID, name, suffix)
	if err != nil {
		return Database{}, Credential{}, err
	}
	if err := s.insertCredentialRow(ctx, record.ID, username, 1); err != nil {
		return Database{}, Credential{}, err
	}
	return record, Credential{Username: username, Password: password, Database: name}, nil
}

// RotateCredential provisions the next credential generation, verifies it,
// optionally updates the managed application, and only then retires the
// previous user so a failed health check keeps the old credential working.
func (s *Service) RotateCredential(ctx context.Context, siteID, suffix string, updateApp bool) (Credential, error) {
	record, err := s.bySuffix(ctx, siteID, suffix)
	if err != nil {
		return Credential{}, err
	}
	generation := record.ActiveGeneration + 1
	username, err := UserName(siteID, generation)
	if err != nil {
		return Credential{}, err
	}
	previous, err := UserName(siteID, record.ActiveGeneration)
	if err != nil {
		return Credential{}, err
	}
	password, err := generateCredential()
	if err != nil {
		return Credential{}, err
	}
	createInput := struct {
		SiteID   string `json:"site_id"`
		Database string `json:"database"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{siteID, record.Name, username, password}
	if err := s.agentCall(ctx, "mariadb.rotate_user", createInput, &struct{}{}); err != nil {
		return Credential{}, err
	}
	if updateApp && s.appConfig != nil {
		if err := s.appConfig(ctx, siteID, record.Name, username, password); err != nil {
			return Credential{}, fmt.Errorf("update managed application: %w", err)
		}
	}
	if err := s.agentCall(ctx, "mariadb.verify_credential", createInput, &struct{}{}); err != nil {
		return Credential{}, fmt.Errorf("verify replacement credential: %w", err)
	}
	if err := s.agentCall(ctx, "mariadb.rotate_user", struct {
		SiteID         string `json:"site_id"`
		Database       string `json:"database"`
		Username       string `json:"username"`
		Password       string `json:"password"`
		RetireUsername string `json:"retire_username,omitempty"`
	}{siteID, record.Name, username, password, previous}, &struct{}{}); err != nil {
		return Credential{}, err
	}
	if err := s.insertCredentialRow(ctx, record.ID, username, generation); err != nil {
		return Credential{}, err
	}
	if err := s.retireCredentialRows(ctx, record.ID, generation); err != nil {
		return Credential{}, err
	}
	return Credential{Username: username, Password: password, Database: record.Name}, nil
}

// Backup dumps one database through the agent and records the result.
func (s *Service) Backup(ctx context.Context, siteID, suffix string) (Backup, error) {
	record, err := s.bySuffix(ctx, siteID, suffix)
	if err != nil {
		return Backup{}, err
	}
	var result struct {
		Path   string `json:"path"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	if err := s.agentCall(ctx, "mariadb.dump", struct {
		SiteID   string `json:"site_id"`
		Database string `json:"database"`
	}{siteID, record.Name}, &result); err != nil {
		return Backup{}, err
	}
	id, err := newID()
	if err != nil {
		return Backup{}, err
	}
	backup := Backup{ID: id, Database: record.Name, Suffix: record.Suffix, AgentPath: result.Path, SizeBytes: result.Size, SHA256: result.SHA256, CreatedAt: s.now().UTC().Truncate(time.Second)}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO database_backups(id, database_id, agent_path, size_bytes, sha256, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, backup.ID, record.ID, backup.AgentPath, backup.SizeBytes, backup.SHA256, backup.CreatedAt.Unix())
		return err
	})
	if err != nil {
		return Backup{}, err
	}
	return backup, nil
}

// Restore loads one recorded dump back into its database.
func (s *Service) Restore(ctx context.Context, siteID, suffix, backupID string) error {
	record, err := s.bySuffix(ctx, siteID, suffix)
	if err != nil {
		return err
	}
	var path string
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT agent_path FROM database_backups WHERE id = ? AND database_id = ?`, backupID, record.ID).Scan(&path)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBackupNotFound
	}
	if err != nil {
		return err
	}
	return s.agentCall(ctx, "mariadb.restore", struct {
		SiteID   string `json:"site_id"`
		Database string `json:"database"`
		Path     string `json:"path"`
	}{siteID, record.Name, path}, &struct{}{})
}

// Delete removes the database, its users, and its recorded backups.
func (s *Service) Delete(ctx context.Context, siteID, suffix string) error {
	record, err := s.bySuffix(ctx, siteID, suffix)
	if err != nil {
		return err
	}
	var usernames []string
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT username FROM database_credentials WHERE database_id = ?`, record.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var username string
			if err := rows.Scan(&username); err != nil {
				return err
			}
			usernames = append(usernames, username)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	if err := s.agentCall(ctx, "mariadb.drop_database", struct {
		SiteID    string   `json:"site_id"`
		Database  string   `json:"database"`
		Usernames []string `json:"usernames"`
	}{siteID, record.Name, usernames}, &struct{}{}); err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM databases WHERE id = ?", record.ID)
		return err
	})
}

// List returns the databases of a site.
func (s *Service) List(ctx context.Context, siteID string) ([]Database, error) {
	var result []Database
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at
			FROM databases WHERE site_id = ? ORDER BY created_at, id`, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record Database
			var createdAt, updatedAt int64
			if err := rows.Scan(&record.ID, &record.SiteID, &record.Name, &record.Suffix, &record.State, &record.ActiveGeneration, &record.PasswordSet, &createdAt, &updatedAt); err != nil {
				return err
			}
			record.CreatedAt, record.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
			result = append(result, record)
		}
		return rows.Err()
	})
	return result, err
}

// ListBackups returns recorded dumps for one database.
func (s *Service) ListBackups(ctx context.Context, siteID, suffix string) ([]Backup, error) {
	record, err := s.bySuffix(ctx, siteID, suffix)
	if err != nil {
		return nil, err
	}
	var result []Backup
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT b.id, b.agent_path, b.size_bytes, b.sha256, b.created_at
			FROM database_backups b WHERE b.database_id = ? ORDER BY b.created_at DESC, b.id DESC LIMIT 50`, record.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var backup Backup
			var createdAt int64
			if err := rows.Scan(&backup.ID, &backup.AgentPath, &backup.SizeBytes, &backup.SHA256, &createdAt); err != nil {
				return err
			}
			backup.Database, backup.Suffix = record.Name, record.Suffix
			backup.CreatedAt = time.Unix(createdAt, 0).UTC()
			result = append(result, backup)
		}
		return rows.Err()
	})
	return result, err
}

// ConfigurePHPMyAdmin installs the shared phpMyAdmin copy on first use and
// activates the site endpoint in the requested mode.
func (s *Service) ConfigurePHPMyAdmin(ctx context.Context, siteID string, mode PHPMyAdminMode, hostname string, port int) (Endpoint, Credential, error) {
	if mode != ModePrivate && mode != ModePublicSubdomain && mode != ModePublicPort {
		return Endpoint{}, Credential{}, errors.New("phpmyadmin mode is unsupported")
	}
	if err := s.agentCall(ctx, "phpmyadmin.install", struct {
		Version string `json:"version"`
	}{"5.2.2"}, &struct{}{}); err != nil {
		return Endpoint{}, Credential{}, err
	}
	credential := Credential{}
	input := struct {
		SiteID      string `json:"site_id"`
		Mode        string `json:"mode"`
		Hostname    string `json:"hostname,omitempty"`
		Port        int    `json:"port,omitempty"`
		BasicUser   string `json:"basic_user,omitempty"`
		BasicSecret string `json:"basic_secret,omitempty"`
	}{SiteID: siteID, Mode: string(mode)}
	switch mode {
	case ModePrivate:
		assigned, err := s.reservePrivatePort(ctx)
		if err != nil {
			return Endpoint{}, Credential{}, err
		}
		input.Port = assigned
	case ModePublicSubdomain:
		input.Hostname = strings.TrimSpace(hostname)
		input.Port = 443
	case ModePublicPort:
		input.Hostname = strings.TrimSpace(hostname)
		if port < 1 || port > 65535 {
			return Endpoint{}, Credential{}, errors.New("phpmyadmin port is invalid")
		}
		if err := s.ensurePortFree(ctx, port, siteID); err != nil {
			return Endpoint{}, Credential{}, err
		}
		input.Port = port
	}
	if mode != ModePrivate {
		secret, err := generateCredential()
		if err != nil {
			return Endpoint{}, Credential{}, err
		}
		input.BasicUser, input.BasicSecret = "admin", secret
		credential = Credential{Username: "admin", Password: secret, Database: "phpmyadmin"}
	}
	if err := s.agentCall(ctx, "phpmyadmin.activate", input, &struct{}{}); err != nil {
		return Endpoint{}, Credential{}, err
	}
	now := s.now().UTC().Unix()
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO phpmyadmin_endpoints(site_id, mode, hostname, port, basic_auth_user, basic_auth_set, created_at, updated_at)
			VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?)
			ON CONFLICT(site_id) DO UPDATE SET mode = excluded.mode, hostname = excluded.hostname, port = excluded.port,
				basic_auth_set = excluded.basic_auth_set, updated_at = excluded.updated_at`,
			siteID, mode, input.Hostname, input.Port, input.BasicUser, mode != ModePrivate, now, now)
		return err
	})
	if err != nil {
		return Endpoint{}, Credential{}, err
	}
	endpoint := Endpoint{SiteID: siteID, Mode: mode, Hostname: input.Hostname, Port: input.Port, BasicAuthSet: mode != ModePrivate, BasicUser: input.BasicUser}
	return endpoint, credential, nil
}

// DisablePHPMyAdmin removes only TomPanel-owned endpoint resources.
func (s *Service) DisablePHPMyAdmin(ctx context.Context, siteID string) error {
	endpoint, err := s.Endpoint(ctx, siteID)
	if err != nil {
		return err
	}
	if err := s.agentCall(ctx, "phpmyadmin.disable", struct {
		SiteID string `json:"site_id"`
		Port   int    `json:"port,omitempty"`
	}{siteID, endpoint.Port}, &struct{}{}); err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM phpmyadmin_endpoints WHERE site_id = ?", siteID)
		return err
	})
}

// Endpoint returns the phpMyAdmin configuration of a site.
func (s *Service) Endpoint(ctx context.Context, siteID string) (Endpoint, error) {
	var endpoint Endpoint
	var hostname sql.NullString
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT mode, hostname, port, basic_auth_user, basic_auth_set
			FROM phpmyadmin_endpoints WHERE site_id = ?`, siteID).Scan(&endpoint.Mode, &hostname, &endpoint.Port, &endpoint.BasicUser, &endpoint.BasicAuthSet)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, ErrEndpointNotFound
	}
	if err != nil {
		return Endpoint{}, err
	}
	endpoint.SiteID = siteID
	endpoint.Hostname = hostname.String
	return endpoint, nil
}

func (s *Service) reservePrivatePort(ctx context.Context) (int, error) {
	used := map[int]bool{}
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT port FROM phpmyadmin_endpoints WHERE port IS NOT NULL")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var port int
			if err := rows.Scan(&port); err != nil {
				return err
			}
			used[port] = true
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	for port := privatePortFirst; port <= privatePortLast; port++ {
		if used[port] || port == 80 || port == 443 {
			continue
		}
		return port, nil
	}
	return 0, ErrPortUnavailable
}

func (s *Service) ensurePortFree(ctx context.Context, port int, siteID string) error {
	var owner string
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT site_id FROM phpmyadmin_endpoints WHERE port = ?", port).Scan(&owner)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if owner != siteID {
		return ErrPortUnavailable
	}
	return nil
}

func (s *Service) bySuffix(ctx context.Context, siteID, suffix string) (Database, error) {
	var record Database
	var createdAt, updatedAt int64
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at
			FROM databases WHERE site_id = ? AND suffix = ?`, siteID, suffix).
			Scan(&record.ID, &record.SiteID, &record.Name, &record.Suffix, &record.State, &record.ActiveGeneration, &record.PasswordSet, &createdAt, &updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Database{}, ErrDatabaseNotFound
	}
	if err != nil {
		return Database{}, fmt.Errorf("get database: %w", err)
	}
	record.CreatedAt, record.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
	return record, nil
}

func (s *Service) insertDatabase(ctx context.Context, siteID, name, suffix string) (Database, error) {
	id, err := newID()
	if err != nil {
		return Database{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	record := Database{ID: id, SiteID: siteID, Name: name, Suffix: suffix, State: "active", ActiveGeneration: 1, CreatedAt: now, UpdatedAt: now}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO databases(id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'active', 1, 1, ?, ?)`, id, siteID, name, suffix, now.Unix(), now.Unix())
		return err
	})
	if err != nil {
		return Database{}, fmt.Errorf("save database: %w", err)
	}
	return record, nil
}

func (s *Service) insertCredentialRow(ctx context.Context, databaseID, username string, generation int) error {
	id, err := newID()
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO database_credentials(id, database_id, username, generation, state, created_at)
			VALUES (?, ?, ?, ?, 'active', ?)`, id, databaseID, username, generation, s.now().UTC().Unix())
		return err
	})
}

func (s *Service) retireCredentialRows(ctx context.Context, databaseID string, newGeneration int) error {
	now := s.now().UTC().Unix()
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE database_credentials SET state = 'retired' WHERE database_id = ? AND generation < ?`, databaseID, newGeneration); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE databases SET active_generation = ?, updated_at = ? WHERE id = ?`, newGeneration, now, databaseID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrDatabaseNotFound
		}
		return nil
	})
}

func generateCredential() (string, error) {
	var builder strings.Builder
	for i := 0; i < credentialLength; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(credentialAlphabet))))
		if err != nil {
			return "", fmt.Errorf("generate credential: %w", err)
		}
		builder.WriteByte(credentialAlphabet[index.Int64()])
	}
	return builder.String(), nil
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
