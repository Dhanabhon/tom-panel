package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

const (
	// WordPressInstallJobKind installs WordPress on a prepared PHP site.
	WordPressInstallJobKind = "wordpress.install"
	// WordPressUpdateJobKind applies the configured update policy.
	WordPressUpdateJobKind = "wordpress.update"
	// WordPressSuffix is the database suffix dedicated to WordPress.
	WordPressSuffix = "wordpress"

	appsAAD = "tompanel.apps"
)

var (
	ErrInstallationNotFound = errors.New("application installation not found")
	ErrAlreadyInstalled     = errors.New("application already installed for this site")
)

// Installation is the persisted WordPress state of a site.
type Installation struct {
	ID        string
	SiteID    string
	State     string
	Version   string
	AdminUser string
	AdminEmail string
	Policy    WordPressPolicy
	SystemCron bool
	PageCache  bool
	RedisCache bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// OneTimeInstallCredentials is the single reveal of generated secrets.
type OneTimeInstallCredentials struct {
	AdminUser     string
	AdminPassword string
	Database      string
	DBUser        string
	DBPassword    string
}

// DatabaseProvider is the slice of the databases service used here.
type DatabaseProvider interface {
	Create(ctx context.Context, siteID, suffix string) (databases.Database, databases.Credential, error)
}

type wordpressJobInput struct {
	SiteID string `json:"site_id"`
}

// WordPressProvisioner turns persisted installation state into durable jobs.
// Secrets are loaded from the encrypted columns at build time so a restart
// rebuilds identical steps without persisting them in job inputs.
type WordPressProvisioner struct {
	store    *store.Store
	sites    *sites.Repository
	agent    func(ctx context.Context, operation string, input, output any) error
	database DatabaseProvider
	now      func() time.Time
}

// NewWordPressProvisioner builds the provisioner.
func NewWordPressProvisioner(database *store.Store, repository *sites.Repository, agentCall func(ctx context.Context, operation string, input, output any) error) *WordPressProvisioner {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &WordPressProvisioner{store: database, sites: repository, agent: call, now: time.Now}
}

// SetDatabaseProvider installs the database collaborator.
func (p *WordPressProvisioner) SetDatabaseProvider(provider DatabaseProvider) { p.database = provider }

// PrepareInstall creates the site database and the pending installation
// record, returning every generated secret exactly once.
func (p *WordPressProvisioner) PrepareInstall(ctx context.Context, siteID, adminUser, adminEmail, title string) (OneTimeInstallCredentials, error) {
	site, err := p.sites.Get(ctx, siteID)
	if err != nil {
		return OneTimeInstallCredentials{}, err
	}
	if site.Kind != sites.KindPHP {
		return OneTimeInstallCredentials{}, errors.New("wordpress requires a php site")
	}
	if _, err := p.installation(ctx, siteID); err == nil {
		return OneTimeInstallCredentials{}, ErrAlreadyInstalled
	} else if !errors.Is(err, ErrInstallationNotFound) {
		return OneTimeInstallCredentials{}, err
	}
	if p.database == nil {
		return OneTimeInstallCredentials{}, errors.New("database service is unavailable")
	}
	record, credential, err := p.database.Create(ctx, siteID, WordPressSuffix)
	if err != nil {
		return OneTimeInstallCredentials{}, fmt.Errorf("create wordpress database: %w", err)
	}
	_ = record
	adminPassword, err := GenerateWordPressSecrets()
	if err != nil {
		return OneTimeInstallCredentials{}, err
	}
	id, err := newAppID()
	if err != nil {
		return OneTimeInstallCredentials{}, err
	}
	adminEncrypted, err := p.store.Encrypt([]byte(adminPassword), []byte(appsAAD))
	if err != nil {
		return OneTimeInstallCredentials{}, err
	}
	dbEncrypted, err := p.store.Encrypt([]byte(credential.Password), []byte(appsAAD))
	if err != nil {
		return OneTimeInstallCredentials{}, err
	}
	now := p.now().UTC().Unix()
	err = p.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO app_installations(id, site_id, app, state, database_suffix, admin_username, admin_email, admin_secret, db_secret, created_at, updated_at)
			VALUES (?, ?, 'wordpress', 'pending', ?, ?, ?, ?, ?, ?, ?)`,
			id, siteID, WordPressSuffix, adminUser, adminEmail, adminEncrypted, dbEncrypted, now, now)
		return err
	})
	if err != nil {
		return OneTimeInstallCredentials{}, fmt.Errorf("save installation: %w", err)
	}
	return OneTimeInstallCredentials{
		AdminUser: adminUser, AdminPassword: adminPassword,
		Database: credential.Database, DBUser: credential.Username, DBPassword: credential.Password,
	}, nil
}

func (p *WordPressProvisioner) installInput(ctx context.Context, siteID, title string) (WordPressInstallInput, error) {
	installation, err := p.installation(ctx, siteID)
	if err != nil {
		return WordPressInstallInput{}, err
	}
	site, err := p.sites.Get(ctx, siteID)
	if err != nil {
		return WordPressInstallInput{}, err
	}
	adminPassword, err := p.secret(ctx, siteID, "admin_secret")
	if err != nil {
		return WordPressInstallInput{}, err
	}
	dbPassword, err := p.secret(ctx, siteID, "db_secret")
	if err != nil {
		return WordPressInstallInput{}, err
	}
	var databaseName, dbUser string
	err = p.store.Tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT d.name, c.username FROM databases d
			JOIN database_credentials c ON c.database_id = d.id AND c.state = 'active'
			WHERE d.site_id = ? AND d.suffix = ?`, siteID, WordPressSuffix)
		return row.Scan(&databaseName, &dbUser)
	})
	if err != nil {
		return WordPressInstallInput{}, fmt.Errorf("resolve wordpress database: %w", err)
	}
	return WordPressInstallInput{
		SiteID: siteID, SiteURL: "https://" + site.PrimaryDomain,
		Database: databaseName, DBUser: dbUser, DBPassword: dbPassword,
		AdminUser: installation.AdminUser, AdminEmail: installation.AdminEmail, AdminPassword: adminPassword,
		Title: title, Policy: installation.Policy,
	}, nil
}

// BuildInstallJob assembles the durable WordPress installation job.
func (p *WordPressProvisioner) BuildInstallJob(siteID, title string) (jobs.Definition, error) {
	input, err := json.Marshal(wordpressJobInput{SiteID: siteID})
	if err != nil {
		return jobs.Definition{}, err
	}
	return p.buildInstallJob(input, siteID, title)
}

func (p *WordPressProvisioner) buildInstallJob(input json.RawMessage, siteID, title string) (jobs.Definition, error) {
	if _, err := p.installInput(context.Background(), siteID, title); err != nil {
		return jobs.Definition{}, err
	}
	return jobs.Definition{
		Kind:  WordPressInstallJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "ensure_cli", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, p.agent(ctx, "wordpress.ensure_cli", struct {
					Version string `json:"version"`
				}{"2.2.0"}, &struct{}{})
			}},
			{Key: "install", Run: func(ctx context.Context) (json.RawMessage, error) {
				install, err := p.installInput(ctx, siteID, title)
				if err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, "wordpress.install", install, &struct{}{})
			}},
			{Key: "configure_cron", Run: func(ctx context.Context) (json.RawMessage, error) {
				installation, err := p.installation(ctx, siteID)
				if err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, "wordpress.configure_cron", struct {
					SiteID  string `json:"site_id"`
					Enabled bool   `json:"enabled"`
				}{siteID, installation.SystemCron}, &struct{}{})
			}},
			{Key: "activate", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, p.SetState(ctx, siteID, "active")
			}},
		},
	}, nil
}

// BuildUpdateJob applies the persisted update policy.
func (p *WordPressProvisioner) BuildUpdateJob(siteID string) (jobs.Definition, error) {
	input, err := json.Marshal(wordpressJobInput{SiteID: siteID})
	if err != nil {
		return jobs.Definition{}, err
	}
	if _, err := p.installation(context.Background(), siteID); err != nil {
		return jobs.Definition{}, err
	}
	return jobs.Definition{
		Kind:  WordPressUpdateJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "update", Run: func(ctx context.Context) (json.RawMessage, error) {
				install, err := p.installInput(ctx, siteID, "")
				if err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, "wordpress.update_core", install, &struct{}{})
			}},
		},
	}, nil
}

// UpdateDBConfig rewrites wp-config database credentials without argv.
func (p *WordPressProvisioner) UpdateDBConfig(ctx context.Context, siteID, database, username, password string) error {
	return p.agent(ctx, "wordpress.update_db_config", struct {
		SiteID   string `json:"site_id"`
		Database string `json:"database"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{siteID, database, username, password}, &struct{}{})
}

// ClearCache flushes the site's WordPress cache directories.
func (p *WordPressProvisioner) ClearCache(ctx context.Context, siteID string) error {
	return p.agent(ctx, "wordpress.clear_cache", struct {
		SiteID string `json:"site_id"`
	}{siteID}, &struct{}{})
}

// ConfigureRedis toggles the site-scoped Redis ACL user.
func (p *WordPressProvisioner) ConfigureRedis(ctx context.Context, siteID string, enabled bool, password string) error {
	if !enabled {
		return p.agent(ctx, "redis.remove_site_acl", struct {
			SiteID string `json:"site_id"`
		}{siteID}, &struct{}{})
	}
	prefix, err := databases.SitePrefix(siteID)
	if err != nil {
		return err
	}
	return p.agent(ctx, "redis.ensure_site_acl", struct {
		SiteID   string `json:"site_id"`
		Password string `json:"password"`
		Prefix   string `json:"prefix"`
	}{siteID, password, prefix}, &struct{}{})
}

// SetPolicy stores the independent update channels.
func (p *WordPressProvisioner) SetPolicy(ctx context.Context, siteID string, policy WordPressPolicy) error {
	if _, err := p.installation(ctx, siteID); err != nil {
		return err
	}
	return p.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE app_installations SET policy_minor = ?, policy_major = ?, policy_plugins = ?, policy_themes = ?, updated_at = ? WHERE site_id = ?`,
			boolInt(policy.MinorCore), boolInt(policy.MajorCore), boolInt(policy.Plugins), boolInt(policy.Themes), p.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrInstallationNotFound
		}
		return nil
	})
}

// SetSystemCron toggles system-driven WP-Cron.
func (p *WordPressProvisioner) SetSystemCron(ctx context.Context, siteID string, enabled bool) error {
	if _, err := p.installation(ctx, siteID); err != nil {
		return err
	}
	if err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE app_installations SET system_cron = ?, updated_at = ? WHERE site_id = ?`,
			boolInt(enabled), p.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrInstallationNotFound
		}
		return nil
	}); err != nil {
		return err
	}
	return p.agent(ctx, "wordpress.configure_cron", struct {
		SiteID  string `json:"site_id"`
		Enabled bool   `json:"enabled"`
	}{siteID, enabled}, &struct{}{})
}

// SetState transitions the installation state.
func (p *WordPressProvisioner) SetState(ctx context.Context, siteID, state string) error {
	return p.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE app_installations SET state = ?, updated_at = ? WHERE site_id = ?",
			state, p.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrInstallationNotFound
		}
		return nil
	})
}

// Installation loads the persisted WordPress state of a site.
func (p *WordPressProvisioner) Installation(ctx context.Context, siteID string) (Installation, error) {
	return p.installation(ctx, siteID)
}

func (p *WordPressProvisioner) installation(ctx context.Context, siteID string) (Installation, error) {
	var installation Installation
	var createdAt, updatedAt int64
	err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, state, coalesce(version, ''), admin_username, admin_email,
			policy_minor, policy_major, policy_plugins, policy_themes, system_cron, page_cache, redis_cache, created_at, updated_at
			FROM app_installations WHERE site_id = ? AND app = 'wordpress'`, siteID).
			Scan(&installation.ID, &installation.SiteID, &installation.State, &installation.Version, &installation.AdminUser, &installation.AdminEmail,
				&installation.Policy.MinorCore, &installation.Policy.MajorCore, &installation.Policy.Plugins, &installation.Policy.Themes,
				&installation.SystemCron, &installation.PageCache, &installation.RedisCache, &createdAt, &updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Installation{}, ErrInstallationNotFound
	}
	if err != nil {
		return Installation{}, fmt.Errorf("get installation: %w", err)
	}
	installation.CreatedAt, installation.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
	return installation, nil
}

func (p *WordPressProvisioner) secret(ctx context.Context, siteID, column string) (string, error) {
	if column != "admin_secret" && column != "db_secret" {
		return "", errors.New("unknown secret column")
	}
	var encrypted []byte
	err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT "+column+" FROM app_installations WHERE site_id = ?", siteID).Scan(&encrypted)
	})
	if err != nil {
		return "", err
	}
	if len(encrypted) == 0 {
		return "", errors.New("installation secret is unavailable")
	}
	decrypted, err := p.store.Decrypt(encrypted, []byte(appsAAD))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// Register wires the job builders into the manager.
func (p *WordPressProvisioner) Register(manager *jobs.Manager) error {
	if err := manager.Register(WordPressInstallJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed wordpressJobInput
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		return p.buildInstallJob(input, parsed.SiteID, "")
	}); err != nil {
		return err
	}
	return manager.Register(WordPressUpdateJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed wordpressJobInput
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		return p.BuildUpdateJob(parsed.SiteID)
	})
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
