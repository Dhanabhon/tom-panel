package apps

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

// LaravelInstallation is the persisted Laravel state of a site.
type LaravelInstallation struct {
	ID              string
	SiteID          string
	State           string
	Repository      string
	Branch          string
	NodeBuild       bool
	DeployPublicKey string
	CurrentRelease  string
	SystemCron      bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// LaravelOneTimeCredentials is the single reveal of the database secret.
type LaravelOneTimeCredentials struct {
	Database      string
	DBUser        string
	DBPassword    string
	DeployKeyHint string
}

type laravelJobInput struct {
	SiteID        string `json:"site_id"`
	RunMigrations bool   `json:"run_migrations"`
}

// LaravelProvisioner builds durable Laravel install and deploy jobs.
// Secrets live in the encrypted columns and are re-read at build time.
type LaravelProvisioner struct {
	store    *store.Store
	sites    *sites.Repository
	agent    func(ctx context.Context, operation string, input, output any) error
	database DatabaseProvider
	now      func() time.Time
}

// NewLaravelProvisioner builds the provisioner.
func NewLaravelProvisioner(database *store.Store, repository *sites.Repository, agentCall func(ctx context.Context, operation string, input, output any) error) *LaravelProvisioner {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &LaravelProvisioner{store: database, sites: repository, agent: call, now: time.Now}
}

// SetDatabaseProvider installs the database collaborator.
func (p *LaravelProvisioner) SetDatabaseProvider(provider DatabaseProvider) { p.database = provider }

// PrepareInstall validates the repository, creates the database, and mints
// the application key. It returns the database secret exactly once.
func (p *LaravelProvisioner) PrepareInstall(ctx context.Context, siteID, repository, branch string, nodeBuild bool) (LaravelOneTimeCredentials, error) {
	site, err := p.sites.Get(ctx, siteID)
	if err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	if site.Kind != sites.KindPHP {
		return LaravelOneTimeCredentials{}, errors.New("laravel requires a php site")
	}
	if err := ValidateLaravelRepo(repository); err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	if err := ValidateLaravelBranch(branch); err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	if _, err := p.installation(ctx, siteID); err == nil {
		return LaravelOneTimeCredentials{}, ErrAlreadyInstalled
	} else if !errors.Is(err, ErrInstallationNotFound) {
		return LaravelOneTimeCredentials{}, err
	}
	if p.database == nil {
		return LaravelOneTimeCredentials{}, errors.New("database service is unavailable")
	}
	_, credential, err := p.database.Create(ctx, siteID, LaravelSuffix)
	if err != nil {
		return LaravelOneTimeCredentials{}, fmt.Errorf("create laravel database: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return LaravelOneTimeCredentials{}, fmt.Errorf("generate application key: %w", err)
	}
	appKey := "base64:" + base64.StdEncoding.EncodeToString(raw)
	appEncrypted, err := p.store.Encrypt([]byte(appKey), []byte(appsAAD))
	if err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	dbEncrypted, err := p.store.Encrypt([]byte(credential.Password), []byte(appsAAD))
	if err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	id, err := newAppID()
	if err != nil {
		return LaravelOneTimeCredentials{}, err
	}
	// Private repositories need a site deploy key minted on the server.
	deployKey := ""
	if isSSHRepository(repository) {
		var result struct {
			PublicKey string `json:"public_key"`
		}
		if err := p.agent(ctx, "laravel.ensure_deploy_key", struct {
			SiteID string `json:"site_id"`
		}{siteID}, &result); err != nil {
			return LaravelOneTimeCredentials{}, err
		}
		deployKey = result.PublicKey
	}
	now := p.now().UTC().Unix()
	err = p.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO app_installations(id, site_id, app, state, database_suffix, repository, branch, node_build, deploy_public_key, admin_secret, db_secret, created_at, updated_at)
			VALUES (?, ?, 'laravel', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, siteID, LaravelSuffix, repository, branch, boolInt(nodeBuild), deployKey, appEncrypted, dbEncrypted, now, now)
		return err
	})
	if err != nil {
		return LaravelOneTimeCredentials{}, fmt.Errorf("save installation: %w", err)
	}
	credentials := LaravelOneTimeCredentials{
		Database: credential.Database, DBUser: credential.Username, DBPassword: credential.Password,
	}
	if deployKey != "" {
		credentials.DeployKeyHint = "Add the site deploy key shown on this page to your Git host with read access."
	}
	return credentials, nil
}

func isSSHRepository(repository string) bool {
	return len(repository) > 4 && repository[:4] == "git@"
}

func (p *LaravelProvisioner) installation(ctx context.Context, siteID string) (LaravelInstallation, error) {
	var installation LaravelInstallation
	var createdAt, updatedAt int64
	err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, state, coalesce(repository, ''), coalesce(branch, ''), node_build,
			coalesce(deploy_public_key, ''), coalesce(current_release, ''), system_cron, created_at, updated_at
			FROM app_installations WHERE site_id = ? AND app = 'laravel'`, siteID).
			Scan(&installation.ID, &installation.SiteID, &installation.State, &installation.Repository, &installation.Branch, &installation.NodeBuild,
				&installation.DeployPublicKey, &installation.CurrentRelease, &installation.SystemCron, &createdAt, &updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return LaravelInstallation{}, ErrInstallationNotFound
	}
	if err != nil {
		return LaravelInstallation{}, fmt.Errorf("get laravel installation: %w", err)
	}
	installation.CreatedAt, installation.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
	return installation, nil
}

// Installation loads the persisted Laravel state of a site.
func (p *LaravelProvisioner) Installation(ctx context.Context, siteID string) (LaravelInstallation, error) {
	return p.installation(ctx, siteID)
}

func (p *LaravelProvisioner) dbCredential(ctx context.Context, siteID string) (database, username, password, appKey string, err error) {
	var databaseName, dbUser string
	err = p.store.Tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT d.name, c.username FROM databases d
			JOIN database_credentials c ON c.database_id = d.id AND c.state = 'active'
			WHERE d.site_id = ? AND d.suffix = ?`, siteID, LaravelSuffix)
		return row.Scan(&databaseName, &dbUser)
	})
	if err != nil {
		return "", "", "", "", err
	}
	dbPassword, err := p.secret(ctx, siteID, "db_secret")
	if err != nil {
		return "", "", "", "", err
	}
	key, err := p.secret(ctx, siteID, "admin_secret")
	if err != nil {
		return "", "", "", "", err
	}
	return databaseName, dbUser, dbPassword, key, nil
}

func (p *LaravelProvisioner) secret(ctx context.Context, siteID, column string) (string, error) {
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

func (p *LaravelProvisioner) assignRelease(ctx context.Context, siteID, release string) error {
	return p.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE app_installations SET current_release = ?, updated_at = ? WHERE site_id = ? AND app = 'laravel'",
			release, p.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrInstallationNotFound
		}
		return nil
	})
}

// BuildInstallJob assembles the first Laravel release pipeline.
func (p *LaravelProvisioner) BuildInstallJob(siteID string) (jobs.Definition, error) {
	installation, err := p.installation(context.Background(), siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	release := GenerateReleaseID(p.now().UTC().Unix())
	if err := p.assignRelease(context.Background(), siteID, release); err != nil {
		return jobs.Definition{}, err
	}
	input, err := json.Marshal(laravelJobInput{SiteID: siteID})
	if err != nil {
		return jobs.Definition{}, err
	}
	steps, err := BuildLaravelInstallJob(LaravelInstallInput{
		SiteID: siteID, Repository: installation.Repository, Branch: installation.Branch, NodeBuild: installation.NodeBuild,
	})
	if err != nil {
		return jobs.Definition{}, err
	}
	return jobs.Definition{Kind: LaravelInstallJobKind, Input: input, Steps: p.stepsFor(ctx0(), siteID, release, steps, true, 0)}, nil
}

// BuildDeployJob assembles a deployment; migrations need explicit consent.
func (p *LaravelProvisioner) BuildDeployJob(siteID string, runMigrations bool) (jobs.Definition, error) {
	installation, err := p.installation(context.Background(), siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	if installation.State != "active" {
		return jobs.Definition{}, errors.New("laravel is not installed yet")
	}
	site, err := p.sites.Get(context.Background(), siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	release := GenerateReleaseID(p.now().UTC().Unix())
	if err := p.assignRelease(context.Background(), siteID, release); err != nil {
		return jobs.Definition{}, err
	}
	input, err := json.Marshal(laravelJobInput{SiteID: siteID, RunMigrations: runMigrations})
	if err != nil {
		return jobs.Definition{}, err
	}
	steps, err := BuildLaravelDeployJob(LaravelDeployInput{
		SiteID: siteID, Repository: installation.Repository, Branch: installation.Branch,
		NodeBuild: installation.NodeBuild, HTTPSPort: site.HTTPSPort, RunMigrations: runMigrations, Release: release,
	})
	if err != nil {
		return jobs.Definition{}, err
	}
	return jobs.Definition{Kind: LaravelDeployJobKind, Input: input, Steps: p.stepsFor(ctx0(), siteID, release, steps, false, site.HTTPSPort)}, nil
}

func ctx0() context.Context { return context.Background() }

// stepsFor converts the pipeline names into durable job steps.
func (p *LaravelProvisioner) stepsFor(_ context.Context, siteID, release string, names []string, install bool, httpsPort int) []jobs.Step {
	steps := make([]jobs.Step, 0, len(names)+1)
	for _, name := range names {
		operation := name
		steps = append(steps, jobs.Step{Key: name, Run: func(ctx context.Context) (json.RawMessage, error) {
			installation, err := p.installation(ctx, siteID)
			if err != nil {
				return nil, err
			}
			switch operation {
			case "laravel.checkout":
				return nil, p.agent(ctx, operation, laravelCheckoutPayload{SiteID: siteID, Repository: installation.Repository, Branch: installation.Branch, Release: release, UseKey: installation.DeployPublicKey != ""}, &struct{}{})
			case "laravel.composer_install", "laravel.node_build", "laravel.migrate", "laravel.optimize", "laravel.activate_release":
				return nil, p.agent(ctx, operation, laravelReleasePayload{SiteID: siteID, Release: release}, &struct{}{})
			case "laravel.configure_environment":
				database, username, password, appKey, err := p.dbCredential(ctx, siteID)
				if err != nil {
					return nil, err
				}
				site, err := p.sites.Get(ctx, siteID)
				if err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, operation, struct {
					SiteID   string `json:"site_id"`
					Database string `json:"database"`
					Username string `json:"username"`
					Password string `json:"password"`
					AppKey   string `json:"app_key"`
					AppURL   string `json:"app_url"`
				}{siteID, database, username, password, appKey, "https://" + site.PrimaryDomain}, &struct{}{})
			case "laravel.health_check":
				site, err := p.sites.Get(ctx, siteID)
				if err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, operation, struct {
					SiteID    string `json:"site_id"`
					Hostname  string `json:"hostname"`
					HTTPSPort int    `json:"https_port"`
				}{siteID, site.PrimaryDomain, site.HTTPSPort}, &struct{}{})
			case "laravel.ensure_workers":
				return nil, p.agent(ctx, operation, struct {
					SiteID  string `json:"site_id"`
					Enabled bool   `json:"enabled"`
				}{siteID, true}, &struct{}{})
			default:
				return nil, fmt.Errorf("unknown laravel step %q", operation)
			}
		}})
	}
	if install {
		steps = append(steps, jobs.Step{Key: "activate", Run: func(ctx context.Context) (json.RawMessage, error) {
			return nil, p.SetLaravelState(ctx, siteID, "active")
		}})
	}
	return steps
}

type laravelCheckoutPayload struct {
	SiteID     string `json:"site_id"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Release    string `json:"release"`
	UseKey     bool   `json:"use_key,omitempty"`
}

type laravelReleasePayload struct {
	SiteID  string `json:"site_id"`
	Release string `json:"release"`
}

// SetLaravelState transitions the installation state.
func (p *LaravelProvisioner) SetLaravelState(ctx context.Context, siteID, state string) error {
	return p.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE app_installations SET state = ?, updated_at = ? WHERE site_id = ? AND app = 'laravel'",
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

// SetWorkers toggles the managed queue and scheduler units.
func (p *LaravelProvisioner) SetWorkers(ctx context.Context, siteID string, enabled bool) error {
	if _, err := p.installation(ctx, siteID); err != nil {
		return err
	}
	return p.agent(ctx, "laravel.ensure_workers", struct {
		SiteID  string `json:"site_id"`
		Enabled bool   `json:"enabled"`
	}{siteID, enabled}, &struct{}{})
}

// Register wires the job builders into the manager.
func (p *LaravelProvisioner) Register(manager *jobs.Manager) error {
	if err := manager.Register(LaravelInstallJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		return p.rebuild(input, true)
	}); err != nil {
		return err
	}
	return manager.Register(LaravelDeployJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		return p.rebuild(input, false)
	})
}

// rebuild reconstructs a definition from persisted state so restarts and
// retries keep the exact original step layout.
func (p *LaravelProvisioner) rebuild(input json.RawMessage, install bool) (jobs.Definition, error) {
	var parsed laravelJobInput
	if err := json.Unmarshal(input, &parsed); err != nil {
		return jobs.Definition{}, err
	}
	installation, err := p.installation(context.Background(), parsed.SiteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	if installation.CurrentRelease == "" {
		return jobs.Definition{}, errors.New("installation has no assigned release")
	}
	site, err := p.sites.Get(context.Background(), parsed.SiteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	var names []string
	if install {
		names, err = BuildLaravelInstallJob(LaravelInstallInput{
			SiteID: parsed.SiteID, Repository: installation.Repository, Branch: installation.Branch, NodeBuild: installation.NodeBuild,
		})
	} else {
		names, err = BuildLaravelDeployJob(LaravelDeployInput{
			SiteID: parsed.SiteID, Repository: installation.Repository, Branch: installation.Branch,
			NodeBuild: installation.NodeBuild, HTTPSPort: site.HTTPSPort, RunMigrations: parsed.RunMigrations, Release: installation.CurrentRelease,
		})
	}
	if err != nil {
		return jobs.Definition{}, err
	}
	kind := LaravelDeployJobKind
	if install {
		kind = LaravelInstallJobKind
	}
	return jobs.Definition{Kind: kind, Input: input, Steps: p.stepsFor(context.Background(), parsed.SiteID, installation.CurrentRelease, names, install, site.HTTPSPort)}, nil
}
