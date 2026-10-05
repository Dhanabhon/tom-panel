package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

const wpSiteID = "44444444444444444444444444444444"

type fakeDatabaseProvider struct {
	calls []string
}

func (f *fakeDatabaseProvider) Create(_ context.Context, siteID, suffix string) (databases.Database, databases.Credential, error) {
	f.calls = append(f.calls, suffix)
	name, _ := databases.DatabaseName(siteID, suffix)
	user, _ := databases.UserName(siteID, 1)
	return databases.Database{Name: name}, databases.Credential{Username: user, Password: strings.Repeat("p", 24), Database: name}, nil
}

func newWordPressTestEnv(t *testing.T) (*WordPressProvisioner, *store.Store, string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "state.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO admins(id, username, password_hash, created_at, updated_at)
			VALUES (1, 'admin', x'00', 0, 0)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, php_version, created_at, updated_at)
			VALUES (?, 'php', 'active', 'wp.example.test', 443, 1, '8.3', 0, 0)`, wpSiteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	operations := &[]string{}
	caller := func(ctx context.Context, operation string, input, output any) error {
		*operations = append(*operations, operation)
		return nil
	}
	repository := sites.NewRepository(database)
	provisioner := NewWordPressProvisioner(database, repository, caller)
	provisioner.SetDatabaseProvider(&fakeDatabaseProvider{})
	return provisioner, database, dir, operations
}

func seedWordPressDatabaseRow(t *testing.T, database *store.Store) {
	t.Helper()
	name, _ := databases.DatabaseName(wpSiteID, WordPressSuffix)
	user, _ := databases.UserName(wpSiteID, 1)
	err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO databases(id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at)
			VALUES ('dddddddddddddddddddddddddddddddd', ?, ?, ?, 'active', 1, 1, 0, 0)`, wpSiteID, name, WordPressSuffix); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO database_credentials(id, database_id, username, generation, state, created_at)
			VALUES ('cccccccccccccccccccccccccccccccc', 'dddddddddddddddddddddddddddddddd', ?, 1, 'active', 0)`, user)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrepareInstallReturnsSecretsOnceAndStoresEncrypted(t *testing.T) {
	provisioner, database, dir, _ := newWordPressTestEnv(t)
	credentials, err := provisioner.PrepareInstall(context.Background(), wpSiteID, "tom", "tom@example.test", "My site")
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AdminPassword == "" || credentials.DBPassword != strings.Repeat("p", 24) {
		t.Fatalf("credentials incomplete: %+v", credentials)
	}
	var stored strings.Builder
	for _, suffix := range []string{"", "-wal", "-shm"} {
		content, err := os.ReadFile(filepath.Join(dir, "state.db") + suffix)
		if err == nil {
			stored.Write(content)
		}
	}
	if strings.Contains(stored.String(), credentials.AdminPassword) {
		t.Fatal("admin password persisted in plaintext")
	}
	installation, err := provisioner.Installation(context.Background(), wpSiteID)
	if err != nil || installation.State != "pending" {
		t.Fatalf("installation: %+v %v", installation, err)
	}
	if _, err := provisioner.PrepareInstall(context.Background(), wpSiteID, "tom", "tom@example.test", "x"); !errors.Is(err, ErrAlreadyInstalled) {
		t.Fatalf("duplicate install: %v", err)
	}
	_ = database
}

func TestInstallJobRebuildsWithoutPersistedSecrets(t *testing.T) {
	provisioner, _, _, _ := newWordPressTestEnv(t)
	seedWordPressDatabaseRow(t, provisioner.store)
	if _, err := provisioner.PrepareInstall(context.Background(), wpSiteID, "tom", "tom@example.test", "My site"); err != nil {
		t.Fatal(err)
	}
	// The job input carries only the site id; the persisted form is safe.
	definition, err := provisioner.BuildInstallJob(wpSiteID, "My site")
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(definition.Input, &input); err != nil {
		t.Fatal(err)
	}
	if len(input) != 1 || input["site_id"] != wpSiteID {
		t.Fatalf("job input must only carry the site id: %v", input)
	}
	if len(definition.Steps) != 4 || definition.Steps[0].Key != "ensure_cli" || definition.Steps[3].Key != "activate" {
		t.Fatalf("unexpected steps: %+v", definition.Steps)
	}
	// A second builder (as the manager does on restart) still resolves secrets.
	rebuilt, err := provisioner.BuildInstallJob(wpSiteID, "My site")
	if err != nil {
		t.Fatal(err)
	}
	if len(rebuilt.Steps) != len(definition.Steps) {
		t.Fatal("rebuild changed the step layout")
	}
}

func TestPrepareInstallRequiresPHPSite(t *testing.T) {
	provisioner, _, _, _ := newWordPressTestEnv(t)
	// Replace the site with a static one.
	err := provisioner.store.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), "UPDATE sites SET kind = 'static' WHERE id = ?", wpSiteID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.PrepareInstall(context.Background(), wpSiteID, "tom", "tom@example.test", "x"); err == nil {
		t.Fatal("wordpress install accepted a static site")
	}
}

func TestRegisterAndRunInstallJob(t *testing.T) {
	provisioner, _, _, operations := newWordPressTestEnv(t)
	seedWordPressDatabaseRow(t, provisioner.store)
	if _, err := provisioner.PrepareInstall(context.Background(), wpSiteID, "tom", "tom@example.test", "My site"); err != nil {
		t.Fatal(err)
	}
	manager := jobs.NewManager(provisioner.store)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	definition, err := provisioner.BuildInstallJob(wpSiteID, "My site")
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, err := manager.Get(context.Background(), jobID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == jobs.StatusSucceeded {
			break
		}
		if job.Status == jobs.StatusFailed {
			t.Fatalf("install job failed: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	job, err := manager.Get(context.Background(), jobID)
	if err != nil || job.Status != jobs.StatusSucceeded {
		t.Fatalf("job did not succeed: %+v %v", job, err)
	}
	joined := strings.Join(*operations, ",")
	if !strings.Contains(joined, "wordpress.ensure_cli") || !strings.Contains(joined, "wordpress.install") {
		t.Fatalf("expected agent operations missing: %s", joined)
	}
	installation, err := provisioner.Installation(context.Background(), wpSiteID)
	if err != nil || installation.State != "active" {
		t.Fatalf("installation not activated: %+v %v", installation, err)
	}
}
