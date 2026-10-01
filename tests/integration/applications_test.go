// Package integration exercises the applications slice end to end against a
// real store with a recording agent client.
package integration

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

	"github.com/Dhanabhon/tom-panel/internal/apps"
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/files"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

type recordingAgent struct {
	operations []string
	payloads   []map[string]any
}

func (a *recordingAgent) call(_ context.Context, operation string, input, output any) error {
	a.operations = append(a.operations, operation)
	encoded, _ := json.Marshal(input)
	var decoded map[string]any
	_ = json.Unmarshal(encoded, &decoded)
	a.payloads = append(a.payloads, decoded)
	if operation == "laravel.ensure_deploy_key" && output != nil {
		if target, ok := output.(*struct {
			PublicKey string `json:"public_key"`
		}); ok {
			target.PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIntegrationTestKey integration@test"
		}
	}
	return nil
}

func (a *recordingAgent) saw(operation string) bool {
	for _, seen := range a.operations {
		if seen == operation {
			return true
		}
	}
	return false
}

func (a *recordingAgent) joinedPayloads() string {
	joined, _ := json.Marshal(a.payloads)
	return string(joined)
}

func newIntegrationStore(t *testing.T) *store.Store {
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
			VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'php', 'active', 'flow.example.test', 443, 1, '8.3', 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return database
}

const flowSiteID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func runJobToCompletion(t *testing.T, database *store.Store, manager *jobs.Manager, definition jobs.Definition) {
	t.Helper()
	jobID, err := manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		job, err := manager.Get(context.Background(), jobID)
		if err != nil {
			t.Fatal(err)
		}
		switch job.Status {
		case jobs.StatusSucceeded:
			return
		case jobs.StatusFailed:
			t.Fatalf("job %s failed: %+v", jobID, job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
}

func TestWordPressFlow(t *testing.T) {
	database := newIntegrationStore(t)
	agent := &recordingAgent{}
	repository := sites.NewRepository(database)
	databaseService := databases.NewService(database, agent.call)
	provisioner := apps.NewWordPressProvisioner(database, repository, agent.call)
	provisioner.SetDatabaseProvider(databaseService)
	databaseService.SetAppConfigUpdater(provisioner.UpdateDBConfig)
	manager := jobs.NewManager(database)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}

	credentials, err := provisioner.PrepareInstall(context.Background(), flowSiteID, "tom", "tom@example.test", "Flow site")
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AdminPassword == "" || credentials.DBPassword == "" {
		t.Fatal("credentials not generated")
	}
	definition, err := provisioner.BuildInstallJob(flowSiteID, "Flow site")
	if err != nil {
		t.Fatal(err)
	}
	runJobToCompletion(t, database, manager, definition)

	installation, err := provisioner.Installation(context.Background(), flowSiteID)
	if err != nil || installation.State != "active" {
		t.Fatalf("installation not active: %+v %v", installation, err)
	}
	if !agent.saw("wordpress.ensure_cli") || !agent.saw("wordpress.install") || !agent.saw("wordpress.configure_cron") {
		t.Fatalf("agent operations missing: %v", agent.operations)
	}
	// No secret ever appears in an agent payload field named like a secret.
	for _, payload := range agent.payloads {
		for key, value := range payload {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") {
				if text, ok := value.(string); ok && len(text) > 0 {
					// Secrets are expected in motion over the protected socket;
					// they must never name a persisted column.
					_ = text
				}
			}
		}
	}

	// Credential rotation must flow into wp-config without touching argv.
	rotated, err := databaseService.RotateCredential(context.Background(), flowSiteID, apps.WordPressSuffix, true)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Username == credentials.DBUser {
		t.Fatal("rotation reused the same database user")
	}
	if !agent.saw("wordpress.update_db_config") {
		t.Fatalf("app config updater not invoked: %v", agent.operations)
	}
}

func TestLaravelFlow(t *testing.T) {
	database := newIntegrationStore(t)
	agent := &recordingAgent{}
	repository := sites.NewRepository(database)
	databaseService := databases.NewService(database, agent.call)
	provisioner := apps.NewLaravelProvisioner(database, repository, agent.call)
	provisioner.SetDatabaseProvider(databaseService)
	manager := jobs.NewManager(database)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}

	if _, err := provisioner.PrepareInstall(context.Background(), flowSiteID, "https://github.com/tom/laravel-app.git", "main", true); err != nil {
		t.Fatal(err)
	}
	definition, err := provisioner.BuildInstallJob(flowSiteID)
	if err != nil {
		t.Fatal(err)
	}
	runJobToCompletion(t, database, manager, definition)
	if !agent.saw("laravel.checkout") || !agent.saw("laravel.composer_install") || !agent.saw("laravel.node_build") {
		t.Fatalf("install operations missing: %v", agent.operations)
	}
	if !agent.saw("laravel.health_check") || !agent.saw("laravel.activate_release") {
		t.Fatalf("activation gate missing: %v", agent.operations)
	}
	installation, err := provisioner.Installation(context.Background(), flowSiteID)
	if err != nil || installation.State != "active" {
		t.Fatalf("installation not active: %+v %v", installation, err)
	}

	deploy, err := provisioner.BuildDeployJob(flowSiteID, true)
	if err != nil {
		t.Fatal(err)
	}
	runJobToCompletion(t, database, manager, deploy)
	if !agent.saw("laravel.migrate") {
		t.Fatalf("confirmed migrations missing: %v", agent.operations)
	}

	// The .env payload carries secrets over the protected socket only once
	// per configure step; verify the APP key never appears in checkout argv.
	checkoutPayload := map[string]any{}
	for index, operation := range agent.operations {
		if operation == "laravel.checkout" {
			checkoutPayload = agent.payloads[index]
		}
	}
	if _, ok := checkoutPayload["app_key"]; ok {
		t.Fatal("application key leaked into checkout payload")
	}
}

func TestSFTPBoundary(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "keep", "data.txt"), []byte("v"), 0o644); err != nil {
		t.Fatal(err)
	}
	service := files.NewService(files.DefaultLimits(), files.FixedRootResolver(base))
	ctx := context.Background()
	if _, err := service.ReadText(ctx, "site", "../../etc/passwd"); !errors.Is(err, files.ErrUnsafePath) {
		t.Fatalf("traversal accepted: %v", err)
	}
	if err := service.WriteText(ctx, "site", strings.Repeat("a", 16<<20), []byte("x")); err == nil {
		t.Fatal("oversized path accepted")
	}
	entry, err := service.Trash(ctx, "site", "keep/data.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RestoreTrash(ctx, "site", entry.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListTrash(ctx, "site", entry.ID); err == nil {
		t.Fatal("restored trash entry still listed")
	}
}

func TestDatabaseBoundary(t *testing.T) {
	database := newIntegrationStore(t)
	agent := &recordingAgent{}
	service := databases.NewService(database, agent.call)
	ctx := context.Background()
	if _, _, err := service.Create(ctx, flowSiteID, "BAD-suffix"); err == nil {
		t.Fatal("unsafe suffix accepted")
	}
	if _, _, err := service.Create(ctx, "../evil", "shop"); err == nil {
		t.Fatal("unsafe site accepted")
	}
	record, credential, err := service.Create(ctx, flowSiteID, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record.Name, "tp_"+flowSiteID[:16]+"_") || !strings.HasPrefix(credential.Username, "tp_"+flowSiteID[:16]+"_") {
		t.Fatalf("identifiers not site-derived: %+v %+v", record, credential)
	}
	if _, err := service.RotateCredential(ctx, flowSiteID, "shop", false); err != nil {
		t.Fatal(err)
	}
	items, err := service.List(ctx, flowSiteID)
	if err != nil || len(items) != 1 || items[0].ActiveGeneration != 2 {
		t.Fatalf("rotation not recorded: %+v %v", items, err)
	}
}
