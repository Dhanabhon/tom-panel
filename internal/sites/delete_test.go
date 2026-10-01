package sites

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

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

const deleteSiteID = "cccccccccccccccccccccccccccccccc"

type deleteHarness struct {
	store      *store.Store
	repo       *Repository
	provisioner *DeleteProvisioner
	agentLog   *[]string
	dnsDeletes *[]string
	backupCalls *[]string
	manager    *jobs.Manager
}

func newDeleteHarness(t *testing.T) *deleteHarness {
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
	agentLog := &[]string{}
	dnsDeletes := &[]string{}
	backupCalls := &[]string{}
	repo := NewRepository(database)
	provisioner := NewDeleteProvisioner(database, repo, func(_ context.Context, operation string, _, _ any) error {
		*agentLog = append(*agentLog, operation)
		if operation == "site.quarantine" {
			// The real agent moves the tree; record the derived path.
			return nil
		}
		return nil
	}, &fakeDNSRemover{deleted: dnsDeletes, store: database})
	provisioner.SetBackupFinalizer(func(_ context.Context, siteID string) error {
		*backupCalls = append(*backupCalls, siteID)
		return nil
	})
	provisioner.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	return &deleteHarness{
		store: database, repo: repo, provisioner: provisioner,
		agentLog: agentLog, dnsDeletes: dnsDeletes, backupCalls: backupCalls,
		manager: jobs.NewManager(database),
	}
}

type fakeDNSRemover struct {
	deleted *[]string
	store   *store.Store
}

// DeleteDNS mirrors the domains service contract: release the remote record
// and remove the ledger row.
func (f *fakeDNSRemover) DeleteDNS(ctx context.Context, id string) error {
	*f.deleted = append(*f.deleted, id)
	return f.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM dns_records WHERE id = ?", id)
		return err
	})
}

func (h *deleteHarness) seedSite(t *testing.T) {
	t.Helper()
	if _, err := h.repo.Create(context.Background(), CreateInput{
		Kind: KindPHP, PrimaryDomain: "delete.example.test", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.3",
	}); err != nil {
		t.Fatal(err)
	}
	items, _ := h.repo.List(context.Background())
	for _, item := range items {
		if item.PrimaryDomain == "delete.example.test" {
			if err := h.repo.SetState(context.Background(), item.ID, StateActive); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("seed site not found")
}

func (h *deleteHarness) siteID(t *testing.T) string {
	t.Helper()
	items, err := h.repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return items[0].ID
}

func TestQuarantineNeverDeletesExternalDNS(t *testing.T) {
	harness := newDeleteHarness(t)
	harness.seedSite(t)
	siteID := harness.siteID(t)
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES ('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'static', 'active', 'other.example.test', 443, 0, 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		// One managed record owned by the site, one manual record on the same
		// site, one managed record belonging to a different site.
		for _, seed := range []struct {
			id, siteID string
			managed    int
		}{
			{"1111111111111111111111111111111a", siteID, 1},
			{"1111111111111111111111111111111b", siteID, 0},
			{"1111111111111111111111111111111c", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 1},
		} {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO dns_records(id, site_id, record_type, hostname, content, provider, managed, created_at, updated_at)
				VALUES (?, ?, 'A', 'x.example.test', '203.0.113.1', 'cloudflare', ?, 0, 0)`, seed.id, seed.siteID, seed.managed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	definition, err := harness.provisioner.BuildDeleteJob(siteID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.provisioner.Register(harness.manager); err != nil {
		t.Fatal(err)
	}
	jobID, err := harness.manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	runJob(t, harness.manager, jobID)

	// Only the site's managed record was released.
	if len(*harness.dnsDeletes) != 1 || (*harness.dnsDeletes)[0] != "1111111111111111111111111111111a" {
		t.Fatalf("external dns deleted: %v", *harness.dnsDeletes)
	}
	site, err := harness.repo.Get(context.Background(), siteID)
	if err != nil || site.State != StateQuarantined {
		t.Fatalf("site not quarantined: %+v %v", site, err)
	}
	var count int
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM dns_records").Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("surviving records = %d, want 2 (manual + foreign managed)", count)
	}
	var purgesAt int64
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT purges_at FROM site_quarantine WHERE site_id = ?", siteID).Scan(&purgesAt)
	}); err != nil {
		t.Fatal(err)
	}
	if purgesAt != time.Unix(1_800_000_000, 0).Add(7*24*time.Hour).Unix() {
		t.Fatalf("quarantine window = %d", purgesAt)
	}
}

func runJob(t *testing.T, manager *jobs.Manager, jobID string) {
	t.Helper()
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
			return
		}
		if job.Status == jobs.StatusFailed {
			t.Fatalf("delete job failed: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("delete job did not finish")
}

func TestDeleteKeepsManagedDNSWhenDeclined(t *testing.T) {
	harness := newDeleteHarness(t)
	harness.seedSite(t)
	siteID := harness.siteID(t)
	definition, err := harness.provisioner.BuildDeleteJob(siteID, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.provisioner.Register(harness.manager); err != nil {
		t.Fatal(err)
	}
	// Reset the state the builder set so the job runs through cleanly.
	_ = harness.repo.SetState(context.Background(), siteID, StateDeleting)
	jobID, err := harness.manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	runJob(t, harness.manager, jobID)
	if len(*harness.dnsDeletes) != 0 {
		t.Fatalf("dns released despite opt-out: %v", *harness.dnsDeletes)
	}
	if len(*harness.backupCalls) != 1 {
		t.Fatalf("final backup missing: %v", *harness.backupCalls)
	}
}

func TestDeleteRejectsInvalidState(t *testing.T) {
	harness := newDeleteHarness(t)
	harness.seedSite(t)
	siteID := harness.siteID(t)
	if err := harness.repo.SetState(context.Background(), siteID, StateDeleting); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.provisioner.BuildDeleteJob(siteID, true); !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("got %v, want ErrInvalidStateTransition", err)
	}
}

func TestPurgeExpiredOnlyRemovesDueSites(t *testing.T) {
	harness := newDeleteHarness(t)
	harness.seedSite(t)
	siteID := harness.siteID(t)
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO site_quarantine(site_id, data_path, quarantined_at, purges_at)
			VALUES (?, '/srv/tompanel/quarantine/GARBAGE', 0, 0)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The unconfined garbage path must be refused by the agent boundary; the
	// fake agent accepts everything, so use a confined-looking path.
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), "UPDATE site_quarantine SET data_path = ? WHERE site_id = ?",
			"/srv/tompanel/quarantine/"+siteID+"-000000001", siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	kept := "ffffffffffffffffffffffffffffffff"
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES (?, 'static', 'quarantined', 'keep.example.test', 443, 0, 0, 0)`, kept); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO site_quarantine(site_id, data_path, quarantined_at, purges_at)
			VALUES (?, '/srv/tompanel/quarantine/GARBAGE-2', 0, 9999999999)`, kept)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := harness.provisioner.PurgeExpired(context.Background(), time.Unix(1_800_100_000, 0)); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := harness.store.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM site_quarantine").Scan(&remaining)
	}); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("quarantine rows = %d, want 1 (undue site kept)", remaining)
	}
	if _, err := harness.repo.Get(context.Background(), siteID); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("expired site row survived: %v", err)
	}
}

func TestDeleteJobInputCarriesOnlyIdentity(t *testing.T) {
	harness := newDeleteHarness(t)
	harness.seedSite(t)
	if err := harness.repo.SetState(context.Background(), harness.siteID(t), StateActive); err != nil {
		t.Fatal(err)
	}
	definition, err := harness.provisioner.BuildDeleteJob(harness.siteID(t), true)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(definition.Input, &input); err != nil {
		t.Fatal(err)
	}
	if len(input) != 2 {
		t.Fatalf("delete input must stay minimal: %v", input)
	}
	joined := strings.Join(stepKeys(definition), ",")
	if !strings.Contains(joined, "final_backup") || !strings.Contains(joined, "quarantine") {
		t.Fatalf("pipeline steps wrong: %s", joined)
	}
}

func stepKeys(definition jobs.Definition) []string {
	keys := make([]string, 0, len(definition.Steps))
	for _, step := range definition.Steps {
		keys = append(keys, step.Key)
	}
	return keys
}
