package operations

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

	"github.com/Dhanabhon/tom-panel/internal/store"
)

func operationsStore(t *testing.T) *store.Store {
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
			VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'php', 'active', 'one.example.test', 443, 0, '8.4', 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return database
}

type fakeServiceAgent struct {
	units   []string
	replies map[string]map[string]any
}

func (f *fakeServiceAgent) call(_ context.Context, operation string, input, output any) error {
	encoded, _ := json.Marshal(input)
	var decoded map[string]any
	_ = json.Unmarshal(encoded, &decoded)
	unit, _ := decoded["unit"].(string)
	f.units = append(f.units, operation+":"+unit)
	if f.replies != nil && f.replies[operation] != nil && output != nil {
		reply, _ := json.Marshal(f.replies[operation])
		_ = json.Unmarshal(reply, output)
	}
	return nil
}

func TestServiceActionRejectsUnmanagedUnit(t *testing.T) {
	database := operationsStore(t)
	agent := &fakeServiceAgent{}
	manager := NewServiceManager(database, agent.call)
	if err := manager.Restart(context.Background(), "ssh.service"); !errors.Is(err, ErrUnmanagedService) {
		t.Fatalf("got %v, want ErrUnmanagedService", err)
	}
	if len(agent.units) != 0 {
		t.Fatalf("unmanaged action reached the agent: %v", agent.units)
	}
	if err := manager.Restart(context.Background(), "nginx"); err != nil {
		t.Fatal(err)
	}
	if len(agent.units) != 1 || agent.units[0] != "service.restart:nginx.service" {
		t.Fatalf("unexpected agent call: %v", agent.units)
	}
}

func TestInspectReportsImpactPerUnit(t *testing.T) {
	database := operationsStore(t)
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, php_version, created_at, updated_at)
			VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'static', 'active', 'two.example.test', 443, 0, NULL, 0, 0)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO databases(id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at)
			VALUES ('dddddddddddddddddddddddddddddd01', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'tp_aaaaaaaaaaaaaaaa_shop', 'shop', 'active', 1, 1, 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	agent := &fakeServiceAgent{replies: map[string]map[string]any{
		"service.inspect": {"active": true, "state": "active/running"},
	}}
	manager := NewServiceManager(database, agent.call)
	services, err := manager.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != len(ManagedKeys) {
		t.Fatalf("services = %d, want %d", len(services), len(ManagedKeys))
	}
	for _, service := range services {
		if !service.Active || service.State != "active/running" {
			t.Fatalf("unit state not reported: %+v", service)
		}
		switch service.Key {
		case "nginx":
			if len(service.ImpactedSites) != 2 {
				t.Fatalf("nginx must impact every site: %+v", service)
			}
		case "mariadb":
			if len(service.ImpactedSites) != 1 || service.ImpactedSites[0] != "one.example.test" {
				t.Fatalf("mariadb impact wrong: %+v", service)
			}
		case "php8.4":
			if len(service.ImpactedSites) != 1 || service.ImpactedSites[0] != "one.example.test" {
				t.Fatalf("php 8.4 impact wrong: %+v", service)
			}
		case "php8.3", "php8.5", "redis":
			if len(service.ImpactedSites) != 0 {
				t.Fatalf("%s should impact nobody: %+v", service.Key, service)
			}
		}
	}
}

type fakeLogAgent struct {
	captured map[string]any
	lines    []string
}

func (f *fakeLogAgent) call(_ context.Context, operation string, input, _ any) error {
	encoded, _ := json.Marshal(input)
	var decoded map[string]any
	_ = json.Unmarshal(encoded, &decoded)
	f.captured = decoded
	if operation == "log.read" {
		f.lines = append(f.lines, decoded["search"].(string))
	}
	return nil
}

func TestLogReaderRedactsRegisteredSecrets(t *testing.T) {
	if got := RedactLogLine(`POST /wp-login.php password=hunter2 user=tom`); strings.Contains(got, "hunter2") {
		t.Fatalf("password leaked: %s", got)
	}
	if got := RedactLogLine(`Authorization: Bearer abc123`); strings.Contains(got, "abc123") {
		t.Fatalf("token leaked: %s", got)
	}
	if got := RedactLogLine(`GET /healthz 200`); got != `GET /healthz 200` {
		t.Fatalf("plain line mangled: %s", got)
	}
}

func TestLogReaderBoundsAndValidates(t *testing.T) {
	reader := NewLogReader(func(context.Context, string, any, any) error { return nil })
	if _, err := reader.Read(context.Background(), LogQuery{SiteID: "a", Source: "syslog"}); !errors.Is(err, ErrUnsupportedLogSource) {
		t.Fatalf("got %v", err)
	}
	if _, err := reader.Read(context.Background(), LogQuery{SiteID: "a", Source: "app", Search: strings.Repeat("x", 300)}); err == nil {
		t.Fatal("oversized search accepted")
	}
	agent := &fakeLogAgent{}
	bounded := NewLogReader(agent.call)
	if _, err := bounded.Read(context.Background(), LogQuery{SiteID: strings.Repeat("a", 32), Source: "app", Search: "error", MaxLines: 10000}); err != nil {
		t.Fatal(err)
	}
	if agent.captured["max_lines"].(float64) != float64(logMaxLines) {
		t.Fatalf("line bound not enforced: %v", agent.captured["max_lines"])
	}
}

func TestRetentionDoesNotRecursivelyFlood(t *testing.T) {
	database := operationsStore(t)
	// Seed more rows than one batch.
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		for i := 0; i < retentionBatch+50; i++ {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO audit_events(id, admin_id, action, target_kind, target_id, detail_json, created_at)
				VALUES (?, 1, 'x', 't', 'v', '{}', ?)`, i+1, int64(i)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	retention := NewRetention(database, RetentionRules{JobsDays: 30, AuditDays: 180})
	retention.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	_, removed, err := retention.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if removed != retentionBatch+50 {
		t.Fatalf("removed = %d, want %d", removed, retentionBatch+50)
	}
	// A second pass finds nothing left to do.
	_, again, err := retention.Apply(context.Background())
	if err != nil || again != 0 {
		t.Fatalf("second pass removed %d rows: %v", again, err)
	}
}

func TestMetricsSnapshotReadsProc(t *testing.T) {
	procRoot := t.TempDir()
	files := map[string]string{
		"loadavg": "0.52 0.58 0.59 1/512 12345\n",
		"meminfo": "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2097152 kB\nSwapFree:        1048576 kB\n",
		"stat":    "cpu  100 0 100 700 0 0 0 0 0 0\ncpu0 50 0 50 350 0 0 0 0 0 0\n",
		"uptime":  "86400.42 160000.00\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(procRoot, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := ReadSnapshot(procRoot, t.TempDir())
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snapshot.MemoryTotalMB != 16000 || snapshot.MemoryUsedMB != 8000 {
		t.Fatalf("memory figures wrong: %+v", snapshot)
	}
	if snapshot.SwapUsedMB != 1024 {
		t.Fatalf("swap figures wrong: %+v", snapshot)
	}
	if snapshot.Load1 != 0.52 || snapshot.UptimeHours < 23.9 || snapshot.UptimeHours > 24.1 {
		t.Fatalf("load or uptime wrong: %+v", snapshot)
	}
	if snapshot.CPUPercent <= 0 || snapshot.CPUPercent >= 100 {
		t.Fatalf("cpu percent out of range: %+v", snapshot)
	}
}
