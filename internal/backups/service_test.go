package backups

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

const backupSiteID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newBackupStore(t *testing.T) *store.Store {
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
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES (?, 'php', 'active', 'backup.example.test', 443, 0, 0, 0)`, backupSiteID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO databases(id, site_id, name, suffix, state, active_generation, password_set, created_at, updated_at)
			VALUES ('dddddddddddddddddddddddddddddd01', ?, 'tp_bbbbbbbbbbbbbbbb_shop', 'shop', 'active', 1, 1, 0, 0)`, backupSiteID); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO database_credentials(id, database_id, username, generation, state, created_at)
			VALUES ('cccccccccccccccccccccccccccccc01', 'dddddddddddddddddddddddddddddd01', 'tp_bbbbbbbbbbbbbbbb_u1', 1, 'active', 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return database
}

type backupAgentLog struct {
	operations []string
	responses  map[string]any
	failOn     map[string]error
	uploads    []string
}

func (l *backupAgentLog) call(_ context.Context, operation string, input, output any) error {
	l.operations = append(l.operations, operation)
	if l.failOn != nil && l.failOn[operation] != nil {
		return l.failOn[operation]
	}
	if l.responses != nil && l.responses[operation] != nil && output != nil {
		encoded, _ := json.Marshal(l.responses[operation])
		_ = json.Unmarshal(encoded, output)
	}
	if operation == "backup.upload" {
		if encoded, err := json.Marshal(input); err == nil {
			l.uploads = append(l.uploads, string(encoded))
		}
	}
	return nil
}

func TestDiskGuardStopsBackupBelowTwoGiB(t *testing.T) {
	err := CheckDisk(DiskState{Total: 80 << 30, Used: 79 << 30, Free: 1 << 30})
	if !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("got %v, want ErrInsufficientDisk", err)
	}
	if err := CheckDisk(DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30}); err != nil {
		t.Fatalf("healthy disk rejected: %v", err)
	}
	if err := CheckDisk(DiskState{Total: 100 << 30, Used: 84 << 30, Free: 16 << 30}); err != nil {
		t.Fatalf("84%% use must still pass: %v", err)
	}
	if err := CheckDisk(DiskState{Total: 100 << 30, Used: 86 << 30, Free: 14 << 30}); !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("86%% use must stop: %v", err)
	}
}

func TestCreateStopsOnDiskGuard(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{"backup.disk_guard": DiskState{Total: 80 << 30, Used: 79 << 30, Free: 1 << 30}},
	}
	service := NewService(database, log.call)
	if _, _, err := service.Create(context.Background(), backupSiteID, string(KindManual)); !errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("got %v, want ErrInsufficientDisk", err)
	}
	if len(log.operations) != 1 {
		t.Fatalf("archive ran despite the disk guard: %v", log.operations)
	}
}

func TestCreateBuildsManifestAndPersists(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard":     DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":        archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 120, SHA256: strings.Repeat("a", 64)},
			"backup.database_dump":  archiveResult{Path: "/var/backups/tompanel/x/db-1.sql", Size: 80, SHA256: strings.Repeat("b", 64)},
		},
	}
	service := NewService(database, log.call)
	backup, manifest, err := service.Create(context.Background(), backupSiteID, string(KindManual))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != ManifestVersion || len(manifest.Files) != 1 || len(manifest.Database) != 1 {
		t.Fatalf("manifest incomplete: %+v", manifest)
	}
	if !manifest.Consistency.DatabaseSnapshotTxn || !manifest.Consistency.FilesArchiveStreamed {
		t.Fatalf("consistency flags missing: %+v", manifest.Consistency)
	}
	if !backup.Protected {
		t.Fatal("manual backups must be protected")
	}
	stored, parsed, err := service.Get(context.Background(), backup.ID)
	if err != nil || parsed.SiteID != backupSiteID || stored.State != "complete" {
		t.Fatalf("round-trip failed: %+v %+v %v", stored, parsed, err)
	}
}

func TestRestoreFailureReactivatesPreRestoreState(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard":  DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":     archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 120, SHA256: strings.Repeat("a", 64)},
			"backup.verify":      archiveResult{SHA256: strings.Repeat("a", 64)},
		},
		failOn: map[string]error{"backup.activate_restore": errors.New("activation failed")},
	}
	service := NewService(database, log.call)
	created, _, err := service.Create(context.Background(), backupSiteID, string(KindManual))
	if err != nil {
		t.Fatal(err)
	}
	log.operations = nil
	if err := service.Restore(context.Background(), created.ID); err == nil {
		t.Fatal("restore succeeded despite activation failure")
	}
	joined := strings.Join(log.operations, ",")
	if !strings.Contains(joined, "backup.restore_files") {
		t.Fatalf("restore never staged files: %s", joined)
	}
	// The failing restore must roll back to the pre-restore body.
	if !strings.Contains(joined, "backup.restore_files,backup.activate_restore,backup.restore_files,backup.activate_restore") &&
		!strings.Contains(joined, "backup.activate_restore,backup.restore_files") {
		t.Fatalf("rollback sequence missing: %s", joined)
	}
}

func TestRestoreVerifiesChecksumFirst(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard": DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":    archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 120, SHA256: strings.Repeat("a", 64)},
			"backup.verify":     archiveResult{SHA256: strings.Repeat("c", 64)},
		},
	}
	service := NewService(database, log.call)
	created, _, err := service.Create(context.Background(), backupSiteID, string(KindManual))
	if err != nil {
		t.Fatal(err)
	}
	log.operations = nil
	if err := service.Restore(context.Background(), created.ID); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("got %v, want ErrChecksumMismatch", err)
	}
	if len(log.operations) != 1 {
		t.Fatalf("restore continued past the checksum gate: %v", log.operations)
	}
}

func TestRetentionKeepsSevenScheduledAndProtectsManual(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard": DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":    archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 10, SHA256: strings.Repeat("a", 64)},
		},
	}
	service := NewService(database, log.call)
	base := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	for i := 0; i < 9; i++ {
		service.now = func() time.Time { return base.Add(time.Duration(i) * time.Hour) }
		if _, _, err := service.Create(context.Background(), backupSiteID, string(KindScheduled)); err != nil {
			t.Fatal(err)
		}
	}
	service.now = func() time.Time { return base.Add(24 * time.Hour) }
	if _, _, err := service.Create(context.Background(), backupSiteID, string(KindManual)); err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyRetention(context.Background(), backupSiteID); err != nil {
		t.Fatal(err)
	}
	items, err := service.List(context.Background(), backupSiteID)
	if err != nil {
		t.Fatal(err)
	}
	var scheduled, manual int
	for _, item := range items {
		switch item.Kind {
		case KindScheduled:
			scheduled++
		case KindManual:
			manual++
		}
	}
	if scheduled != retainedScheduled {
		t.Fatalf("scheduled retained = %d, want %d", scheduled, retainedScheduled)
	}
	if manual != 1 {
		t.Fatalf("manual backup touched by retention: %d", manual)
	}
}

func TestScheduleDueRunsOncePerDayAtStableSlot(t *testing.T) {
	database := newBackupStore(t)
	service := NewService(database, func(context.Context, string, any, any) error { return nil })
	hour, minute := DailySlot(backupSiteID)
	before := time.Date(2026, 10, 1, hour, minute-1, 0, 0, time.UTC)
	due, err := service.ScheduleDue(context.Background(), before)
	if err != nil || len(due) != 0 {
		t.Fatalf("not due before slot: %v %v", due, err)
	}
	atSlot := time.Date(2026, 10, 1, hour, minute, 0, 0, time.UTC)
	due, err = service.ScheduleDue(context.Background(), atSlot)
	if err != nil || len(due) != 1 || due[0] != backupSiteID {
		t.Fatalf("due at slot: %v %v", due, err)
	}
	again, _ := DailySlot(backupSiteID)
	if again != hour {
		t.Fatal("slot is not stable")
	}
}

func TestProtectedBackupRequiresForce(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard": DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":    archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 10, SHA256: strings.Repeat("a", 64)},
		},
	}
	service := NewService(database, log.call)
	created, _, err := service.Create(context.Background(), backupSiteID, string(KindManual))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background(), created.ID, false); !errors.Is(err, ErrProtectedBackup) {
		t.Fatalf("got %v, want ErrProtectedBackup", err)
	}
	if err := service.Delete(context.Background(), created.ID, true); err != nil {
		t.Fatalf("forced delete failed: %v", err)
	}
}

func TestRemoteUploadSendsEncryptedSettingsOnly(t *testing.T) {
	database := newBackupStore(t)
	log := &backupAgentLog{
		responses: map[string]any{
			"backup.disk_guard": DiskState{Total: 80 << 30, Used: 20 << 30, Free: 60 << 30},
			"backup.archive":    archiveResult{Path: "/var/backups/tompanel/x/files-1.tar.gz", Size: 10, SHA256: strings.Repeat("a", 64)},
			"backup.upload":     archiveResult{Path: "site/backup.tar.age", Size: 42, SHA256: strings.Repeat("d", 64)},
		},
	}
	service := NewService(database, log.call)
	service.SetRemoteProvider(func(context.Context) (RemoteSettings, bool) {
		return RemoteSettings{
			Bucket: "bucket", Region: "auto", AccessKeyID: "AKIA-test", SecretKey: "secret-key",
			AgeRecipient: "age1-test-recipient", Prefix: "tompanel",
		}, true
	})
	backup, _, err := service.Create(context.Background(), backupSiteID, string(KindScheduled))
	if err != nil {
		t.Fatal(err)
	}
	if backup.Storage != StorageLocalS3 || backup.ObjectKey != "site/backup.tar.age" {
		t.Fatalf("remote upload not recorded: %+v", backup)
	}
	if len(log.uploads) != 1 {
		t.Fatalf("expected one upload: %v", log.uploads)
	}
	// The secret key crosses the protected socket but the key hint in the
	// persisted row must never include credentials.
	if strings.Contains(backup.ObjectKey, "AKIA") || strings.Contains(backup.ObjectKey, "secret-key") {
		t.Fatal("credentials leaked into persisted fields")
	}
}

func TestManifestRoundTripAndValidation(t *testing.T) {
	manifest := Manifest{Version: ManifestVersion, SiteID: backupSiteID, CreatedAt: 1}
	manifest.AppendFile("a.tar.gz", 5, "aa")
	manifest.AppendDatabase("db", "/var/backups/x/db.sql", 7, "bb")
	encoded, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(encoded)
	if err != nil || len(parsed.Files) != 1 || parsed.Database[0].Path != "/var/backups/x/db.sql" {
		t.Fatalf("round trip failed: %+v %v", parsed, err)
	}
	if _, err := ParseManifest([]byte(`{"version":0}`)); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("invalid manifest accepted: %v", err)
	}
}
