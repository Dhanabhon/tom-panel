package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	canonical "github.com/Dhanabhon/tom-panel/migrations"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.db.Close() })
	return s
}

func TestTxCommitsSuccessfulWork(t *testing.T) {
	s := openTestStore(t)
	err := s.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO settings(key, value, updated_at) VALUES ('theme', 'system', 1)")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'theme'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("committed rows = %d, want 1", count)
	}
}

func TestTxRollsBackFailedWork(t *testing.T) {
	s := openTestStore(t)
	wantErr := errors.New("stop")
	err := s.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO settings(key, value, updated_at) VALUES ('theme', 'system', 1)"); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Tx() error = %v, want %v", err, wantErr)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'theme'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back rows = %d, want 0", count)
	}
}

func TestMigrationsAreAtomic(t *testing.T) {
	s := openTestStore(t)
	err := migrate(context.Background(), s.db, fstest.MapFS{
		"0002_broken.sql": {Data: []byte("CREATE TABLE must_rollback (id INTEGER); this is not SQL;")},
	})
	if err == nil {
		t.Fatal("broken migration succeeded")
	}

	var versions int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("schema_migrations contains %d rows, want 1", versions)
	}

	var tables int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'must_rollback'").Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("partial migration survived rollback")
	}
}

func TestRuntimeMigrationsConsumeCanonicalFS(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "canonical.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate(context.Background(), db, canonical.FS); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := db.QueryRow("SELECT name FROM schema_migrations WHERE version = 1").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "0001_core.sql" {
		t.Fatalf("applied migration = %q, want 0001_core.sql", name)
	}
	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'admins'").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != 1 {
		t.Fatal("canonical migration did not create admins")
	}
	if _, err := canonical.FS.ReadFile(name); err != nil {
		t.Fatalf("applied migration is not in canonical FS: %v", err)
	}
}

func TestOpenConfiguresSQLite(t *testing.T) {
	s := openTestStore(t)
	for pragma, want := range map[string]string{
		"journal_mode": "wal",
		"foreign_keys": "1",
		"busy_timeout": "5000",
		"synchronous":  "2",
	} {
		var got string
		if err := s.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %s, want %s", pragma, got, want)
		}
	}

	for _, table := range []string{"admins", "sessions", "jobs", "job_steps", "audit_events", "managed_resources", "settings"} {
		var exists int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != 1 {
			t.Errorf("table %s does not exist", table)
		}
	}
}

func TestOpenConfiguresEveryReplacementConnection(t *testing.T) {
	s := openTestStore(t)
	s.db.SetMaxIdleConns(0)
	before := s.db.Stats().MaxIdleClosed
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=DELETE",
		"PRAGMA foreign_keys=OFF",
		"PRAGMA busy_timeout=0",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := conn.ExecContext(context.Background(), pragma); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if s.db.Stats().MaxIdleClosed <= before {
		t.Fatal("database/sql did not close the original physical connection")
	}

	replacement, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	for pragma, want := range map[string]string{
		"journal_mode": "wal",
		"foreign_keys": "1",
		"busy_timeout": "5000",
		"synchronous":  "2",
	} {
		var got string
		if err := replacement.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("replacement connection PRAGMA %s = %s, want %s", pragma, got, want)
		}
	}
}

func TestOpenRejectsInvalidMasterKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
		mode os.FileMode
	}{
		{name: "wrong length", key: []byte("short"), mode: 0o400},
		{name: "wrong mode", key: []byte("0123456789abcdef0123456789abcdef"), mode: 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "master.key")
			if err := os.WriteFile(keyPath, tc.key, tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath); err == nil {
				t.Fatal("invalid master key accepted")
			}
		})
	}
}
