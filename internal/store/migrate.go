package store

import (
	"context"
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	name    string
	sql     string
}

var coreMigrations = []migration{{version: 1, name: "0001_core.sql", sql: coreSchema}}

func migrate(ctx context.Context, db *sql.DB, migrations []migration) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	for _, m := range migrations {
		var applied int
		err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", m.version).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if applied != 0 {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", m.version, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("apply migration %d: %w", m.version, err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, name) VALUES (?, ?)", m.version, m.name); err != nil {
		return fmt.Errorf("record migration %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", m.version, err)
	}
	return nil
}

const coreSchema = `
CREATE TABLE admins (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    totp_secret BLOB,
    recovery_codes BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash BLOB PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    step_up_until INTEGER
);

CREATE INDEX sessions_admin_id ON sessions(admin_id);
CREATE INDEX sessions_expiry ON sessions(absolute_expires_at);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    input_json BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelling', 'cancelled')),
    error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER
);

CREATE INDEX jobs_status_created ON jobs(status, created_at);

CREATE TABLE job_steps (
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    step_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    result_json BLOB,
    redacted_output TEXT,
    error TEXT,
    started_at INTEGER,
    finished_at INTEGER,
    PRIMARY KEY (job_id, step_key),
    UNIQUE (job_id, position)
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_kind TEXT,
    target_id TEXT,
    detail_json BLOB NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);

CREATE INDEX audit_events_created ON audit_events(created_at);

CREATE TABLE managed_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    external_id TEXT,
    path TEXT,
    owner_job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    CHECK (external_id IS NOT NULL OR path IS NOT NULL)
);

CREATE INDEX managed_resources_owner_job ON managed_resources(owner_job_id);
CREATE UNIQUE INDEX managed_resources_external ON managed_resources(kind, external_id) WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX managed_resources_path ON managed_resources(kind, path) WHERE path IS NOT NULL;

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);`
