package store

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"io"
	"os"

	_ "modernc.org/sqlite"
)

// Store owns TomPanel's durable state and field-encryption primitive.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

// Open validates the master key, opens SQLite, configures durability, and applies migrations.
func Open(ctx context.Context, dbPath, keyPath string) (*Store, error) {
	key, err := readMasterKey(keyPath)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// ponytail: one connection keeps connection-local PRAGMAs invariant; use a connector hook if profiling requires a pool.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := initialize(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db, aead: aead}, nil
}

func initialize(ctx context.Context, db *sql.DB) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect sqlite: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=FULL",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure sqlite: %w", err)
		}
	}
	if err := migrate(ctx, db, coreMigrations); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func readMasterKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open master key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect master key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return nil, fmt.Errorf("master key must be a regular file with mode 0400")
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must contain exactly 32 bytes")
	}
	return key, nil
}

// Tx runs fn in a transaction and commits only when fn succeeds.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
