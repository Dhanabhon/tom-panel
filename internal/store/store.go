package store

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/Dhanabhon/tom-panel/migrations"
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

	db, err := sql.Open("sqlite", sqliteDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
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
	if err := migrate(ctx, db, migrations.FS); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func sqliteDSN(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	query := u.Query()
	query.Set("_journal_mode", "WAL")
	query.Set("_foreign_keys", "ON")
	query.Set("_busy_timeout", "5000")
	query.Set("_synchronous", "FULL")
	u.RawQuery = query.Encode()
	return u.String()
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
