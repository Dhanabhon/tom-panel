package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

var (
	ErrUnsupportedPHP   = errors.New("unsupported PHP version")
	ErrPostBelowUpload  = errors.New("PHP post limit is below upload limit")
	ErrInvalidPHPConfig = errors.New("invalid PHP configuration")
	ErrNotPHPSite       = errors.New("site does not use PHP")
)

type PHPConfig struct {
	Version          string
	MemoryMB         int
	UploadMB         int
	PostMB           int
	ExecutionSeconds int
	InputVars        int
	DisplayErrors    bool
}

func DefaultPHPConfig(version string) PHPConfig {
	return PHPConfig{Version: version, MemoryMB: 256, UploadMB: 64, PostMB: 64, ExecutionSeconds: 60, InputVars: 1000}
}

func ValidatePHPConfig(config PHPConfig) error {
	if config.Version != "8.3" && config.Version != "8.4" && config.Version != "8.5" {
		return ErrUnsupportedPHP
	}
	if config.MemoryMB < 64 || config.MemoryMB > 2048 || config.UploadMB < 1 || config.UploadMB > 1024 ||
		config.PostMB < 1 || config.PostMB > 2048 || config.ExecutionSeconds < 1 || config.ExecutionSeconds > 600 ||
		config.InputVars < 100 || config.InputVars > 10000 {
		return ErrInvalidPHPConfig
	}
	if config.PostMB < config.UploadMB {
		return ErrPostBelowUpload
	}
	return nil
}

type Service struct{ store *store.Store }

func NewService(database *store.Store) *Service { return &Service{store: database} }

func (s *Service) SaveConfig(ctx context.Context, siteID string, config PHPConfig) error {
	if len(siteID) != 32 {
		return ErrInvalidPHPConfig
	}
	if err := ValidatePHPConfig(config); err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		var kind string
		if err := tx.QueryRowContext(ctx, "SELECT kind FROM sites WHERE id = ?", siteID).Scan(&kind); err != nil || kind != "php" {
			return ErrNotPHPSite
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO php_runtimes(version, installed, updated_at) VALUES (?, 0, unixepoch())
			ON CONFLICT(version) DO NOTHING`, config.Version); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO site_php_config
			(site_id, version, memory_mb, upload_mb, post_mb, execution_seconds, input_vars, display_errors, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
			ON CONFLICT(site_id) DO UPDATE SET version=excluded.version, memory_mb=excluded.memory_mb,
			upload_mb=excluded.upload_mb, post_mb=excluded.post_mb, execution_seconds=excluded.execution_seconds,
			input_vars=excluded.input_vars, display_errors=excluded.display_errors, updated_at=excluded.updated_at`,
			siteID, config.Version, config.MemoryMB, config.UploadMB, config.PostMB,
			config.ExecutionSeconds, config.InputVars, config.DisplayErrors)
		return err
	})
}

func (s *Service) AffectedSites(ctx context.Context, version string) ([]string, error) {
	if version != "8.3" && version != "8.4" && version != "8.5" {
		return nil, ErrUnsupportedPHP
	}
	var sites []string
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT site_id FROM site_php_config WHERE version = ? ORDER BY site_id`, version)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			sites = append(sites, id)
		}
		return rows.Err()
	})
	sort.Strings(sites)
	return sites, err
}

func (s *Service) Config(ctx context.Context, siteID string) (PHPConfig, error) {
	var config PHPConfig
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT version, memory_mb, upload_mb, post_mb, execution_seconds, input_vars, display_errors
			FROM site_php_config WHERE site_id = ?`, siteID).Scan(&config.Version, &config.MemoryMB, &config.UploadMB,
			&config.PostMB, &config.ExecutionSeconds, &config.InputVars, &config.DisplayErrors)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return PHPConfig{}, fmt.Errorf("PHP configuration not found")
	}
	return config, err
}
