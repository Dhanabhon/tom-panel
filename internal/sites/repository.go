package sites

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
	"modernc.org/sqlite"
)

var ErrSiteNotFound = errors.New("site not found")

type Repository struct {
	store *store.Store
	now   func() time.Time
}

func NewRepository(database *store.Store) *Repository {
	return &Repository{store: database, now: time.Now}
}

func (r *Repository) Create(ctx context.Context, input CreateInput) (Site, error) {
	if err := ValidateCreate(input, nil); err != nil {
		return Site{}, err
	}
	hostname, _ := normalizeHostname(input.PrimaryDomain)
	input.PrimaryDomain = hostname
	siteID, err := newID()
	if err != nil {
		return Site{}, err
	}
	domainID, err := newID()
	if err != nil {
		return Site{}, err
	}
	now := r.now().UTC().Truncate(time.Second)
	site := Site{
		ID: siteID, Kind: input.Kind, State: StateProvisioning,
		PrimaryDomain: hostname, HTTPPort: input.HTTPPort, HTTPSPort: input.HTTPSPort,
		PHPVersion: input.PHPVersion, ProxyTarget: input.ProxyTarget,
		CreatedAt: now, UpdatedAt: now,
	}
	err = r.store.Tx(ctx, func(tx *sql.Tx) error {
		var httpPort any
		if input.HTTPPort != 0 {
			httpPort = input.HTTPPort
		}
		var phpVersion, proxyTarget any
		if input.PHPVersion != "" {
			phpVersion = input.PHPVersion
		}
		if input.ProxyTarget != "" {
			proxyTarget = input.ProxyTarget
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sites
			(id, kind, state, primary_domain, http_port, https_port, php_version, proxy_target, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, site.ID, site.Kind, site.State, hostname, httpPort, input.HTTPSPort, phpVersion, proxyTarget, now.Unix(), now.Unix()); err != nil {
			return fmt.Errorf("insert site: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO domains
			(id, site_id, hostname, port, kind, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'primary', ?, ?)`, domainID, site.ID, hostname, input.HTTPSPort, now.Unix(), now.Unix()); err != nil {
			if isConstraint(err) {
				return ErrEndpointOccupied
			}
			return fmt.Errorf("insert primary domain: %w", err)
		}
		if input.HTTPPort != 0 && input.HTTPPort != input.HTTPSPort {
			httpDomainID, err := newID()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO domains
				(id, site_id, hostname, port, kind, created_at, updated_at)
				VALUES (?, ?, ?, ?, 'primary', ?, ?)`, httpDomainID, site.ID, hostname, input.HTTPPort, now.Unix(), now.Unix()); err != nil {
				if isConstraint(err) {
					return ErrEndpointOccupied
				}
				return fmt.Errorf("insert HTTP domain: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return Site{}, err
	}
	return site, nil
}

func (r *Repository) Get(ctx context.Context, id string) (Site, error) {
	var site Site
	var httpPort sql.NullInt64
	var phpVersion, proxyTarget sql.NullString
	var createdAt, updatedAt int64
	err := r.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, kind, state, primary_domain, http_port, https_port,
			php_version, proxy_target, created_at, updated_at FROM sites WHERE id = ?`, id).
			Scan(&site.ID, &site.Kind, &site.State, &site.PrimaryDomain, &httpPort, &site.HTTPSPort,
				&phpVersion, &proxyTarget, &createdAt, &updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Site{}, ErrSiteNotFound
	}
	if err != nil {
		return Site{}, fmt.Errorf("get site: %w", err)
	}
	site.HTTPPort = int(httpPort.Int64)
	site.PHPVersion = phpVersion.String
	site.ProxyTarget = proxyTarget.String
	site.CreatedAt = time.Unix(createdAt, 0).UTC()
	site.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return site, nil
}

func (r *Repository) SetState(ctx context.Context, id string, next State) error {
	return r.store.Tx(ctx, func(tx *sql.Tx) error {
		var current State
		if err := tx.QueryRowContext(ctx, "SELECT state FROM sites WHERE id = ?", id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return ErrSiteNotFound
		} else if err != nil {
			return fmt.Errorf("read site state: %w", err)
		}
		if err := ValidateStateTransition(current, next); err != nil {
			return err
		}
		if current == next {
			return nil
		}
		result, err := tx.ExecContext(ctx, "UPDATE sites SET state = ?, updated_at = ? WHERE id = ? AND state = ?", next, r.now().UTC().Unix(), id, current)
		if err != nil {
			return fmt.Errorf("update site state: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect site update: %w", err)
		}
		if changed != 1 {
			return errors.New("site state changed concurrently")
		}
		return nil
	})
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func isConstraint(err error) bool {
	var databaseError *sqlite.Error
	return errors.As(err, &databaseError) && databaseError.Code()&0xff == 19
}
