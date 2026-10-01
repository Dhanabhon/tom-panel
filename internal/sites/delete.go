package sites

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

// DeleteJobKind runs the guarded site deletion lifecycle.
const DeleteJobKind = "site.delete"

const quarantineDays = 7

// DNSRemover deletes one managed DNS record; domains.Service satisfies it.
type DNSRemover interface {
	DeleteDNS(ctx context.Context, id string) error
}

// DatabaseLister reports the databases owned by a site.
type DatabaseLister interface {
	List(ctx context.Context, siteID string) (names []string, users [][]string, err error)
}

// BackupFinalizer captures the final pre-deletion backup.
type BackupFinalizer interface {
	Create(ctx context.Context, siteID, kind string) (id string, err error)
}

// DeleteProvisioner builds the durable site deletion job. Deletion is a long
// pipeline: disable, final backup, optional DNS release, database teardown,
// and a seven-day metadata quarantine that never touches foreign resources.
type DeleteProvisioner struct {
	store     *store.Store
	repo      *Repository
	agent     func(ctx context.Context, operation string, input, output any) error
	dns       DNSRemover
	databases func(ctx context.Context, siteID string) ([]databaseTeardown, error)
	backups   func(ctx context.Context, siteID string) error
	now       func() time.Time
}

type databaseTeardown struct {
	Name      string
	Usernames []string
}

type deleteJobInput struct {
	SiteID          string `json:"site_id"`
	RemoveManagedDNS bool  `json:"remove_managed_dns"`
}

// NewDeleteProvisioner builds the provisioner with required collaborators.
func NewDeleteProvisioner(database *store.Store, repository *Repository, agentCall func(ctx context.Context, operation string, input, output any) error, dns DNSRemover) *DeleteProvisioner {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &DeleteProvisioner{
		store: database, repo: repository, agent: call, dns: dns, now: time.Now,
		databases: func(ctx context.Context, siteID string) ([]databaseTeardown, error) {
			var teardowns []databaseTeardown
			err := database.Tx(ctx, func(tx *sql.Tx) error {
				rows, err := tx.QueryContext(ctx, `SELECT d.id, d.name FROM databases d WHERE d.site_id = ?`, siteID)
				if err != nil {
					return err
				}
				var ids []string
				var names []string
				defer rows.Close()
				for rows.Next() {
					var id, name string
					if err := rows.Scan(&id, &name); err != nil {
						return err
					}
					ids = append(ids, id)
					names = append(names, name)
				}
				if err := rows.Err(); err != nil {
					return err
				}
				for index, id := range ids {
					userRows, err := tx.QueryContext(ctx, `SELECT username FROM database_credentials WHERE database_id = ?`, id)
					if err != nil {
						return err
					}
					var usernames []string
					for userRows.Next() {
						var username string
						if err := userRows.Scan(&username); err != nil {
							userRows.Close()
							return err
						}
						usernames = append(usernames, username)
					}
					userRows.Close()
					teardowns = append(teardowns, databaseTeardown{Name: names[index], Usernames: usernames})
				}
				return nil
			})
			return teardowns, err
		},
		backups: func(context.Context, string) error { return nil },
	}
}

// SetBackupFinalizer installs the final-backup step collaborator.
func (p *DeleteProvisioner) SetBackupFinalizer(finalize func(ctx context.Context, siteID string) error) {
	if finalize != nil {
		p.backups = finalize
	}
}

// BuildDeleteJob assembles the guarded deletion pipeline.
func (p *DeleteProvisioner) BuildDeleteJob(siteID string, removeManagedDNS bool) (jobs.Definition, error) {
	site, err := p.repo.Get(context.Background(), siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	switch site.State {
	case StateActive, StateDisabled, StateFailed:
	default:
		return jobs.Definition{}, fmt.Errorf("%w: %s", ErrInvalidStateTransition, site.State)
	}
	input, err := json.Marshal(deleteJobInput{SiteID: siteID, RemoveManagedDNS: removeManagedDNS})
	if err != nil {
		return jobs.Definition{}, err
	}
	def, err := p.buildDeleteJob(input, siteID, removeManagedDNS)
	if err != nil {
		return jobs.Definition{}, err
	}
	if err := p.repo.SetState(context.Background(), siteID, StateDeleting); err != nil {
		return jobs.Definition{}, err
	}
	return def, nil
}

func (p *DeleteProvisioner) buildDeleteJob(input json.RawMessage, siteID string, removeManagedDNS bool) (jobs.Definition, error) {
	return jobs.Definition{
		Kind:  DeleteJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "disable", Run: func(ctx context.Context) (json.RawMessage, error) {
				if err := p.agent(ctx, "nginx.disable", struct {
					SiteID string `json:"site_id"`
				}{siteID}, &struct{}{}); err != nil {
					return nil, err
				}
				if err := p.agent(ctx, "laravel.ensure_workers", struct {
					SiteID  string `json:"site_id"`
					Enabled bool   `json:"enabled"`
				}{siteID, false}, &struct{}{}); err != nil {
					return nil, err
				}
				return nil, p.agent(ctx, "sftp.disable_account", struct {
					SiteID string `json:"site_id"`
				}{siteID}, &struct{}{})
			}},
			{Key: "final_backup", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, p.backups(ctx, siteID)
			}},
			{Key: "release_dns", Run: func(ctx context.Context) (json.RawMessage, error) {
				if !removeManagedDNS {
					return nil, nil
				}
				ids, err := p.managedRecordIDs(ctx, siteID)
				if err != nil {
					return nil, err
				}
				for _, id := range ids {
					if err := p.dns.DeleteDNS(ctx, id); err != nil {
						return nil, fmt.Errorf("release managed dns %s: %w", id, err)
					}
				}
				return nil, nil
			}},
			{Key: "drop_databases", Run: func(ctx context.Context) (json.RawMessage, error) {
				teardowns, err := p.databases(ctx, siteID)
				if err != nil {
					return nil, err
				}
				for _, teardown := range teardowns {
					if err := p.agent(ctx, "mariadb.drop_database", struct {
						SiteID    string   `json:"site_id"`
						Database  string   `json:"database"`
						Usernames []string `json:"usernames"`
					}{siteID, teardown.Name, teardown.Usernames}, &struct{}{}); err != nil {
						return nil, err
					}
				}
				return nil, nil
			}},
			{Key: "quarantine", Run: func(ctx context.Context) (json.RawMessage, error) {
				var result struct {
					DataPath string `json:"data_path"`
				}
				if err := p.agent(ctx, "site.quarantine", struct {
					SiteID string `json:"site_id"`
				}{siteID}, &result); err != nil {
					return nil, err
				}
				now := p.now().UTC()
				err := p.store.Tx(ctx, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO site_quarantine(site_id, data_path, quarantined_at, purges_at)
						VALUES (?, ?, ?, ?) ON CONFLICT(site_id) DO UPDATE SET data_path = excluded.data_path, purges_at = excluded.purges_at`,
						siteID, result.DataPath, now.Unix(), now.Add(quarantineDays*24*time.Hour).Unix())
					return err
				})
				if err != nil {
					return nil, err
				}
				return nil, p.repo.SetState(ctx, siteID, StateQuarantined)
			}},
		},
	}, nil
}

// managedRecordIDs returns only this site's managed DNS records.
func (p *DeleteProvisioner) managedRecordIDs(ctx context.Context, siteID string) ([]string, error) {
	var ids []string
	err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM dns_records WHERE site_id = ? AND managed = 1`, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// PurgeExpired removes quarantines whose deadline passed. Only ledger-owned
// rows and the quarantined tree are removed.
func (p *DeleteProvisioner) PurgeExpired(ctx context.Context, at time.Time) error {
	var pending []struct {
		siteID   string
		dataPath string
	}
	err := p.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT site_id, data_path FROM site_quarantine WHERE purges_at <= ?`, at.Unix())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item struct {
				siteID   string
				dataPath string
			}
			if err := rows.Scan(&item.siteID, &item.dataPath); err != nil {
				return err
			}
			pending = append(pending, item)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range pending {
		if err := p.agent(ctx, "site.purge_quarantine", struct {
			SiteID   string `json:"site_id"`
			DataPath string `json:"data_path"`
		}{item.siteID, item.dataPath}, &struct{}{}); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := p.store.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "DELETE FROM site_quarantine WHERE site_id = ?", item.siteID); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "DELETE FROM sites WHERE id = ?", item.siteID)
			return err
		}); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Register wires the deletion job builder into the manager.
func (p *DeleteProvisioner) Register(manager *jobs.Manager) error {
	return manager.Register(DeleteJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed deleteJobInput
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		return p.buildDeleteJob(input, parsed.SiteID, parsed.RemoveManagedDNS)
	})
}
