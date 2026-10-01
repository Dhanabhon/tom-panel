package backups

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

type agentCaller func(ctx context.Context, operation string, input, output any) error

// Service owns backup lifecycle and guarded restores.
type Service struct {
	store     *store.Store
	now       func() time.Time
	agent     agentCaller
	remote    func(ctx context.Context) (RemoteSettings, bool)
	health    func(ctx context.Context, siteID string) error
	databases func(ctx context.Context, siteID string) ([]string, error)
}

// NewService builds the backups service. remote, health, and databases are
// optional collaborators wired by the application.
func NewService(database *store.Store, agentCall func(ctx context.Context, operation string, input, output any) error) *Service {
	call := agentCaller(agentCall)
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &Service{
		store: database, now: time.Now, agent: call,
		remote: func(context.Context) (RemoteSettings, bool) { return RemoteSettings{}, false },
		health: func(context.Context, string) error { return nil },
		databases: func(ctx context.Context, siteID string) ([]string, error) {
			var names []string
			err := database.Tx(ctx, func(tx *sql.Tx) error {
				rows, err := tx.QueryContext(ctx, "SELECT name FROM databases WHERE site_id = ? ORDER BY name", siteID)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var name string
					if err := rows.Scan(&name); err != nil {
						return err
					}
					names = append(names, name)
				}
				return rows.Err()
			})
			return names, err
		},
	}
}

// SetRemoteProvider installs the object-storage configuration lookup.
func (s *Service) SetRemoteProvider(provider func(ctx context.Context) (RemoteSettings, bool)) {
	if provider != nil {
		s.remote = provider
	}
}

// SetHealthCheck installs the post-restore application health gate.
func (s *Service) SetHealthCheck(check func(ctx context.Context, siteID string) error) {
	if check != nil {
		s.health = check
	}
}

type archiveResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Create captures one guarded backup of a site.
func (s *Service) Create(ctx context.Context, siteID, kind string) (Backup, Manifest, error) {
	if kind != string(KindManual) && kind != string(KindScheduled) && kind != string(KindPreRestore) && kind != string(KindFinal) {
		return Backup{}, Manifest{}, errors.New("backup kind is unsupported")
	}
	if kind == string(KindManual) || kind == string(KindScheduled) {
		var disk DiskState
		if err := s.agent(ctx, "backup.disk_guard", struct {
			SiteID string `json:"site_id"`
		}{siteID}, &disk); err != nil {
			return Backup{}, Manifest{}, err
		}
		if err := CheckDisk(disk); err != nil {
			return Backup{}, Manifest{}, err
		}
	}
	var files archiveResult
	if err := s.agent(ctx, "backup.archive", struct {
		SiteID string `json:"site_id"`
	}{siteID}, &files); err != nil {
		return Backup{}, Manifest{}, fmt.Errorf("archive site files: %w", err)
	}
	manifest := Manifest{
		Version: ManifestVersion, SiteID: siteID, Kind: kind, CreatedAt: s.now().UTC().Unix(),
		ToolVersions: map[string]string{"tompanel": "mvp"},
		Consistency:  Consistency{FilesArchiveStreamed: true, DatabaseSnapshotTxn: true},
	}
	manifest.AppendFile(files.Path, files.Size, files.SHA256)
	names, err := s.databases(ctx, siteID)
	if err != nil {
		return Backup{}, Manifest{}, err
	}
	for _, name := range names {
		var dump archiveResult
		if err := s.agent(ctx, "backup.database_dump", struct {
			SiteID   string `json:"site_id"`
			Database string `json:"database"`
		}{siteID, name}, &dump); err != nil {
			return Backup{}, Manifest{}, fmt.Errorf("dump database %s: %w", name, err)
		}
		manifest.AppendDatabase(name, dump.Path, dump.Size, dump.SHA256)
	}
	id, err := newBackupID()
	if err != nil {
		return Backup{}, Manifest{}, err
	}
	manifestBytes, err := manifest.CanonicalJSON()
	if err != nil {
		return Backup{}, Manifest{}, err
	}
	backup := Backup{
		ID: id, SiteID: siteID, Kind: Kind(kind), Storage: StorageLocal, State: "complete",
		SizeBytes: files.Size, SHA256: files.SHA256, Manifest: manifestBytes,
		Protected: kind == string(KindManual) || kind == string(KindPreRestore),
		CreatedAt: s.now().UTC().Truncate(time.Second),
	}
	if remote, ok := s.remote(ctx); ok && remote.Valid() {
		key := remote.ObjectKey(siteID, id)
		var upload archiveResult
		if err := s.agent(ctx, "backup.upload", struct {
			SiteID       string          `json:"site_id"`
			Path         string          `json:"path"`
			Key          string          `json:"key"`
			Settings     RemoteSettings  `json:"settings"`
		}{siteID, files.Path, key, remote}, &upload); err != nil {
			// Local backup remains usable; remote copy is optional.
			backup.State = "complete"
		} else {
			backup.Storage = StorageLocalS3
			backup.ObjectKey = upload.Path
		}
	}
	if err := s.insert(ctx, backup); err != nil {
		return Backup{}, Manifest{}, err
	}
	return backup, manifest, nil
}

// Verify re-checks the stored body against its recorded checksum.
func (s *Service) Verify(ctx context.Context, backupID string) error {
	backup, _, err := s.Get(ctx, backupID)
	if err != nil {
		return err
	}
	var result struct {
		SHA256 string `json:"sha256"`
	}
	if err := s.agent(ctx, "backup.verify", struct {
		SiteID string `json:"site_id"`
		Path   string `json:"path"`
	}{backup.SiteID, backup.AgentPath}, &result); err != nil {
		return err
	}
	if result.SHA256 != backup.SHA256 {
		return ErrChecksumMismatch
	}
	return nil
}

// Restore replays one backup with a pre-restore safety copy and rollback.
func (s *Service) Restore(ctx context.Context, backupID string) error {
	backup, manifest, err := s.Get(ctx, backupID)
	if err != nil {
		return err
	}
	if err := s.Verify(ctx, backupID); err != nil {
		return err
	}
	preRestore, _, err := s.Create(ctx, backup.SiteID, string(KindPreRestore))
	if err != nil {
		return fmt.Errorf("capture pre-restore backup: %w", err)
	}
	restoreBody := func(source Backup, m Manifest) error {
		if err := s.agent(ctx, "backup.restore_files", struct {
			SiteID string `json:"site_id"`
			Path   string `json:"path"`
		}{source.SiteID, source.AgentPath}, &struct{}{}); err != nil {
			return fmt.Errorf("stage files: %w", err)
		}
		for _, database := range m.Database {
			if err := s.agent(ctx, "backup.restore_database", struct {
				SiteID   string `json:"site_id"`
				Database string `json:"database"`
				Path     string `json:"path"`
			}{source.SiteID, database.Name, database.Path}, &struct{}{}); err != nil {
				return fmt.Errorf("stage database: %w", err)
			}
		}
		return nil
	}
	if err := restoreBody(backup, manifest); err != nil {
		return err
	}
	if err := s.agent(ctx, "backup.validate_restore", struct {
		SiteID string `json:"site_id"`
	}{backup.SiteID}, &struct{}{}); err != nil {
		return errors.Join(err, s.rollback(ctx, preRestore))
	}
	if err := s.agent(ctx, "backup.activate_restore", struct {
		SiteID string `json:"site_id"`
	}{backup.SiteID}, &struct{}{}); err != nil {
		return errors.Join(err, s.rollback(ctx, preRestore))
	}
	if err := s.health(ctx, backup.SiteID); err != nil {
		return errors.Join(fmt.Errorf("health check after restore: %w", err), s.rollback(ctx, preRestore))
	}
	return nil
}

// rollback replays the pre-restore backup bodies to reactivate the previous
// state after a failed restore.
func (s *Service) rollback(ctx context.Context, preRestore Backup) error {
	manifest, err := ParseManifest(preRestore.Manifest)
	if err != nil {
		return err
	}
	if len(manifest.Files) == 0 {
		return errors.New("pre-restore manifest is empty")
	}
	if err := s.agent(ctx, "backup.restore_files", struct {
		SiteID string `json:"site_id"`
		Path   string `json:"path"`
	}{preRestore.SiteID, manifest.Files[0].Name}, &struct{}{}); err != nil {
		return err
	}
	if err := s.agent(ctx, "backup.activate_restore", struct {
		SiteID string `json:"site_id"`
	}{preRestore.SiteID}, &struct{}{}); err != nil {
		return err
	}
	return nil
}

// Delete removes one backup body and row.
func (s *Service) Delete(ctx context.Context, backupID string, force bool) error {
	backup, _, err := s.Get(ctx, backupID)
	if err != nil {
		return err
	}
	if backup.Protected && !force {
		return ErrProtectedBackup
	}
	if backup.AgentPath != "" {
		if err := s.agent(ctx, "backup.delete_local", struct {
			SiteID string `json:"site_id"`
			Path   string `json:"path"`
		}{backup.SiteID, backup.AgentPath}, &struct{}{}); err != nil {
			return err
		}
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "DELETE FROM backups WHERE id = ?", backupID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrBackupNotFound
		}
		return nil
	})
}

// ApplyRetention keeps the seven newest scheduled local backups per site and
// never touches manual, pre-restore, or final backups.
func (s *Service) ApplyRetention(ctx context.Context, siteID string) error {
	var ids []string
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM backups
			WHERE site_id = ? AND kind = 'scheduled' AND storage IN ('local', 'local+s3')
			ORDER BY created_at DESC, id DESC`, siteID)
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
	if err != nil {
		return err
	}
	var failures []error
	for index, id := range ids {
		if index < retainedScheduled {
			continue
		}
		if err := s.Delete(ctx, id, false); err != nil && !errors.Is(err, ErrProtectedBackup) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// DailySlot derives the stable randomized daily backup time of a site.
func DailySlot(siteID string) (hour, minute int) {
	sum := sha256.Sum256([]byte("tompanel.backup.slot:" + siteID))
	slot := int(sum[0])<<8 | int(sum[1])
	return slot % 24, (slot >> 8) % 60
}

// ScheduleDue returns the site IDs whose scheduled backup is due and not yet
// created today, oldest slot first.
func (s *Service) ScheduleDue(ctx context.Context, at time.Time) ([]string, error) {
	day := at.UTC().Truncate(24 * time.Hour)
	var candidates []string
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT s.id FROM sites s
			WHERE s.state = 'active'
			  AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id = s.id AND b.kind = 'scheduled' AND b.created_at >= ?)
			ORDER BY s.id`, day.Unix())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			candidates = append(candidates, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(candidates, func(i, j int) bool {
		hi, mi := DailySlot(candidates[i])
		hj, mj := DailySlot(candidates[j])
		if hi != hj {
			return hi < hj
		}
		return mi < mj
	})
	var due []string
	for _, siteID := range candidates {
		hour, minute := DailySlot(siteID)
		if at.UTC().Hour() > hour || at.UTC().Hour() == hour && at.UTC().Minute() >= minute {
			due = append(due, siteID)
		}
	}
	return due, nil
}

// Get loads one backup with its manifest.
func (s *Service) Get(ctx context.Context, backupID string) (Backup, Manifest, error) {
	var backup Backup
	var manifestBytes []byte
	var createdAt int64
	var expires sql.NullInt64
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, kind, storage, state, coalesce(agent_path, ''), coalesce(object_key, ''),
			size_bytes, sha256, manifest, protected, created_at, expires_at
			FROM backups WHERE id = ?`, backupID).
			Scan(&backup.ID, &backup.SiteID, &backup.Kind, &backup.Storage, &backup.State, &backup.AgentPath, &backup.ObjectKey,
				&backup.SizeBytes, &backup.SHA256, &manifestBytes, &backup.Protected, &createdAt, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Backup{}, Manifest{}, ErrBackupNotFound
	}
	if err != nil {
		return Backup{}, Manifest{}, fmt.Errorf("get backup: %w", err)
	}
	backup.CreatedAt = time.Unix(createdAt, 0).UTC()
	if expires.Valid {
		expiry := time.Unix(expires.Int64, 0).UTC()
		backup.ExpiresAt = &expiry
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return Backup{}, Manifest{}, err
	}
	backup.Manifest = manifestBytes
	return backup, manifest, nil
}

// List returns the backups of one site, newest first.
func (s *Service) List(ctx context.Context, siteID string) ([]Backup, error) {
	var result []Backup
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, kind, storage, state, coalesce(agent_path, ''), coalesce(object_key, ''),
			size_bytes, sha256, protected, created_at FROM backups WHERE site_id = ? ORDER BY created_at DESC, id DESC LIMIT 100`, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var backup Backup
			var createdAt int64
			if err := rows.Scan(&backup.ID, &backup.Kind, &backup.Storage, &backup.State, &backup.AgentPath, &backup.ObjectKey,
				&backup.SizeBytes, &backup.SHA256, &backup.Protected, &createdAt); err != nil {
				return err
			}
			backup.SiteID = siteID
			backup.CreatedAt = time.Unix(createdAt, 0).UTC()
			result = append(result, backup)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) insert(ctx context.Context, backup Backup) error {
	var expires any
	if backup.ExpiresAt != nil {
		expires = backup.ExpiresAt.Unix()
	}
	if len(backup.Manifest) == 0 {
		backup.Manifest = json.RawMessage(`{}`)
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO backups(id, site_id, kind, storage, state, agent_path, object_key, size_bytes, sha256, manifest, protected, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`,
			backup.ID, backup.SiteID, backup.Kind, backup.Storage, backup.State, backup.AgentPath, backup.ObjectKey,
			backup.SizeBytes, backup.SHA256, []byte(backup.Manifest), boolInt(backup.Protected), backup.CreatedAt.Unix(), expires)
		return err
	})
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
