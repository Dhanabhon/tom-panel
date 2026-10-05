package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/files"
)

// backupRootPath is the root of every local backup body.
var backupRootPath = "/var/backups/tompanel"

// backupEnvironment carries every privileged effect for tests.
type backupEnvironment struct {
	backupRoot string
	uploader   func(ctx context.Context, settings backups.RemoteSettings, key string, body io.Reader, size int64) (uploaded int64, err error)
}

func defaultBackupEnvironment() backupEnvironment {
	return backupEnvironment{
		backupRoot: backupRootPath,
		uploader:   uploadEncryptedObject,
	}
}

type backupSiteInput struct {
	SiteID string `json:"site_id"`
}

type backupPathInput struct {
	SiteID string `json:"site_id"`
	Path   string `json:"path"`
}

type backupDumpInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
}

type backupRestoreDatabaseInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Path     string `json:"path"`
}

type backupUploadInput struct {
	SiteID   string                 `json:"site_id"`
	Path     string                 `json:"path"`
	Key      string                 `json:"key"`
	Settings backups.RemoteSettings `json:"settings"`
}

type backupBodyResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func confinedBackupPath(root, siteID, path string) bool {
	want := filepath.Join(root, siteID) + string(os.PathSeparator)
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, want)
}

// diskGuardBackup reports the free-space state of the backup volume.
func diskGuardBackup(ctx context.Context, input backupSiteInput) (backups.DiskState, error) {
	if !validSiteID(input.SiteID) {
		return backups.DiskState{}, errors.New("backup.disk_guard payload is invalid")
	}
	var stat syscall.Statfs_t
	if err := statfsDeepestExisting(backupRootPath, &stat); err != nil {
		return backups.DiskState{}, fmt.Errorf("stat backup volume: %w", err)
	}
	blockSize := uint64(stat.Bsize)
	if blockSize == 0 {
		return backups.DiskState{}, errors.New("backup volume block size is invalid")
	}
	return backups.DiskState{
		Total: stat.Blocks * blockSize,
		Free:  stat.Bavail * blockSize,
		Used:  (stat.Blocks - stat.Bfree) * blockSize,
	}, nil
}

// archiveBackupSite captures one tar.gz of the site tree, skipping panel
// internals and the trash area.
func archiveBackupSite(ctx context.Context, input backupSiteInput, env backupEnvironment) (backupBodyResult, error) {
	if !validSiteID(input.SiteID) {
		return backupBodyResult{}, errors.New("backup.archive payload is invalid")
	}
	sitesRoot, err := os.OpenRoot(siteRootPath)
	if err != nil {
		return backupBodyResult{}, err
	}
	if _, err := sitesRoot.Lstat(input.SiteID); err != nil {
		return backupBodyResult{}, fmt.Errorf("site tree missing: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(env.backupRoot, input.SiteID), 0o750); err != nil {
		return backupBodyResult{}, err
	}
	backupRoot, err := os.OpenRoot(env.backupRoot)
	if err != nil {
		return backupBodyResult{}, err
	}
	if err := backupRoot.MkdirAll(input.SiteID, 0o750); err != nil {
		return backupBodyResult{}, err
	}
	name := fmt.Sprintf("files-%d.tar.gz", time.Now().UTC().Unix())
	relative := filepath.Join(input.SiteID, name)
	siteRoot, err := os.OpenRoot(filepath.Join(siteRootPath, input.SiteID))
	if err != nil {
		return backupBodyResult{}, err
	}
	defer siteRoot.Close()
	temporary := filepath.Join(input.SiteID, "."+name+".partial")
	body, err := backupRoot.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return backupBodyResult{}, err
	}
	writeErr := files.ArchiveTo(siteRoot, []string{"public"}, body, files.DefaultLimits())
	closeErr := body.Close()
	if writeErr != nil || closeErr != nil {
		_ = backupRoot.Remove(temporary)
		if writeErr != nil {
			return backupBodyResult{}, writeErr
		}
		return backupBodyResult{}, closeErr
	}
	if err := backupRoot.Rename(temporary, relative); err != nil {
		_ = backupRoot.Remove(temporary)
		return backupBodyResult{}, err
	}
	return hashBackupBody(backupRoot, relative)
}

func hashBackupBody(root *os.Root, relative string) (backupBodyResult, error) {
	handle, err := root.Open(relative)
	if err != nil {
		return backupBodyResult{}, err
	}
	defer handle.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, handle)
	if err != nil {
		return backupBodyResult{}, err
	}
	return backupBodyResult{
		Path:   filepath.Join(root.Name(), relative),
		Size:   size,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func dumpBackupDatabase(ctx context.Context, input backupDumpInput) (backupBodyResult, error) {
	result, err := dumpMariaDBDatabase(ctx, mariadbDatabaseInput{SiteID: input.SiteID, Database: input.Database}, defaultMariaDBEnvironment())
	if err != nil {
		return backupBodyResult{}, err
	}
	return backupBodyResult{Path: result.Path, Size: result.Size, SHA256: result.SHA256}, nil
}

// verifyBackupBody re-hashes one confined backup body.
func verifyBackupBody(ctx context.Context, input backupPathInput) (backupBodyResult, error) {
	if !validSiteID(input.SiteID) {
		return backupBodyResult{}, errors.New("backup.verify payload is invalid")
	}
	root, err := os.OpenRoot(backupRootPath)
	if err != nil {
		return backupBodyResult{}, err
	}
	defer root.Close()
	relative, err := filepath.Rel(backupRootPath, input.Path)
	if err != nil || !confinedBackupPath(backupRootPath, input.SiteID, input.Path) {
		return backupBodyResult{}, errors.New("backup.verify path is not confined")
	}
	return hashBackupBody(root, relative)
}

// uploadBackup streams the local body through age encryption into object
// storage. Plaintext never leaves this machine in the clear.
func uploadBackup(ctx context.Context, input backupUploadInput, env backupEnvironment) (backupBodyResult, error) {
	if !validSiteID(input.SiteID) || !input.Settings.Valid() || input.Key == "" {
		return backupBodyResult{}, errors.New("backup.upload payload is invalid")
	}
	if !confinedBackupPath(env.backupRoot, input.SiteID, input.Path) {
		return backupBodyResult{}, errors.New("backup.upload path is not confined")
	}
	handle, err := os.Open(input.Path)
	if err != nil {
		return backupBodyResult{}, err
	}
	defer handle.Close()
	recipient, err := parseAgeRecipient(input.Settings.AgeRecipient)
	if err != nil {
		return backupBodyResult{}, err
	}
	hasher := sha256.New()
	encrypted, err := ageEncryptReader(handle, recipient)
	if err != nil {
		return backupBodyResult{}, err
	}
	counting := &countingReader{reader: encrypted, counter: hasher}
	uploaded, err := env.uploader(ctx, input.Settings, input.Key, counting, -1)
	if err != nil {
		return backupBodyResult{}, err
	}
	return backupBodyResult{
		Path:   input.Key,
		Size:   uploaded,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

type countingReader struct {
	reader  io.Reader
	counter io.Writer
	read    int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 {
		c.read += int64(n)
		if _, hashErr := c.counter.Write(p[:n]); hashErr != nil && err == nil {
			err = hashErr
		}
	}
	return n, err
}

// restoreBackupFiles extracts one archive into a staging directory inside the
// site root using the File Manager extraction guards.
func restoreBackupFiles(ctx context.Context, input backupPathInput) error {
	if !validSiteID(input.SiteID) || !confinedBackupPath(backupRootPath, input.SiteID, input.Path) {
		return errors.New("backup.restore_files payload is invalid")
	}
	siteRoot, err := os.OpenRoot(filepath.Join(siteRootPath, input.SiteID))
	if err != nil {
		return err
	}
	defer siteRoot.Close()
	staging := filepath.Join(".tompanel", "restore-staging")
	_ = siteRoot.RemoveAll(staging)
	if err := siteRoot.MkdirAll(staging, 0o750); err != nil {
		return err
	}
	archive, err := os.Open(input.Path)
	if err != nil {
		return err
	}
	defer archive.Close()
	stagingRoot, err := siteRoot.OpenRoot(staging)
	if err != nil {
		return err
	}
	defer stagingRoot.Close()
	return files.Extract(stagingRoot, archive, files.DefaultLimits())
}

func restoreBackupDatabase(ctx context.Context, input backupRestoreDatabaseInput) error {
	return restoreMariaDBDatabase(ctx, mariadbRestoreInput{
		SiteID: input.SiteID, Database: input.Database, Path: input.Path,
	}, defaultMariaDBEnvironment())
}

// validateBackupRestore checks the staged tree shape before activation.
func validateBackupRestore(ctx context.Context, input backupSiteInput) error {
	if !validSiteID(input.SiteID) {
		return errors.New("backup.validate_restore payload is invalid")
	}
	root, err := os.OpenRoot(filepath.Join(siteRootPath, input.SiteID))
	if err != nil {
		return err
	}
	defer root.Close()
	staging := filepath.Join(".tompanel", "restore-staging")
	info, err := root.Lstat(staging)
	if err != nil || !info.IsDir() {
		return errors.New("restore staging is missing")
	}
	handle, err := root.Open(staging)
	if err != nil {
		return err
	}
	defer handle.Close()
	entries, err := handle.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("restore staging is empty")
	}
	return nil
}

// activateBackupRestore swaps the staged tree with the live one atomically.
// The previous live tree is preserved under .tompanel for rollback.
func activateBackupRestore(ctx context.Context, input backupSiteInput) error {
	if !validSiteID(input.SiteID) {
		return errors.New("backup.activate_restore payload is invalid")
	}
	root, err := os.OpenRoot(filepath.Join(siteRootPath, input.SiteID))
	if err != nil {
		return err
	}
	defer root.Close()
	staging := filepath.Join(".tompanel", "restore-staging")
	if _, err := root.Lstat(staging); err != nil {
		return errors.New("restore staging is missing")
	}
	previous := filepath.Join(".tompanel", "pre-restore")
	_ = root.RemoveAll(previous)
	handle, err := root.Open(".")
	if err != nil {
		return err
	}
	handle.Close()
	entries, err := root.Open(".")
	if err != nil {
		return err
	}
	names, err := entries.Readdirnames(-1)
	entries.Close()
	if err != nil {
		return err
	}
	if err := root.MkdirAll(previous, 0o750); err != nil {
		return err
	}
	for _, name := range names {
		if name == ".tompanel" {
			continue
		}
		if err := root.Rename(name, filepath.Join(previous, name)); err != nil {
			return err
		}
	}
	staged, err := root.Open(staging)
	if err != nil {
		return err
	}
	stagedNames, err := staged.Readdirnames(-1)
	staged.Close()
	if err != nil {
		return err
	}
	for _, name := range stagedNames {
		if err := root.Rename(filepath.Join(staging, name), name); err != nil {
			return err
		}
	}
	_ = root.RemoveAll(staging)
	return nil
}

// deleteBackupBody removes one confined local backup body.
func deleteBackupBody(ctx context.Context, input backupPathInput) error {
	if !validSiteID(input.SiteID) || !confinedBackupPath(backupRootPath, input.SiteID, input.Path) {
		return errors.New("backup.delete_local payload is invalid")
	}
	root, err := os.OpenRoot(backupRootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	relative, err := filepath.Rel(backupRootPath, input.Path)
	if err != nil {
		return err
	}
	if err := root.Remove(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// statfsDeepestExisting stats the deepest existing ancestor so the guard
// works before the backup root has been created.
func statfsDeepestExisting(path string, stat *syscall.Statfs_t) error {
	for {
		if err := syscall.Statfs(path, stat); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return os.ErrNotExist
		}
		path = parent
	}
}
