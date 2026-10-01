package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/backups"
	"filippo.io/age"
)

func backupHarness(t *testing.T) (sitesBase, backupBase string) {
	t.Helper()
	sitesBase = t.TempDir()
	backupBase = t.TempDir()
	if err := os.MkdirAll(filepath.Join(sitesBase, dbTestSiteID, "public"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sitesBase, dbTestSiteID, "public", "index.html"), []byte("<html>live</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	originalSites := siteRootPath
	originalBackups := backupRootPath
	siteRootPath = sitesBase
	backupRootPath = backupBase
	t.Cleanup(func() {
		siteRootPath = originalSites
		backupRootPath = originalBackups
	})
	return sitesBase, backupBase
}

func TestArchiveBackupSiteProducesConfinedBody(t *testing.T) {
	_, backupBase := backupHarness(t)
	result, err := archiveBackupSite(context.Background(), backupSiteInput{SiteID: dbTestSiteID}, backupEnvironment{backupRoot: backupBase})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Path, filepath.Join(backupBase, dbTestSiteID)+string(os.PathSeparator)) {
		t.Fatalf("archive escaped the backup root: %s", result.Path)
	}
	if result.Size == 0 || len(result.SHA256) != 64 {
		t.Fatalf("archive metadata incomplete: %+v", result)
	}
	verified, err := verifyBackupBody(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: result.Path})
	if err != nil || verified.SHA256 != result.SHA256 {
		t.Fatalf("verify mismatch: %+v %v", verified, err)
	}
	if _, err := verifyBackupBody(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: filepath.Join(backupBase, "..", "etc")}); err == nil {
		t.Fatal("verify accepted an unconfined path")
	}
}

func TestRestoreFilesAndActivationRollForwardAndBack(t *testing.T) {
	sitesBase, backupBase := backupHarness(t)
	result, err := archiveBackupSite(context.Background(), backupSiteInput{SiteID: dbTestSiteID}, backupEnvironment{backupRoot: backupBase})
	if err != nil {
		t.Fatal(err)
	}
	// Change the live content, then restore the archive.
	if err := os.WriteFile(filepath.Join(sitesBase, dbTestSiteID, "public", "index.html"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackupFiles(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: result.Path}); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupRestore(context.Background(), backupSiteInput{SiteID: dbTestSiteID}); err != nil {
		t.Fatal(err)
	}
	// Activation swaps the staged tree in atomically.
	if err := activateBackupRestore(context.Background(), backupSiteInput{SiteID: dbTestSiteID}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(sitesBase, dbTestSiteID, "public", "index.html"))
	if err != nil || string(got) != "<html>live</html>" {
		t.Fatalf("restored content mismatch: %q %v", got, err)
	}
	// The previous live tree survives for rollback.
	if _, err := os.Stat(filepath.Join(sitesBase, dbTestSiteID, ".tompanel", "pre-restore", "public", "index.html")); err != nil {
		t.Fatalf("pre-restore copy missing: %v", err)
	}
}

func TestRestoreFilesRejectsSymlinkArchive(t *testing.T) {
	sitesBase, backupBase := backupHarness(t)
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	if err := writer.WriteHeader(&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	gzipWriter.Write(raw.Bytes())
	gzipWriter.Close()
	if err := os.MkdirAll(filepath.Join(backupBase, dbTestSiteID), 0o750); err != nil {
		t.Fatal(err)
	}
	evilPath := filepath.Join(backupBase, dbTestSiteID, "evil.tar.gz")
	if err := os.WriteFile(evilPath, compressed.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackupFiles(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: evilPath}); err == nil {
		t.Fatal("symlink archive accepted")
	}
	if _, err := os.Lstat(filepath.Join(sitesBase, dbTestSiteID, ".tompanel", "restore-staging", "evil")); err == nil {
		t.Fatal("unsafe entry materialized")
	}
}

func TestEncryptedUploadContainsNoPlaintext(t *testing.T) {
	_, backupBase := backupHarness(t)

	result, err := archiveBackupSite(context.Background(), backupSiteInput{SiteID: dbTestSiteID}, backupEnvironment{backupRoot: backupBase})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var captured bytes.Buffer
	env := backupEnvironment{
		backupRoot: backupBase,
		uploader: func(_ context.Context, _ backups.RemoteSettings, key string, body io.Reader, _ int64) (int64, error) {
			written, err := io.Copy(&captured, body)
			if key == "" {
				return 0, errors.New("empty key")
			}
			return written, err
		},
	}
	upload, err := uploadBackup(context.Background(), backupUploadInput{
		SiteID: dbTestSiteID, Path: result.Path, Key: "site/x.tar.age",
		Settings: backups.RemoteSettings{
			Bucket: "bucket", Region: "auto", AccessKeyID: "AKIA-test", SecretKey: "secret",
			AgeRecipient: identity.Recipient().String(),
		},
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if upload.Size == 0 || upload.SHA256 == "" {
		t.Fatalf("upload result incomplete: %+v", upload)
	}
	if bytes.Contains(captured.Bytes(), []byte("live")) {
		t.Fatal("plaintext leaked into the encrypted object")
	}
	// The captured ciphertext must decrypt back to the archive.
	decrypter, err := age.Decrypt(bytes.NewReader(captured.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := io.ReadAll(decrypter)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(decrypted)
	if hex.EncodeToString(sum[:]) != result.SHA256 {
		t.Fatal("decrypted body does not match the original archive")
	}
	_ = original
}

func TestUploadRejectsUnconfinedPathAndBadRecipient(t *testing.T) {
	_, backupBase := backupHarness(t)
	env := backupEnvironment{backupRoot: backupBase, uploader: func(context.Context, backups.RemoteSettings, string, io.Reader, int64) (int64, error) {
		return 0, nil
	}}
	settings := backups.RemoteSettings{Bucket: "b", AccessKeyID: "a", SecretKey: "s", AgeRecipient: "not-a-recipient"}
	if _, err := uploadBackup(context.Background(), backupUploadInput{
		SiteID: dbTestSiteID, Path: filepath.Join(backupBase, dbTestSiteID, "x.tar.gz"), Key: "k", Settings: settings,
	}, env); err == nil {
		t.Fatal("invalid age recipient accepted")
	}
	identity, _ := age.GenerateX25519Identity()
	settings.AgeRecipient = identity.Recipient().String()
	if _, err := uploadBackup(context.Background(), backupUploadInput{
		SiteID: dbTestSiteID, Path: "/etc/passwd", Key: "k", Settings: settings,
	}, env); err == nil {
		t.Fatal("unconfined upload path accepted")
	}
}

func TestDeleteLocalOnlyRemovesOwnedBody(t *testing.T) {
	_, backupBase := backupHarness(t)
	if err := os.MkdirAll(filepath.Join(backupBase, dbTestSiteID), 0o750); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(backupBase, dbTestSiteID, "files-1.tar.gz")
	if err := os.WriteFile(body, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := deleteBackupBody(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: body}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(body); !os.IsNotExist(err) {
		t.Fatal("body survived deletion")
	}
	if err := deleteBackupBody(context.Background(), backupPathInput{SiteID: dbTestSiteID, Path: filepath.Join(backupBase, "other-site", "x.tar.gz")}); err == nil {
		t.Fatal("foreign body deletion accepted")
	}
}

func TestDiskGuardReportsStatfs(t *testing.T) {
	backupHarness(t)
	if _, err := diskGuardBackup(context.Background(), backupSiteInput{SiteID: dbTestSiteID}); err != nil {
		t.Fatalf("disk guard failed on a real volume: %v", err)
	}
	if _, err := diskGuardBackup(context.Background(), backupSiteInput{SiteID: "../evil"}); err == nil {
		t.Fatal("unsafe site accepted")
	}
}
