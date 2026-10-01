package operations

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

type releaseFixture struct {
	public    ed25519.PublicKey
	manifest  ReleaseManifest
	signature []byte
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ReleaseManifest{
		Version: "1.2.0",
		SHA256:  strings.Repeat("ab", 32),
		URL:     "https://releases.example.com/tompanel-1.2.0.deb",
	}
	signature := ed25519.Sign(private, manifest.canonical())
	manifest.Signature = base64.StdEncoding.EncodeToString(signature)
	return &releaseFixture{public: public, manifest: manifest, signature: signature}
}

func (f *releaseFixture) corruptSignature() []byte {
	corrupted := append([]byte(nil), f.signature...)
	corrupted[0] ^= 0xff
	return corrupted
}

func updateStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "state.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func TestUpdateRejectsManifestWithBadSignature(t *testing.T) {
	fixture := newReleaseFixture(t)
	corrupt := fixture.manifest
	corrupt.Signature = base64.StdEncoding.EncodeToString(fixture.corruptSignature())
	if _, err := VerifyReleaseManifest(corrupt, fixture.public); !hasErrorCode(err, ErrReleaseSignature) {
		t.Fatalf("got %v, want ErrReleaseSignature", err)
	}
	verified, err := VerifyReleaseManifest(fixture.manifest, fixture.public)
	if err != nil || verified.Version != fixture.manifest.Version {
		t.Fatalf("valid manifest rejected: %+v %v", verified, err)
	}
}

func hasErrorCode(err, target error) bool {
	return err != nil && (err == target || strings.Contains(err.Error(), target.Error()))
}

func TestUpdateRejectsMalformedManifests(t *testing.T) {
	fixture := newReleaseFixture(t)
	broken := fixture.manifest
	broken.SHA256 = "short"
	if _, err := VerifyReleaseManifest(broken, fixture.public); err == nil {
		t.Fatal("short checksum accepted")
	}
	broken = fixture.manifest
	broken.URL = "http://insecure.example/x.deb"
	if _, err := VerifyReleaseManifest(broken, fixture.public); err == nil {
		t.Fatal("insecure download URL accepted")
	}
}

func TestTomPanelUpdateJobVerifiesBeforeQueueing(t *testing.T) {
	database := updateStore(t)
	fixture := newReleaseFixture(t)
	updater := NewUpdater(database, func(context.Context, string, any, any) error { return nil }, fixture.public)
	if _, err := updater.BuildTomPanelUpdateJob(context.Background(), fixture.manifest); err != nil {
		t.Fatal(err)
	}
	bad := fixture.manifest
	bad.Signature = base64.StdEncoding.EncodeToString(fixture.corruptSignature())
	if _, err := updater.BuildTomPanelUpdateJob(context.Background(), bad); err == nil {
		t.Fatal("unsigned update job built")
	}
}

func TestPPAUpdateRequiresConfirmation(t *testing.T) {
	database := updateStore(t)
	updater := NewUpdater(database, func(context.Context, string, any, any) error { return nil }, nil)
	if _, err := updater.BuildPackageJob(PackageUpdate{Packages: []string{"nginx"}, Confirmed: false}); err == nil {
		t.Fatal("unconfirmed package update accepted")
	}
	if _, err := updater.BuildPackageJob(PackageUpdate{Packages: []string{"nginx"}, Confirmed: true, FromPPA: true}); err == nil {
		t.Fatal("PPA package accepted")
	}
	if _, err := updater.BuildPackageJob(PackageUpdate{Packages: []string{"nginx;reboot"}, Confirmed: true}); err == nil {
		t.Fatal("injected package name accepted")
	}
	if _, err := updater.BuildPackageJob(PackageUpdate{Packages: []string{"nginx-core", "openssl"}, Confirmed: true}); err != nil {
		t.Fatalf("confirmed official set rejected: %v", err)
	}
}

func TestToolUpdateRequiresConfirmation(t *testing.T) {
	database := updateStore(t)
	updater := NewUpdater(database, func(context.Context, string, any, any) error { return nil }, nil)
	payload := ToolUpdate{Tool: "wpcli", Version: "2.3.0", SHA256: strings.Repeat("cd", 32)}
	if _, err := updater.BuildToolUpdateJob(payload); err == nil {
		t.Fatal("unconfirmed tool update accepted")
	}
	payload.Confirmed = true
	if _, err := updater.BuildToolUpdateJob(payload); err != nil {
		t.Fatalf("confirmed tool update rejected: %v", err)
	}
	payload.Tool = "custom-tool"
	if _, err := updater.BuildToolUpdateJob(payload); err == nil {
		t.Fatal("unknown tool accepted")
	}
}
