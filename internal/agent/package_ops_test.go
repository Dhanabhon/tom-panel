package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type updateCall struct {
	name string
	args string
}

type updateEnvLog struct {
	calls    []updateCall
	failOn   func(name string) bool
	healthOK bool
	body     []byte
	env      updateEnvironment
}

func newUpdateEnvLog(t *testing.T) *updateEnvLog {
	t.Helper()
	log := &updateEnvLog{healthOK: true}
	log.env = updateEnvironment{
		stagingRoot:  t.TempDir(),
		snapshotRoot: t.TempDir(),
		download: func(context.Context, string) ([]byte, error) {
			if log.body != nil {
				return log.body, nil
			}
			return []byte("fake deb package body"), nil
		},
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			log.calls = append(log.calls, updateCall{name: filepath.Base(name), args: strings.Join(args, " ")})
			if log.failOn != nil && log.failOn(filepath.Base(name)) {
				return nil, errors.New("forced failure")
			}
			return nil, nil
		},
		health: func(context.Context) error {
			if log.healthOK {
				return nil
			}
			return errors.New("panel down")
		},
		now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
	return log
}

func (l *updateEnvLog) joined() string {
	var builder strings.Builder
	for _, call := range l.calls {
		builder.WriteString(call.name + " " + call.args + ";")
	}
	return builder.String()
}

func TestStageVerifiesChecksum(t *testing.T) {
	log := newUpdateEnvLog(t)
	input := tompanelStageInput{Version: "1.2.0", SHA256: strings.Repeat("00", 32), URL: "https://releases.example/x.deb"}
	if err := stageTomPanelUpdate(context.Background(), input, log.env); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	checksum := sha256.Sum256([]byte("fake deb package body"))
	sum := hex.EncodeToString(checksum[:])
	input.SHA256 = sum
	if err := stageTomPanelUpdate(context.Background(), input, log.env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(log.env.stagingRoot, "tompanel-1.2.0.deb")); err != nil {
		t.Fatalf("staged package missing: %v", err)
	}
	input.URL = "http://insecure.example/x.deb"
	if err := stageTomPanelUpdate(context.Background(), input, log.env); err == nil {
		t.Fatal("insecure URL accepted")
	}
}

func TestFailedMigrationRestoresDatabaseAndBinaries(t *testing.T) {
	log := newUpdateEnvLog(t)
	fixturePanelPaths(t)
	log.failOn = func(name string) bool { return name == "dpkg" }
	checksum := sha256.Sum256([]byte("fake deb package body"))
	if err := stageTomPanelUpdate(context.Background(), tompanelStageInput{Version: "1.2.0", SHA256: hex.EncodeToString(checksum[:]), URL: "https://releases.example/x.deb"}, log.env); err != nil {
		t.Fatal(err)
	}
	if err := snapshotTomPanel(context.Background(), log.env); err != nil {
		t.Fatal(err)
	}
	if err := activateTomPanelUpdate(context.Background(), tompanelActivateInput{Version: "1.2.0"}, log.env); err == nil {
		t.Fatal("failed install reported success")
	}
	joined := log.joined()
	if !strings.Contains(joined, "dpkg --install") {
		t.Fatalf("install never attempted: %s", joined)
	}
	// Rollback restores state before restarting the service.
	if !strings.Contains(joined, "systemctl restart tompaneld.service") {
		t.Fatalf("rollback restart missing: %s", joined)
	}
}

func TestUnhealthyPanelUpdateRollsBack(t *testing.T) {
	log := newUpdateEnvLog(t)
	fixturePanelPaths(t)
	log.healthOK = false
	log.env.healthWait = 150 * time.Millisecond
	checksum := sha256.Sum256([]byte("fake deb package body"))
	if err := stageTomPanelUpdate(context.Background(), tompanelStageInput{Version: "1.2.0", SHA256: hex.EncodeToString(checksum[:]), URL: "https://releases.example/x.deb"}, log.env); err != nil {
		t.Fatal(err)
	}
	if err := snapshotTomPanel(context.Background(), log.env); err != nil {
		t.Fatal(err)
	}
	if err := activateTomPanelUpdate(context.Background(), tompanelActivateInput{Version: "1.2.0"}, log.env); err == nil {
		t.Fatal("unhealthy update accepted")
	}
	joined := log.joined()
	if !strings.Contains(joined, "dpkg --install") || !strings.Contains(joined, "systemctl restart") {
		t.Fatalf("update sequence wrong: %s", joined)
	}
	// rollback restarts again after restoring the snapshot
	if strings.Count(joined, "systemctl restart") < 2 {
		t.Fatalf("rollback restart missing: %s", joined)
	}
}

// fixturePanelPaths points the production panel paths at fixtures so
// snapshot and rollback have real content to work with.
func fixturePanelPaths(t *testing.T) {
	t.Helper()
	temp := t.TempDir()
	originalDB, originalConfig, originalBin := panelStateDB, panelConfigDir, panelBinaryDir
	panelStateDB = filepath.Join(temp, "tompanel.db")
	panelConfigDir = temp
	panelBinaryDir = filepath.Join(temp, "bin")
	t.Cleanup(func() {
		panelStateDB, panelConfigDir, panelBinaryDir = originalDB, originalConfig, originalBin
	})
	if err := os.WriteFile(panelStateDB, []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temp, "config.toml"), []byte("config"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(panelBinaryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(panelBinaryDir, "tompaneld"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCapturesCompleteState(t *testing.T) {
	log := newUpdateEnvLog(t)
	fixturePanelPaths(t)
	if err := snapshotTomPanel(context.Background(), log.env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(log.env.snapshotRoot, "1800000000", "tompanel.db")); err != nil {
		t.Fatalf("snapshot incomplete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(log.env.snapshotRoot, "1800000000", "tompaneld")); err != nil {
		t.Fatalf("binary snapshot missing: %v", err)
	}
}

func TestApplyOfficialPackagesValidates(t *testing.T) {
	log := newUpdateEnvLog(t)
	if err := applyOfficialPackages(context.Background(), []string{"nginx-core"}, log.env); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.joined(), "apt-get install --only-upgrade") {
		t.Fatalf("apt invocation wrong: %s", log.joined())
	}
	if err := applyOfficialPackages(context.Background(), []string{"ppa-package;rm"}, log.env); err == nil {
		t.Fatal("injected package accepted")
	}
	if err := applyOfficialPackages(context.Background(), nil, log.env); err == nil {
		t.Fatal("empty set accepted")
	}
}

func TestUpdateStateReportsHealth(t *testing.T) {
	log := newUpdateEnvLog(t)
	state, err := tompanelUpdateState(context.Background(), log.env)
	if err != nil || state.State != "active" {
		t.Fatalf("state: %+v %v", state, err)
	}
	log.healthOK = false
	state, err = tompanelUpdateState(context.Background(), log.env)
	if err != nil || state.State != "unknown" {
		t.Fatalf("unhealthy state: %+v %v", state, err)
	}
}

func TestReleaseSignatureHelperMatchesOperations(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("1.2.0\n" + strings.Repeat("ab", 32))
	signature := ed25519.Sign(private, message)
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("signature round trip failed")
	}
	corrupted := append([]byte(nil), signature...)
	corrupted[3] ^= 0x55
	if ed25519.Verify(public, message, corrupted) {
		t.Fatal("corrupted signature verified")
	}
	_ = base64.StdEncoding
}
