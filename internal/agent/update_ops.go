package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	panelHealthURL   = "http://127.0.0.1:8080/healthz"
	panelServiceName = "tompaneld.service"
)

// Panel filesystem locations; variables so tests can point them at
// fixtures.
var (
	stagingRoot    = "/var/lib/tompanel/update-staging"
	snapshotRoot   = "/var/lib/tompanel/update-backup"
	panelStateDB   = "/var/lib/tompanel/tompanel.db"
	panelConfigDir = "/etc/tompanel"
	panelBinaryDir = "/usr/lib/tompanel"
)

type updateEnvironment struct {
	stagingRoot  string
	snapshotRoot string
	healthWait   time.Duration
	download     func(ctx context.Context, url string) ([]byte, error)
	run          func(ctx context.Context, name string, args ...string) ([]byte, error)
	health       func(ctx context.Context) error
	now          func() time.Time
}

func defaultUpdateEnvironment() updateEnvironment {
	return updateEnvironment{
		stagingRoot:  stagingRoot,
		snapshotRoot: snapshotRoot,
		download: func(ctx context.Context, url string) ([]byte, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("download returned HTTP %d", response.StatusCode)
			}
			return io.ReadAll(io.LimitReader(response.Body, 512<<20))
		},
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			command := exec.CommandContext(ctx, name, args...)
			output, err := command.CombinedOutput()
			if err != nil {
				return output, fmt.Errorf("%s: %s: %w", filepath.Base(name), strings.TrimSpace(string(output)), err)
			}
			return output, nil
		},
		health:     panelHealthCheck,
		healthWait: 60 * time.Second,
		now:        time.Now,
	}
}

func panelHealthCheck(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, panelHealthURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("panel health returned HTTP %d", response.StatusCode)
	}
	return nil
}

type tompanelStageInput struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
}

type tompanelActivateInput struct {
	Version string `json:"version"`
}

type tompanelStateResult struct {
	Version string `json:"version"`
	State   string `json:"state"`
}

// stageTomPanelUpdate downloads the signed package and verifies its
// checksum before anything is touched.
func stageTomPanelUpdate(ctx context.Context, input tompanelStageInput, env updateEnvironment) error {
	if input.Version == "" || len(input.SHA256) != 64 || !strings.HasPrefix(input.URL, "https://") {
		return errors.New("tompanel.stage_update payload is invalid")
	}
	packageBody, err := env.download(ctx, input.URL)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(packageBody)
	if hex.EncodeToString(sum[:]) != input.SHA256 {
		return errors.New("staged package checksum mismatch")
	}
	if err := os.MkdirAll(env.stagingRoot, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(env.stagingRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFile("tompanel-"+input.Version+".deb", packageBody, 0o640)
}

// snapshotTomPanel copies database, configuration, and binaries together so
// a failed update restores the complete previous state.
func snapshotTomPanel(_ context.Context, env updateEnvironment) error {
	if err := os.MkdirAll(env.snapshotRoot, 0o700); err != nil {
		return err
	}
	stamp := fmt.Sprint(env.now().UTC().Unix())
	root, err := os.OpenRoot(env.snapshotRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(stamp, 0o700); err != nil {
		return err
	}
	for _, source := range []string{panelStateDB, filepath.Join(panelConfigDir, "config.toml")} {
		content, err := os.ReadFile(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		name := filepath.Base(source)
		if err := root.WriteFile(filepath.Join(stamp, name), content, 0o600); err != nil {
			return err
		}
	}
	binaries, err := os.ReadDir(panelBinaryDir)
	if err == nil {
		for _, binary := range binaries {
			if binary.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Join(panelBinaryDir, binary.Name()))
			if err != nil {
				continue
			}
			if err := root.WriteFile(filepath.Join(stamp, binary.Name()), content, 0o755); err != nil {
				return err
			}
		}
	}
	return root.WriteFile("latest", []byte(stamp), 0o600)
}

// activateTomPanelUpdate installs the staged package, restarts the panel,
// health-checks it, and restores the snapshot set on any failure.
func activateTomPanelUpdate(ctx context.Context, input tompanelActivateInput, env updateEnvironment) error {
	if input.Version == "" {
		return errors.New("tompanel.activate_update payload is invalid")
	}
	root, err := os.OpenRoot(env.stagingRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	packagePath := filepath.Join(env.stagingRoot, "tompanel-"+input.Version+".deb")
	if _, err := root.Lstat("tompanel-" + input.Version + ".deb"); err != nil {
		return errors.New("staged package is missing")
	}
	if _, err := env.run(ctx, "/usr/bin/dpkg", "--install", packagePath); err != nil {
		return errors.Join(err, rollbackTomPanel(ctx, env))
	}
	if _, err := env.run(ctx, "/usr/bin/systemctl", "restart", panelServiceName); err != nil {
		return errors.Join(err, rollbackTomPanel(ctx, env))
	}
	if err := waitForPanel(ctx, env); err != nil {
		return errors.Join(fmt.Errorf("panel unhealthy after update: %w", err), rollbackTomPanel(ctx, env))
	}
	return nil
}

func waitForPanel(ctx context.Context, env updateEnvironment) error {
	wait := env.healthWait
	if wait <= 0 {
		wait = 60 * time.Second
	}
	interval := 2 * time.Second
	if wait < time.Second {
		interval = 50 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if err := env.health(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return errors.New("panel did not become healthy in time")
}

// rollbackTomPanel restores the latest snapshot of database, config, and
// binaries, then restarts the panel.
func rollbackTomPanel(ctx context.Context, env updateEnvironment) error {
	root, err := os.OpenRoot(env.snapshotRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	stamp, err := root.ReadFile("latest")
	if err != nil {
		return errors.New("no snapshot to roll back to")
	}
	directory := string(stamp)
	restoreFile := func(name, destination string, mode os.FileMode) error {
		content, err := root.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		return os.WriteFile(destination, content, mode)
	}
	if err := restoreFile("tompanel.db", panelStateDB, 0o600); err != nil {
		return err
	}
	if err := restoreFile("config.toml", filepath.Join(panelConfigDir, "config.toml"), 0o640); err != nil {
		return err
	}
	entries, err := root.Open(directory)
	if err != nil {
		return err
	}
	names, err := entries.Readdirnames(-1)
	entries.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		switch name {
		case "tompanel.db", "config.toml", "latest":
			continue
		}
		if err := restoreFile(name, filepath.Join(panelBinaryDir, name), 0o755); err != nil {
			return err
		}
	}
	_, err = env.run(ctx, "/usr/bin/systemctl", "restart", panelServiceName)
	return err
}

// tompanelUpdateState reports the outcome of the last activation for
// interrupted-step reconciliation.
func tompanelUpdateState(ctx context.Context, env updateEnvironment) (tompanelStateResult, error) {
	if err := env.health(ctx); err != nil {
		return tompanelStateResult{State: "unknown"}, nil
	}
	return tompanelStateResult{State: "active"}, nil
}

// applyOfficialPackages upgrades confirmed Ubuntu archive packages only.
func applyOfficialPackages(ctx context.Context, packages []string, env updateEnvironment) error {
	if len(packages) == 0 || len(packages) > 64 {
		return errors.New("package.apply_official payload is out of bounds")
	}
	for _, name := range packages {
		if !officialPackageName.MatchString(name) {
			return fmt.Errorf("package %q is not an official archive name", name)
		}
	}
	args := append([]string{"install", "--only-upgrade", "--no-install-recommends", "-y"}, packages...)
	_, err := env.run(ctx, "/usr/bin/apt-get", args...)
	return err
}

var officialPackageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,63}$`)
