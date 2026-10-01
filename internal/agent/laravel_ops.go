package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/apps"
)

const (
	gitBinary        = "/usr/bin/git"
	composerBinary   = "/usr/bin/composer"
	npmBinary        = "/usr/bin/npm"
	phpBinary        = "/usr/bin/php"
	systemdRootPath  = "/etc/systemd/system"
	deployKeyRel     = ".tompanel/deploy_key"
	releasesRel      = "releases"
	sharedRel        = "shared"
	currentRel       = "current"
	legacyPublicRel  = ".tompanel/first-public-backup"
)

// laravelEnvironment carries every privileged effect for tests.
type laravelEnvironment struct {
	run      func(ctx context.Context, name string, args []string, stdin []byte, env []string, dir string) error
	health   func(ctx context.Context, host string, port int) error
	systemd  string
}

func defaultLaravelEnvironment() laravelEnvironment {
	return laravelEnvironment{
		run: func(ctx context.Context, name string, args []string, stdin []byte, env []string, dir string) error {
			command := exec.CommandContext(ctx, name, args...)
			command.Stdin = bytes.NewReader(stdin)
			command.Dir = dir
			if env != nil {
				command.Env = append(os.Environ(), env...)
			}
			output, err := command.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s: %s: %w", filepath.Base(name), strings.TrimSpace(string(output)), err)
			}
			return nil
		},
		health: laravelHTTPHealth,
		systemd: systemdRootPath,
	}
}

func laravelHTTPHealth(ctx context.Context, host string, port int) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		return err
	}
	request.Host = host
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		return fmt.Errorf("release returned HTTP %d", response.StatusCode)
	}
	return nil
}

type laravelCheckoutInput struct {
	SiteID     string `json:"site_id"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Release    string `json:"release"`
	UseKey     bool   `json:"use_key,omitempty"`
}

type laravelReleaseInput struct {
	SiteID  string `json:"site_id"`
	Release string `json:"release"`
}

type laravelHealthInput struct {
	SiteID    string `json:"site_id"`
	Hostname  string `json:"hostname"`
	HTTPSPort int    `json:"https_port"`
}

type laravelWorkersInput struct {
	SiteID  string `json:"site_id"`
	Enabled bool   `json:"enabled"`
}

type laravelEnvInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	AppKey   string `json:"app_key"`
	AppURL   string `json:"app_url"`
}

type laravelDeployKeyInput struct {
	SiteID string `json:"site_id"`
}

func laravelSiteRoot(siteID string) (string, error) {
	if !validSiteID(siteID) {
		return "", errors.New("laravel payload is invalid")
	}
	return filepath.Join(siteRootPath, siteID), nil
}

func validRelease(release string) bool {
	if len(release) != 9 {
		return false
	}
	for _, r := range release {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkoutLaravel clones the requested branch into a new release directory.
// Local and external transports are disabled at the Git level as well.
func checkoutLaravel(ctx context.Context, input laravelCheckoutInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if err := apps.ValidateLaravelRepo(input.Repository); err != nil {
		return err
	}
	if err := apps.ValidateLaravelBranch(input.Branch); err != nil {
		return errors.New("laravel branch is invalid")
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	releasePath := filepath.Join(root, releasesRel, input.Release)
	if err := os.MkdirAll(filepath.Dir(releasePath), 0o750); err != nil {
		return err
	}
	siteRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer siteRoot.Close()
	if _, err := siteRoot.Lstat(filepath.Join(releasesRel, input.Release)); err == nil {
		return errors.New("release already exists")
	}
	args := []string{
		"-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
		"clone", "--branch", input.Branch, "--single-branch", "--depth", "1",
		"--no-hardlinks", input.Repository, filepath.Join(releasesRel, input.Release),
	}
	var extraEnv []string
	if input.UseKey {
		keyPath := filepath.Join(root, deployKeyRel)
		if _, err := os.Stat(keyPath); err != nil {
			return errors.New("deploy key is not installed")
		}
		extraEnv = []string{"GIT_SSH_COMMAND=ssh -i " + keyPath + " -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"}
	}
	if err := env.run(ctx, gitBinary, args, nil, extraEnv, root); err != nil {
		_ = siteRoot.RemoveAll(filepath.Join(releasesRel, input.Release))
		return err
	}
	return nil
}

func composerInstallLaravel(ctx context.Context, input laravelReleaseInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	return env.run(ctx, composerBinary, []string{"install", "--no-dev", "--no-interaction", "--prefer-dist", "--optimize-autoloader"}, nil, nil, filepath.Join(root, releasesRel, input.Release))
}

// nodeBuildLaravel refuses to run without a committed package-lock.json.
func nodeBuildLaravel(ctx context.Context, input laravelReleaseInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	siteRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer siteRoot.Close()
	if _, err := siteRoot.Stat(filepath.Join(releasesRel, input.Release, "package-lock.json")); err != nil {
		return fmt.Errorf("%w: release %s", apps.ErrMissingLockfile, input.Release)
	}
	if err := env.run(ctx, npmBinary, []string{"ci", "--no-fund", "--no-audit"}, nil, nil, filepath.Join(root, releasesRel, input.Release)); err != nil {
		return err
	}
	return env.run(ctx, npmBinary, []string{"run", "build"}, nil, nil, filepath.Join(root, releasesRel, input.Release))
}

func migrateLaravel(ctx context.Context, input laravelReleaseInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	return env.run(ctx, phpBinary, []string{"artisan", "migrate", "--force"}, nil, nil, filepath.Join(root, releasesRel, input.Release))
}

func optimizeLaravel(ctx context.Context, input laravelReleaseInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	return env.run(ctx, phpBinary, []string{"artisan", "optimize"}, nil, nil, filepath.Join(root, releasesRel, input.Release))
}

func healthCheckLaravel(ctx context.Context, input laravelHealthInput, env laravelEnvironment) error {
	if _, err := laravelSiteRoot(input.SiteID); err != nil {
		return err
	}
	if input.HTTPSPort < 1 || input.HTTPSPort > 65535 || strings.TrimSpace(input.Hostname) == "" {
		return errors.New("laravel health payload is invalid")
	}
	return env.health(ctx, strings.TrimSpace(input.Hostname), input.HTTPSPort)
}

// activateLaravel swaps the current symlink atomically. The public directory
// is re-pointed once, on the first activation, from its static content to
// the release's public directory.
func activateLaravel(ctx context.Context, input laravelReleaseInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	if !validRelease(input.Release) {
		return errors.New("laravel release is invalid")
	}
	siteRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer siteRoot.Close()
	if _, err := siteRoot.Lstat(filepath.Join(releasesRel, input.Release, "public")); err != nil {
		return errors.New("release has no public directory")
	}
	if _, err := siteRoot.Lstat(filepath.Join(sharedRel)); err != nil {
		if err := siteRoot.MkdirAll(filepath.Join(sharedRel, "storage"), 0o770); err != nil {
			return err
		}
	}
	candidate := currentRel + ".new"
	_ = siteRoot.Remove(candidate)
	target := filepath.Join(releasesRel, input.Release)
	if err := os.Symlink(filepath.Join(root, target), filepath.Join(root, candidate)); err != nil {
		return err
	}
	if err := siteRoot.Remove(currentRel); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = siteRoot.Remove(candidate)
		return err
	}
	if err := siteRoot.Rename(candidate, currentRel); err != nil {
		_ = siteRoot.Remove(candidate)
		return err
	}
	if info, err := siteRoot.Lstat("public"); err == nil && info.IsDir() {
		if err := siteRoot.MkdirAll(filepath.Dir(legacyPublicRel), 0o750); err != nil {
			return err
		}
		if err := siteRoot.Rename("public", legacyPublicRel); err != nil {
			return err
		}
		if err := os.Symlink(filepath.Join(root, currentRel, "public"), filepath.Join(root, "public.new")); err != nil {
			return err
		}
		if err := siteRoot.Rename("public.new", "public"); err != nil {
			_ = os.Symlink(filepath.Join(root, currentRel, "public"), filepath.Join(root, "public"))
			return err
		}
	}
	return nil
}

// configureLaravelEnvironment writes the shared .env with database secrets
// arriving through the protected socket payload, never argv.
func configureLaravelEnvironment(ctx context.Context, input laravelEnvInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	for _, value := range []string{input.Database, input.Username, input.Password, input.AppKey, input.AppURL} {
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\n\r") {
			return errors.New("laravel environment payload is invalid")
		}
	}
	siteRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer siteRoot.Close()
	if err := siteRoot.MkdirAll(sharedRel, 0o750); err != nil {
		return err
	}
	content := strings.Join([]string{
		"APP_ENV=production",
		"APP_DEBUG=false",
		"APP_URL=" + input.AppURL,
		"APP_KEY=" + input.AppKey,
		"DB_CONNECTION=mysql",
		"DB_HOST=localhost",
		"DB_DATABASE=" + input.Database,
		"DB_USERNAME=" + input.Username,
		"DB_PASSWORD=" + input.Password,
		"DB_SOCKET=/run/mysqld/mysqld.sock",
		"SESSION_DRIVER=file",
		"",
	}, "\n")
	return writeTempInRoot(siteRoot, filepath.Join(sharedRel, ".env"), []byte(content), 0o640)
}

// ensureLaravelDeployKey mints one ed25519 key per site for private repos.
// The private key never leaves the server; the public key is returned once.
func ensureLaravelDeployKey(ctx context.Context, input laravelDeployKeyInput, env laravelEnvironment) (map[string]string, error) {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return nil, err
	}
	siteRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer siteRoot.Close()
	if err := siteRoot.MkdirAll(filepath.Dir(deployKeyRel), 0o750); err != nil {
		return nil, err
	}
	if public, err := siteRoot.ReadFile(deployKeyRel + ".pub"); err == nil && len(public) > 0 {
		return map[string]string{"public_key": strings.TrimSpace(string(public))}, nil
	}
	keyPath := filepath.Join(root, deployKeyRel)
	if err := env.run(ctx, "/usr/bin/ssh-keygen", []string{"-t", "ed25519", "-N", "", "-C", "tompanel-" + input.SiteID[:8], "-f", keyPath}, nil, nil, root); err != nil {
		return nil, err
	}
	public, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return nil, err
	}
	return map[string]string{"public_key": strings.TrimSpace(string(public))}, nil
}

// ensureLaravelWorkers manages the queue worker and scheduler units.
func ensureLaravelWorkers(ctx context.Context, input laravelWorkersInput, env laravelEnvironment) error {
	root, err := laravelSiteRoot(input.SiteID)
	if err != nil {
		return err
	}
	systemdRoot, err := os.OpenRoot(env.systemd)
	if err != nil {
		return err
	}
	defer systemdRoot.Close()
	name := "tompanel-site-" + input.SiteID + "-"
	if !input.Enabled {
		for _, unit := range []string{name + "scheduler.timer", name + "queue.service"} {
			_ = systemdRoot.Remove(unit)
		}
		return env.run(ctx, "/usr/bin/systemctl", []string{"daemon-reload"}, nil, nil, root)
	}
	worker := fmt.Sprintf(`# Managed by TomPanel: %s
[Unit]
Description=TomPanel queue worker for %s
After=network.target mariadb.service

[Service]
User=tp_%s
WorkingDirectory=%s
ExecStart=/usr/bin/php artisan queue:work --sleep=3 --tries=3 --max-time=3600
Restart=always

[Install]
WantedBy=multi-user.target
`, input.SiteID, input.SiteID, input.SiteID[:16], filepath.Join(root, currentRel))
	scheduler := fmt.Sprintf(`# Managed by TomPanel: %s
[Unit]
Description=TomPanel scheduler for %s

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
`, input.SiteID, input.SiteID)
	schedulerService := fmt.Sprintf(`# Managed by TomPanel: %s
[Unit]
Description=TomPanel scheduler run for %s

[Service]
Type=oneshot
User=tp_%s
WorkingDirectory=%s
ExecStart=/usr/bin/php artisan schedule:run
`, input.SiteID, input.SiteID, input.SiteID[:16], filepath.Join(root, currentRel))
	if err := writeTempInRoot(systemdRoot, name+"queue.service", []byte(worker), 0o644); err != nil {
		return err
	}
	if err := writeTempInRoot(systemdRoot, name+"scheduler.service", []byte(schedulerService), 0o644); err != nil {
		return err
	}
	if err := writeTempInRoot(systemdRoot, name+"scheduler.timer", []byte(scheduler), 0o644); err != nil {
		return err
	}
	if err := env.run(ctx, "/usr/bin/systemctl", []string{"daemon-reload"}, nil, nil, root); err != nil {
		return err
	}
	if err := env.run(ctx, "/usr/bin/systemctl", []string{"enable", "--now", name + "queue.service", name + "scheduler.timer"}, nil, nil, root); err != nil {
		return err
	}
	return nil
}
