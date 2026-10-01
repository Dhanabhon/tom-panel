package agent

import (
	"bytes"
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
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/apps"
)

const (
	wpCLIVersion  = "2.2.0"
	wpCLISHABits  = "d1a3e22ffdf11d6d8b2d2f2f19c30f2b8e62d21b1c4e31d54d2e5f0b4a49c3b1"
	wpCLIDownload = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli-" + wpCLIVersion + ".phar"
	wpCacheRel    = "wp-content/cache"
	cronRootPath  = "/etc/cron.d"
)

type wordpressEnvironment struct {
	installRoot string
	version     string
	expectedSHA string
	cronRoot    string
	download    func(ctx context.Context) ([]byte, error)
	runWP       func(ctx context.Context, call apps.WPCLICall) error
	health      func(ctx context.Context, siteID string) error
}

func defaultWordPressEnvironment() wordpressEnvironment {
	return wordpressEnvironment{
		installRoot: "/usr/local/bin/wp",
		version:     wpCLIVersion,
		expectedSHA: wpCLISHABits,
		download: func(ctx context.Context) ([]byte, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, wpCLIDownload, nil)
			if err != nil {
				return nil, err
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("download wp-cli: HTTP %d", response.StatusCode)
			}
			return io.ReadAll(io.LimitReader(response.Body, 64<<20))
		},
		runWP: func(ctx context.Context, call apps.WPCLICall) error {
			command := exec.CommandContext(ctx, call.Binary, call.Args...)
			command.Stdin = bytes.NewReader(call.Stdin)
			output, err := command.CombinedOutput()
			if err != nil {
				return fmt.Errorf("wp-cli: %s: %w", strings.TrimSpace(string(output)), err)
			}
			return nil
		},
		health: func(ctx context.Context, siteID string) error {
			return verifyWordPressInstall(ctx, siteID)
		},
		cronRoot: cronRootPath,
	}
}

type wordpressEnsureCLIInput struct {
	Version string `json:"version"`
}

type wordpressInstallInput struct {
	apps.WordPressInstallInput
}

type wordpressUpdateInput struct {
	apps.WordPressInstallInput
}

type wordpressCronInput struct {
	SiteID  string `json:"site_id"`
	Enabled bool   `json:"enabled"`
}

type wordpressDBConfigInput struct {
	SiteID   string `json:"site_id"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// updateWordPressDBConfig rewrites the wp-config database constants in
// place. The password never appears in any process argument list.
func updateWordPressDBConfig(ctx context.Context, input wordpressDBConfigInput, rootPath string) error {
	if !validSiteID(input.SiteID) {
		return errors.New("wordpress.update_db_config payload is invalid")
	}
	for _, value := range []string{input.Database, input.Username, input.Password} {
		if value == "" || len(value) > 128 || strings.ContainsAny(value, "\n\r'\\") {
			return errors.New("wordpress.update_db_config payload is invalid")
		}
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	configPath := filepath.Join(input.SiteID, "public", "wp-config.php")
	content, err := root.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read wp-config: %w", err)
	}
	updated, nameChanged := rewriteWPConfigConstant(string(content), "DB_NAME", input.Database)
	updated, userChanged := rewriteWPConfigConstant(updated, "DB_USER", input.Username)
	updated, passwordChanged := rewriteWPConfigConstant(updated, "DB_PASSWORD", input.Password)
	if !nameChanged || !userChanged || !passwordChanged {
		return errors.New("wp-config database constants were not found")
	}
	return writeTempInRoot(root, configPath, []byte(updated), 0o640)
}

// rewriteWPConfigConstant replaces one define() line, returning the new
// document and whether a substitution happened.
func rewriteWPConfigConstant(content, constant, value string) (string, bool) {
	pattern := "define( '" + constant + "', '"
	start := strings.Index(content, pattern)
	if start < 0 {
		return content, false
	}
	rest := content[start+len(pattern):]
	end := strings.Index(rest, "' );")
	if end < 0 {
		end = strings.Index(rest, "');")
		if end < 0 {
			return content, false
		}
	}
	return content[:start+len(pattern)] + value + rest[end:], true
}

func ensureWPCLI(ctx context.Context, input wordpressEnsureCLIInput, env wordpressEnvironment) error {
	if input.Version != env.version {
		return errors.New("wordpress.ensure_cli version is not pinned")
	}
	if info, err := os.Stat(env.installRoot); err == nil && info.Mode().IsRegular() {
		return nil
	}
	phar, err := env.download(ctx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(phar)
	if hex.EncodeToString(sum[:]) != env.expectedSHA {
		return errors.New("wp-cli checksum mismatch")
	}
	if err := os.MkdirAll(filepath.Dir(env.installRoot), 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(env.installRoot))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(env.installRoot)
	temporary := "." + name + ".candidate"
	if err := root.WriteFile(temporary, phar, 0o755); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return nil
}

func installWordPress(ctx context.Context, input wordpressInstallInput, env wordpressEnvironment) error {
	calls, err := apps.BuildWordPressInstallCall(input.WordPressInstallInput)
	if err != nil {
		return err
	}
	for _, call := range calls {
		if err := env.runWP(ctx, call); err != nil {
			return err
		}
	}
	return env.health(ctx, input.SiteID)
}

func verifyWordPressInstall(ctx context.Context, siteID string) error {
	call := apps.WPCLICall{Binary: "/usr/local/bin/wp", Args: []string{"--path=" + wpInstallPath(siteID), "option", "get", "siteurl"}}
	command := exec.CommandContext(ctx, call.Binary, call.Args...)
	command.Stdin = bytes.NewReader(call.Stdin)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("verify wordpress: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(output)), "http") {
		return errors.New("wordpress did not report a site URL")
	}
	return nil
}

func updateWordPress(ctx context.Context, input wordpressUpdateInput, env wordpressEnvironment) error {
	calls, err := apps.BuildWordPressUpdateCall(input.WordPressInstallInput)
	if err != nil {
		return err
	}
	for index, call := range calls {
		if err := env.runWP(ctx, call); err != nil {
			return errors.Join(fmt.Errorf("wordpress update step %d failed: %w", index, err), rollbackWordPress(ctx, input.SiteID, env))
		}
	}
	if err := env.health(ctx, input.SiteID); err != nil {
		return errors.Join(fmt.Errorf("wordpress unhealthy after update: %w", err), rollbackWordPress(ctx, input.SiteID, env))
	}
	return nil
}

func rollbackWordPress(ctx context.Context, siteID string, env wordpressEnvironment) error {
	path := wpInstallPath(siteID)
	restore := []apps.WPCLICall{
		{Binary: "/usr/local/bin/wp", Args: []string{"--path=" + path, "db", "import", "../.tompanel/pre-update.sql"}},
		{Binary: "/usr/local/bin/wp", Args: []string{"--path=" + path, "core", "update", "--version=" + apps.WordPressCoreVersion}},
		{Binary: "/usr/local/bin/wp", Args: []string{"--path=" + path, "cache", "flush"}},
	}
	var failures []error
	for _, call := range restore {
		if err := env.runWP(ctx, call); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func wpInstallPath(siteID string) string {
	return filepath.Join(siteRootPath, siteID, "public")
}

func configureWordPressCron(ctx context.Context, input wordpressCronInput, env wordpressEnvironment) error {
	if !validSiteID(input.SiteID) {
		return errors.New("wordpress.configure_cron payload is invalid")
	}
	path := wpInstallPath(input.SiteID)
	constant := "false"
	if input.Enabled {
		constant = "true"
	}
	if err := env.runWP(ctx, apps.WPCLICall{Binary: "/usr/local/bin/wp", Args: []string{
		"--path=" + path, "config", "set", "DISABLE_WP_CRON", constant, "--raw",
	}}); err != nil {
		return err
	}
	root, err := os.OpenRoot(env.cronRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "tompanel-wp-" + input.SiteID
	if !input.Enabled {
		_ = root.Remove(name)
		return nil
	}
	line := fmt.Sprintf("# Managed by TomPanel: %s\n*/5 * * * * www-data /usr/local/bin/wp --path=%s cron event run --due-now >/dev/null 2>&1\n", input.SiteID, path)
	return root.WriteFile(name, []byte(line), 0o640)
}

// clearWordPressCache removes only the selected site's cache directories.
func clearWordPressCache(ctx context.Context, input siteInput, rootPath string) error {
	if !validSiteID(input.SiteID) {
		return errors.New("wordpress.clear_cache payload is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(filepath.Join(input.SiteID, wpCacheRel)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return root.RemoveAll(filepath.Join(input.SiteID, wpCacheRel))
}
