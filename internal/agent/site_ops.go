package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

const siteRootPath = "/srv/tompanel/sites"

var nginxMu sync.Mutex

var ufwRuleLine = regexp.MustCompile(`^\[\s*([0-9]+)\]\s+([0-9]+)/tcp\s+.*# TomPanel:([0-9a-f]{32})\s*$`)

type siteInput struct {
	SiteID string `json:"site_id"`
}

type ensureDirectoriesResult struct {
	SiteRoot   string `json:"site_root"`
	PublicRoot string `json:"public_root"`
}

type nginxActivateInput struct {
	SiteID     string `json:"site_id"`
	Config     string `json:"config"`
	HealthHost string `json:"health_host"`
	HealthPort int    `json:"health_port"`
}

type ufwInput struct {
	SiteID string `json:"site_id"`
	Port   int    `json:"port"`
}

type nginxEnvironment struct {
	root   string
	run    func(context.Context, string, ...string) error
	health func(context.Context, string, int) error
}

func decodeEnsureDirectories(payload json.RawMessage) (siteInput, error) {
	var input siteInput
	if err := decodeStrict(payload, &input); err != nil || !validSiteID(input.SiteID) {
		return siteInput{}, errors.New("site.ensure_directories payload is invalid")
	}
	return input, nil
}

func ensureDirectories(_ context.Context, payload json.RawMessage, rootPath string) (ensureDirectoriesResult, error) {
	input, err := decodeEnsureDirectories(payload)
	if err != nil {
		return ensureDirectoriesResult{}, err
	}
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return ensureDirectoriesResult{}, fmt.Errorf("create site root: %w", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return ensureDirectoriesResult{}, fmt.Errorf("open site root: %w", err)
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Join(input.SiteID, "public"), 0o750); err != nil {
		return ensureDirectoriesResult{}, fmt.Errorf("create site directories: %w", err)
	}
	if err := root.Chmod(input.SiteID, 0o755); err != nil {
		return ensureDirectoriesResult{}, fmt.Errorf("secure site directory: %w", err)
	}
	if err := root.Chmod(filepath.Join(input.SiteID, "public"), 0o750); err != nil {
		return ensureDirectoriesResult{}, fmt.Errorf("secure public directory: %w", err)
	}
	base := filepath.Join(siteRootPath, input.SiteID)
	return ensureDirectoriesResult{SiteRoot: base, PublicRoot: filepath.Join(base, "public")}, nil
}

func setDirectoryOwner(siteID, rootPath string) error {
	uid, gid, err := directoryOwnerIDs(siteID, user.Lookup, user.LookupGroup)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	public, err := root.Open(filepath.Join(siteID, "public"))
	if err != nil {
		return err
	}
	defer public.Close()
	if err := public.Chown(uid, gid); err != nil {
		return fmt.Errorf("own public directory: %w", err)
	}
	return nil
}

func directoryOwnerIDs(siteID string, lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) (int, int, error) {
	account, err := lookupUser("tp_" + siteID[:16])
	if err != nil {
		return 0, 0, fmt.Errorf("lookup site identity: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse site UID: %w", err)
	}
	nginx, err := lookupGroup("www-data")
	if err != nil {
		return 0, 0, fmt.Errorf("lookup Nginx group: %w", err)
	}
	gid, err := strconv.Atoi(nginx.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse Nginx GID: %w", err)
	}
	return uid, gid, nil
}

func ensureIdentity(ctx context.Context, payload json.RawMessage) (map[string]string, error) {
	var input siteInput
	if err := decodeStrict(payload, &input); err != nil || !validSiteID(input.SiteID) {
		return nil, errors.New("site.ensure_identity payload is invalid")
	}
	name, err := ensureSiteUser(ctx, input.SiteID)
	if err != nil {
		return nil, err
	}
	return map[string]string{"username": name}, nil
}

func activateNginx(ctx context.Context, input nginxActivateInput, env nginxEnvironment) error {
	marker := "# Managed by TomPanel: " + input.SiteID + "\n"
	if !validSiteID(input.SiteID) || !strings.HasPrefix(input.Config, marker) || len(input.Config) > 256<<10 || input.HealthPort < 1 || input.HealthPort > 65535 {
		return errors.New("nginx.validate_activate payload is invalid")
	}
	host, err := sites.NormalizeHostname(input.HealthHost)
	if err != nil {
		return errors.New("nginx.validate_activate health hostname is invalid")
	}
	nginxMu.Lock()
	defer nginxMu.Unlock()

	root, err := os.OpenRoot(env.root)
	if err != nil {
		return fmt.Errorf("open nginx config root: %w", err)
	}
	defer root.Close()
	name := "tp-" + input.SiteID + ".conf"
	temporary := "." + name + ".candidate"
	backup := "." + name + ".rollback"
	old, readErr := root.ReadFile(backup)
	hadBackup := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read Nginx rollback: %w", readErr)
	}
	hadOld := hadBackup && len(old) > 0
	if !hadBackup {
		old, readErr = root.ReadFile(name)
		hadOld = readErr == nil
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read active nginx config: %w", readErr)
		}
	}
	if hadOld && !strings.HasPrefix(string(old), marker) {
		return errors.New("refusing to replace an unmanaged nginx config")
	}
	if !hadBackup {
		if err := root.WriteFile(backup, old, 0o600); err != nil {
			return fmt.Errorf("write Nginx rollback: %w", err)
		}
	}
	if err := root.WriteFile(temporary, []byte(input.Config), 0o640); err != nil {
		return fmt.Errorf("write nginx candidate: %w", err)
	}
	defer root.Remove(temporary)
	if err := root.Rename(temporary, name); err != nil {
		return fmt.Errorf("activate nginx candidate: %w", err)
	}
	restore := func() error {
		var restoreErr error
		if hadOld {
			if err := root.WriteFile(temporary, old, 0o640); err != nil {
				return fmt.Errorf("write Nginx rollback: %w", err)
			}
			if err := root.Rename(temporary, name); err != nil {
				return fmt.Errorf("activate Nginx rollback: %w", err)
			}
		} else if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErr = fmt.Errorf("remove failed Nginx config: %w", err)
		}
		if err := root.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("remove Nginx rollback: %w", err))
		}
		return restoreErr
	}
	rollback := func() error {
		if err := restore(); err != nil {
			return err
		}
		if err := env.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
			return fmt.Errorf("validate Nginx rollback: %w", err)
		}
		if err := env.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
			return fmt.Errorf("reload Nginx rollback: %w", err)
		}
		return nil
	}
	if err := env.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		return errors.Join(fmt.Errorf("validate nginx: %w", err), restore())
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return errors.Join(fmt.Errorf("reload nginx: %w", err), rollback())
	}
	if err := env.health(ctx, host, input.HealthPort); err != nil {
		return errors.Join(fmt.Errorf("health-check nginx: %w", err), rollback())
	}
	if err := root.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove Nginx rollback: %w", err)
	}
	return nil
}

func disableNginx(ctx context.Context, input siteInput, env nginxEnvironment) error {
	if !validSiteID(input.SiteID) {
		return errors.New("nginx.disable payload is invalid")
	}
	nginxMu.Lock()
	defer nginxMu.Unlock()
	root, err := os.OpenRoot(env.root)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "tp-" + input.SiteID + ".conf"
	old, err := root.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(old), "# Managed by TomPanel: "+input.SiteID+"\n") {
		return errors.New("refusing to disable an unmanaged nginx config")
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	if err := env.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		_ = root.WriteFile(name, old, 0o640)
		return err
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		_ = root.WriteFile(name, old, 0o640)
		_ = env.run(ctx, "/usr/bin/systemctl", "reload", "nginx")
		return err
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) error {
	output, err := commandOutput(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	return command.CombinedOutput()
}

func nginxHealth(ctx context.Context, host string, port int) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		return err
	}
	request.Host = host
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode >= 500 {
		return fmt.Errorf("site returned HTTP %d", response.StatusCode)
	}
	return nil
}

func decodeStrict(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("payload contains trailing data")
	}
	return nil
}

func validSiteID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func defaultNginxEnvironment() nginxEnvironment {
	return nginxEnvironment{root: "/etc/nginx/sites-enabled", run: runCommand, health: nginxHealth}
}

func validateUFW(input ufwInput) error {
	if !validSiteID(input.SiteID) || input.Port < 1 || input.Port > 65535 {
		return errors.New("UFW payload is invalid")
	}
	return nil
}

func ensureUFW(ctx context.Context, input ufwInput) error {
	if err := validateUFW(input); err != nil {
		return err
	}
	return runCommand(ctx, "/usr/sbin/ufw", "allow", strconv.Itoa(input.Port)+"/tcp", "comment", "TomPanel:"+input.SiteID)
}

func removeOwnedUFW(ctx context.Context, input ufwInput) error {
	return removeOwnedUFWWith(ctx, input, commandOutput, runCommand)
}

func removeOwnedUFWWith(ctx context.Context, input ufwInput, output func(context.Context, string, ...string) ([]byte, error), run func(context.Context, string, ...string) error) error {
	if err := validateUFW(input); err != nil {
		return err
	}
	status, err := output(ctx, "/usr/sbin/ufw", "status", "numbered")
	if err != nil {
		return fmt.Errorf("list UFW rules: %w", err)
	}
	var numbers []int
	for _, line := range strings.Split(string(status), "\n") {
		match := ufwRuleLine.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 4 || match[2] != strconv.Itoa(input.Port) || match[3] != input.SiteID {
			continue
		}
		number, _ := strconv.Atoi(match[1])
		numbers = append(numbers, number)
	}
	for index := len(numbers) - 1; index >= 0; index-- {
		if err := run(ctx, "/usr/sbin/ufw", "--force", "delete", strconv.Itoa(numbers[index])); err != nil {
			return fmt.Errorf("remove owned UFW rule: %w", err)
		}
	}
	return nil
}
