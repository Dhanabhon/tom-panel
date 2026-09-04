package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var phpPackageMu sync.Mutex

type phpPoolInput struct {
	SiteID  string `json:"site_id"`
	Version string `json:"version"`
	Config  string `json:"config"`
}

type phpExtensionInput struct {
	Version   string `json:"version"`
	Extension string `json:"extension"`
}

func ensurePHP(ctx context.Context, input phpPoolInput, run func(context.Context, string, ...string) error) error {
	if !validSiteID(input.SiteID) || !validPHPVersion(input.Version) {
		return errors.New("PHP pool payload is invalid")
	}
	return run(ctx, "/usr/sbin/php-fpm"+input.Version, "-v")
}

func activatePHPPool(ctx context.Context, input phpPoolInput, rootPath string, run func(context.Context, string, ...string) error) error {
	marker := "; Managed by TomPanel: " + input.SiteID + "\n"
	if !validSiteID(input.SiteID) || !validPHPVersion(input.Version) || !strings.HasPrefix(input.Config, marker) || len(input.Config) > 128<<10 {
		return errors.New("PHP pool payload is invalid")
	}
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "tp_" + input.SiteID[:16] + ".conf"
	old, readErr := root.ReadFile(name)
	hadOld := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if hadOld && !strings.HasPrefix(string(old), marker) {
		return errors.New("refusing to replace an unmanaged PHP pool")
	}
	temporary := "." + name + ".new"
	if err := root.WriteFile(temporary, []byte(input.Config), 0o640); err != nil {
		return err
	}
	defer root.Remove(temporary)
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	restore := func() error {
		if hadOld {
			if err := root.WriteFile(name, old, 0o640); err != nil {
				return fmt.Errorf("restore PHP-FPM pool: %w", err)
			}
			return nil
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove failed PHP-FPM pool: %w", err)
		}
		return nil
	}
	binary := "/usr/sbin/php-fpm" + input.Version
	service := "php" + input.Version + "-fpm"
	if err := run(ctx, binary, "-t"); err != nil {
		return errors.Join(fmt.Errorf("validate PHP-FPM: %w", err), restore())
	}
	if err := run(ctx, "/usr/bin/systemctl", "reload", service); err != nil {
		return errors.Join(fmt.Errorf("reload PHP-FPM: %w", err), restore(),
			run(ctx, binary, "-t"), run(ctx, "/usr/bin/systemctl", "reload", service))
	}
	return nil
}

func disablePHPPool(ctx context.Context, input phpPoolInput, rootPath string, run func(context.Context, string, ...string) error) error {
	if !validSiteID(input.SiteID) || !validPHPVersion(input.Version) {
		return errors.New("PHP pool payload is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "tp_" + input.SiteID[:16] + ".conf"
	old, err := root.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(old), "; Managed by TomPanel: "+input.SiteID+"\n") {
		return errors.New("refusing to remove an unmanaged PHP-FPM pool")
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	restore := func() error { return root.WriteFile(name, old, 0o640) }
	binary, service := "/usr/sbin/php-fpm"+input.Version, "php"+input.Version+"-fpm"
	if err := run(ctx, binary, "-t"); err != nil {
		return errors.Join(fmt.Errorf("validate PHP-FPM without pool: %w", err), restore())
	}
	if err := run(ctx, "/usr/bin/systemctl", "reload", service); err != nil {
		return errors.Join(fmt.Errorf("reload PHP-FPM without pool: %w", err), restore(),
			run(ctx, binary, "-t"), run(ctx, "/usr/bin/systemctl", "reload", service))
	}
	return nil
}

func validateExtension(input phpExtensionInput) error {
	if !validPHPVersion(input.Version) {
		return errors.New("PHP version is unsupported")
	}
	allowed := map[string]bool{
		"curl": true, "gd": true, "imagick": true, "intl": true, "mbstring": true,
		"mysql": true, "redis": true, "xml": true, "zip": true,
	}
	if !allowed[input.Extension] {
		return errors.New("PHP extension is unsupported")
	}
	return nil
}

func installPHPExtension(ctx context.Context, input phpExtensionInput) error {
	if err := validateExtension(input); err != nil {
		return err
	}
	phpPackageMu.Lock()
	defer phpPackageMu.Unlock()
	packageName := "php" + input.Version + "-" + input.Extension
	return runCommand(ctx, "/usr/bin/apt-get", "install", "-y", "--no-install-recommends", packageName)
}

func validPHPVersion(version string) bool {
	return version == "8.3" || version == "8.4" || version == "8.5"
}

func phpPoolRoot(version string) string {
	return filepath.Join("/etc/php", version, "fpm", "pool.d")
}
