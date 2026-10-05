package apps

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	// ErrUnsafeGitTransport marks repository URLs that must not be cloned.
	ErrUnsafeGitTransport = errors.New("git transport is not allowed")
	// ErrMissingLockfile marks Node builds requested without package-lock.json.
	ErrMissingLockfile = errors.New("package-lock.json is required for node builds")

	// LaravelInstallJobKind installs a first Laravel release.
	LaravelInstallJobKind = "laravel.install"
	// LaravelDeployJobKind ships a new atomic release.
	LaravelDeployJobKind = "laravel.deploy"
	// LaravelSuffix is the database suffix dedicated to Laravel.
	LaravelSuffix = "laravel"
)

// LaravelInstallInput describes one guided installation.
type LaravelInstallInput struct {
	SiteID     string `json:"site_id"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	NodeBuild  bool   `json:"node_build"`
}

// LaravelDeployInput describes one deployment.
type LaravelDeployInput struct {
	SiteID        string `json:"site_id"`
	Repository    string `json:"repository"`
	Branch        string `json:"branch"`
	NodeBuild     bool   `json:"node_build"`
	HTTPSPort     int    `json:"https_port"`
	RunMigrations bool   `json:"run_migrations"`
	Release       string `json:"release"`
}

// ValidateLaravelRepo accepts HTTPS and SSH Git locations only. Local,
// file, and ext transports are rejected before any clone runs.
func ValidateLaravelRepo(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 2048 || strings.ContainsAny(trimmed, " \t\n\r") {
		return fmt.Errorf("%w: repository URL is malformed", ErrUnsafeGitTransport)
	}
	if strings.HasPrefix(trimmed, "git@") {
		if !strings.Contains(trimmed, ":") || !strings.HasSuffix(trimmed, ".git") {
			return fmt.Errorf("%w: SSH location is malformed", ErrUnsafeGitTransport)
		}
		return nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("%w: only https or SSH locations are allowed", ErrUnsafeGitTransport)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not allowed", ErrUnsafeGitTransport, parsed.Scheme)
	}
	if parsed.Host == "" || strings.Contains(parsed.Path, "..") {
		return fmt.Errorf("%w: repository host or path is malformed", ErrUnsafeGitTransport)
	}
	return nil
}

// ValidateLaravelBranch accepts a plain Git branch name.
func ValidateLaravelBranch(branch string) error {
	trimmed := strings.TrimSpace(branch)
	if trimmed == "" || len(trimmed) > 128 {
		return errors.New("branch is invalid")
	}
	if strings.HasPrefix(trimmed, "-") || strings.ContainsAny(trimmed, " \t\n\r~^:?*[\\") {
		return errors.New("branch is invalid")
	}
	return nil
}

// BuildLaravelInstallJob assembles the first-release pipeline.
func BuildLaravelInstallJob(input LaravelInstallInput) ([]string, error) {
	if err := ValidateLaravelRepo(input.Repository); err != nil {
		return nil, err
	}
	if err := ValidateLaravelBranch(input.Branch); err != nil {
		return nil, err
	}
	if !validSiteID(input.SiteID) {
		return nil, fmt.Errorf("%w: site id", ErrInvalidInput)
	}
	steps := []string{"laravel.checkout", "laravel.composer_install"}
	if input.NodeBuild {
		steps = append(steps, "laravel.node_build")
	}
	steps = append(steps, "laravel.configure_environment", "laravel.migrate", "laravel.optimize", "laravel.health_check", "laravel.activate_release", "laravel.ensure_workers")
	return steps, nil
}

// BuildLaravelDeployJob assembles the fixed deployment pipeline. Migrations
// are a separately confirmed step and activation happens only after the
// health gate, so a failed deployment keeps the current release live.
func BuildLaravelDeployJob(input LaravelDeployInput) ([]string, error) {
	if err := ValidateLaravelRepo(input.Repository); err != nil {
		return nil, err
	}
	if err := ValidateLaravelBranch(input.Branch); err != nil {
		return nil, err
	}
	if !validSiteID(input.SiteID) {
		return nil, fmt.Errorf("%w: site id", ErrInvalidInput)
	}
	if input.HTTPSPort < 1 || input.HTTPSPort > 65535 {
		return nil, fmt.Errorf("%w: https port", ErrInvalidInput)
	}
	steps := []string{"laravel.checkout", "laravel.composer_install"}
	if input.NodeBuild {
		steps = append(steps, "laravel.node_build")
	}
	if input.RunMigrations {
		steps = append(steps, "laravel.migrate")
	}
	steps = append(steps, "laravel.optimize", "laravel.health_check", "laravel.activate_release")
	return steps, nil
}

// GenerateReleaseID mints a sortable release identifier.
func GenerateReleaseID(unix int64) string {
	return fmt.Sprintf("%09d", unix)
}
