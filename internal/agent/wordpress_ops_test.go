package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/apps"
)

type wpCallLog struct {
	calls []apps.WPCLICall
	failOn func(joinedArgs string) bool
	healthFails bool
}

func (l *wpCallLog) run(_ context.Context, call apps.WPCLICall) error {
	l.calls = append(l.calls, call)
	if l.failOn != nil && l.failOn(strings.Join(call.Args, " ")) {
		return errors.New("wp-cli forced failure")
	}
	return nil
}

func wpTestInput() apps.WordPressInstallInput {
	return apps.WordPressInstallInput{
		SiteID: dbTestSiteID, SiteURL: "https://wp.example.test",
		Database: "tp_" + dbTestSiteID[:16] + "_wp", DBUser: "tp_" + dbTestSiteID[:16] + "_u1",
		DBPassword: "db-secret-password-12345", AdminUser: "tom", AdminEmail: "tom@example.test",
		AdminPassword: "admin-secret-password-1", Title: "Site", Policy: apps.DefaultWordPressPolicy(),
	}
}

func TestInstallWordPressRunsBuiltCalls(t *testing.T) {
	log := &wpCallLog{}
	env := wordpressEnvironment{runWP: log.run, health: func(context.Context, string) error { return nil }}
	if err := installWordPress(context.Background(), wordpressInstallInput{WordPressInstallInput: wpTestInput()}, env); err != nil {
		t.Fatal(err)
	}
	if len(log.calls) == 0 {
		t.Fatal("no wp-cli calls executed")
	}
	for _, call := range log.calls {
		if strings.Contains(strings.Join(call.Args, " "), "db-secret-password-12345") ||
			strings.Contains(strings.Join(call.Args, " "), "admin-secret-password-1") {
			t.Fatalf("secret leaked into argv: %v", call.Args)
		}
	}
}

func TestFailedUpdateRestoresBackup(t *testing.T) {
	log := &wpCallLog{failOn: func(joined string) bool { return strings.Contains(joined, "core update") && !strings.Contains(joined, "--version") }}
	env := wordpressEnvironment{runWP: log.run, health: func(context.Context, string) error { return nil }}
	err := updateWordPress(context.Background(), wordpressUpdateInput{WordPressInstallInput: wpTestInput()}, env)
	if err == nil {
		t.Fatal("update succeeded despite core failure")
	}
	joined := ""
	for _, call := range log.calls {
		joined += strings.Join(call.Args, " ") + "\n"
	}
	if !strings.Contains(joined, "db import ../.tompanel/pre-update.sql") {
		t.Fatalf("failed update did not restore the database backup: %s", joined)
	}
	if !strings.Contains(joined, "core update --version=") {
		t.Fatalf("failed update did not pin the previous core version: %s", joined)
	}
}

func TestUnhealthyUpdateRollsBack(t *testing.T) {
	log := &wpCallLog{}
	env := wordpressEnvironment{runWP: log.run, health: func(context.Context, string) error { return errors.New("site down") }}
	if err := updateWordPress(context.Background(), wordpressUpdateInput{WordPressInstallInput: wpTestInput()}, env); err == nil {
		t.Fatal("unhealthy update accepted")
	}
	joined := ""
	for _, call := range log.calls {
		joined += strings.Join(call.Args, " ") + "\n"
	}
	if !strings.Contains(joined, "db import") {
		t.Fatalf("unhealthy update skipped rollback: %s", joined)
	}
}

func TestWordPressCronManagedFile(t *testing.T) {
	cronDir := t.TempDir()
	log := &wpCallLog{}
	env := wordpressEnvironment{runWP: log.run, cronRoot: cronDir}
	if err := configureWordPressCron(context.Background(), wordpressCronInput{SiteID: dbTestSiteID, Enabled: true}, env); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(cronDir, "tompanel-wp-"+dbTestSiteID))
	if err != nil || !strings.HasPrefix(string(content), "# Managed by TomPanel: "+dbTestSiteID) {
		t.Fatalf("cron file malformed: %q %v", content, err)
	}
	if !strings.Contains(string(content), "DISABLE_WP_CRON") && !strings.Contains(strings.Join(argsOf(log), " "), "DISABLE_WP_CRON true") {
		t.Fatal("wp-cron not disabled in configuration")
	}
	if err := configureWordPressCron(context.Background(), wordpressCronInput{SiteID: dbTestSiteID, Enabled: false}, env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cronDir, "tompanel-wp-"+dbTestSiteID)); !os.IsNotExist(err) {
		t.Fatal("cron file survived disable")
	}
}

func argsOf(log *wpCallLog) []string {
	var result []string
	for _, call := range log.calls {
		result = append(result, strings.Join(call.Args, " "))
	}
	return result
}

func TestClearCacheTouchesOnlySelectedSite(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, dbTestSiteID, "wp-content", "cache", "fastcache")
	other := filepath.Join(base, "99999999999999999999999999999999", "wp-content", "cache", "fastcache")
	for _, dir := range []string{target, other} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "entry"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearWordPressCache(context.Background(), siteInput{SiteID: dbTestSiteID}, base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("selected site cache survived")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another site's cache was removed: %v", err)
	}
}

func TestEnsureWPCLIVerifiesChecksum(t *testing.T) {
	dir := t.TempDir()
	phar := []byte("fake wp-cli phar binary")
	env := wordpressEnvironment{
		installRoot: filepath.Join(dir, "wp"),
		version:     "2.2.0",
		expectedSHA: "6f4d1a0e8b8f4b9e2e9d4f0f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7",
		download: func(context.Context) ([]byte, error) { return nil, errors.New("unused") },
	}
	// wrong checksum
	env.download = func(context.Context) ([]byte, error) { return phar, nil }
	if err := ensureWPCLI(context.Background(), wordpressEnsureCLIInput{Version: "2.2.0"}, env); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if err := ensureWPCLI(context.Background(), wordpressEnsureCLIInput{Version: "9.9.9"}, env); err == nil {
		t.Fatal("unpinned version accepted")
	}
}
