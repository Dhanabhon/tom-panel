package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const laravelRelease = "000000100"

type laravelCall struct {
	name string
	args string
	dir  string
	env  []string
}

type laravelCallLog struct {
	calls       []laravelCall
	failOn      func(name string) bool
	healthFails bool
}

func (l *laravelCallLog) run(_ context.Context, name string, args []string, _ []byte, env []string, dir string) error {
	l.calls = append(l.calls, laravelCall{name: filepath.Base(name), args: strings.Join(args, " "), dir: dir, env: env})
	if l.failOn != nil && l.failOn(filepath.Base(name)) {
		return errors.New("forced failure")
	}
	return nil
}

func laravelHarness(t *testing.T) (string, laravelEnvironment, *laravelCallLog) {
	t.Helper()
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, dbTestSiteID), 0o755); err != nil {
		t.Fatal(err)
	}
	log := &laravelCallLog{}
	env := laravelEnvironment{
		run:     log.run,
		systemd: filepath.Join(base, "systemd"),
		health:  func(context.Context, string, int) error { return nil },
	}
	if err := os.MkdirAll(env.systemd, 0o755); err != nil {
		t.Fatal(err)
	}
	original := siteRootPath
	siteRootPath = base
	t.Cleanup(func() { siteRootPath = original })
	return base, env, log
}

func TestLaravelCheckoutLocksUnsafeTransports(t *testing.T) {
	base, env, log := laravelHarness(t)
	if err := checkoutLaravel(context.Background(), laravelCheckoutInput{
		SiteID: dbTestSiteID, Repository: "file:///tmp/repo", Branch: "main", Release: laravelRelease,
	}, env); err == nil {
		t.Fatal("local transport accepted")
	}
	if err := checkoutLaravel(context.Background(), laravelCheckoutInput{
		SiteID: dbTestSiteID, Repository: "https://github.com/tom/app.git", Branch: "main", Release: laravelRelease,
	}, env); err != nil {
		t.Fatal(err)
	}
	if len(log.calls) == 0 || log.calls[0].name != "git" {
		t.Fatalf("git not invoked: %+v", log.calls)
	}
	args := log.calls[0].args
	if !strings.Contains(args, "protocol.ext.allow=never") || !strings.Contains(args, "protocol.file.allow=never") {
		t.Fatalf("git transports not locked: %s", args)
	}
	if !strings.Contains(args, "releases/"+laravelRelease) {
		t.Fatalf("clone target not a release directory: %s", args)
	}
	if strings.Contains(args, "..") {
		t.Fatalf("traversal in clone target: %s", args)
	}
	_ = base
}

func TestNodeBuildRequiresLockfile(t *testing.T) {
	base, env, log := laravelHarness(t)
	if err := nodeBuildLaravel(context.Background(), laravelReleaseInput{SiteID: dbTestSiteID, Release: laravelRelease}, env); err == nil {
		t.Fatal("node build accepted without package-lock.json")
	}
	if len(log.calls) != 0 {
		t.Fatal("node build executed despite missing lockfile")
	}
	releaseDir := filepath.Join(base, dbTestSiteID, releasesRel, laravelRelease)
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := nodeBuildLaravel(context.Background(), laravelReleaseInput{SiteID: dbTestSiteID, Release: laravelRelease}, env); err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, call := range log.calls {
		joined += call.name + " " + call.args + ";"
	}
	if !strings.Contains(joined, "npm ci") || !strings.Contains(joined, "npm run build") {
		t.Fatalf("node build sequence wrong: %s", joined)
	}
}

func TestFailedHealthCheckKeepsCurrentRelease(t *testing.T) {
	base, env, _ := laravelHarness(t)
	env.health = func(context.Context, string, int) error { return errors.New("release unhealthy") }
	if err := healthCheckLaravel(context.Background(), laravelHealthInput{
		SiteID: dbTestSiteID, Hostname: "app.example.test", HTTPSPort: 443,
	}, env); err == nil {
		t.Fatal("failing health check accepted")
	}
	// An earlier release stays current because activation never runs.
	if _, err := os.Lstat(filepath.Join(base, dbTestSiteID, currentRel)); !os.IsNotExist(err) {
		t.Fatal("current symlink changed despite failed health check")
	}
}

func TestActivateReleaseIsAtomicAndReroutesPublic(t *testing.T) {
	base, env, _ := laravelHarness(t)
	site := filepath.Join(base, dbTestSiteID)
	releaseDir := filepath.Join(site, releasesRel, laravelRelease)
	if err := os.MkdirAll(filepath.Join(releaseDir, "public"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(site, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "public", "placeholder.html"), []byte("static"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := activateLaravel(context.Background(), laravelReleaseInput{SiteID: dbTestSiteID, Release: laravelRelease}, env); err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink(filepath.Join(site, currentRel))
	if err != nil || !strings.HasSuffix(current, filepath.Join(releasesRel, laravelRelease)) {
		t.Fatalf("current symlink wrong: %q %v", current, err)
	}
	public, err := os.Readlink(filepath.Join(site, "public"))
	if err != nil || !strings.HasSuffix(public, filepath.Join(currentRel, "public")) {
		t.Fatalf("public not rerouted: %q %v", public, err)
	}
	if _, err := os.Stat(filepath.Join(site, legacyPublicRel, "placeholder.html")); err != nil {
		t.Fatalf("original public content not preserved: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(site, currentRel+".new")); !os.IsNotExist(err) {
		t.Fatal("candidate symlink leaked")
	}
}

func TestConfigureEnvironmentKeepsSecretsOutOfArgv(t *testing.T) {
	base, env, log := laravelHarness(t)
	input := laravelEnvInput{
		SiteID: dbTestSiteID, Database: "tp_" + dbTestSiteID[:16] + "_laravel",
		Username: "tp_" + dbTestSiteID[:16] + "_u1", Password: "laravel-db-secret-123456",
		AppKey: "base64:GENERATEDAPPKEYVALUE==", AppURL: "https://app.example.test",
	}
	if err := configureLaravelEnvironment(context.Background(), input, env); err != nil {
		t.Fatal(err)
	}
	for _, call := range log.calls {
		if strings.Contains(call.args, "laravel-db-secret-123456") {
			t.Fatalf("secret leaked into argv: %s", call.args)
		}
	}
	content, err := os.ReadFile(filepath.Join(base, dbTestSiteID, sharedRel, ".env"))
	if err != nil || !strings.Contains(string(content), "DB_PASSWORD=laravel-db-secret-123456") {
		t.Fatalf("environment file wrong: %q %v", content, err)
	}
	info, err := os.Stat(filepath.Join(base, dbTestSiteID, sharedRel, ".env"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf(".env permissions: %v %v", info.Mode().Perm(), err)
	}
}

func TestEnsureWorkersManagesMarkedUnits(t *testing.T) {
	_, env, _ := laravelHarness(t)
	if err := ensureLaravelWorkers(context.Background(), laravelWorkersInput{SiteID: dbTestSiteID, Enabled: true}, env); err != nil {
		t.Fatal(err)
	}
	queue, err := os.ReadFile(filepath.Join(env.systemd, "tompanel-site-"+dbTestSiteID+"-queue.service"))
	if err != nil || !strings.HasPrefix(string(queue), "# Managed by TomPanel: "+dbTestSiteID) {
		t.Fatalf("queue unit malformed: %q %v", queue, err)
	}
	if !strings.Contains(string(queue), "php artisan queue:work") {
		t.Fatalf("queue unit missing worker command: %s", queue)
	}
	if _, err := os.Stat(filepath.Join(env.systemd, "tompanel-site-"+dbTestSiteID+"-scheduler.timer")); err != nil {
		t.Fatal("scheduler timer missing")
	}
	if err := ensureLaravelWorkers(context.Background(), laravelWorkersInput{SiteID: dbTestSiteID, Enabled: false}, env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.systemd, "tompanel-site-"+dbTestSiteID+"-queue.service")); !os.IsNotExist(err) {
		t.Fatal("worker unit survived disable")
	}
}

func TestMigrationRefusalOnMissingRelease(t *testing.T) {
	_, env, log := laravelHarness(t)
	if err := migrateLaravel(context.Background(), laravelReleaseInput{SiteID: dbTestSiteID, Release: "abc"}, env); err == nil {
		t.Fatal("invalid release accepted for migration")
	}
	if len(log.calls) != 0 {
		t.Fatal("migration executed despite invalid release")
	}
	if err := migrateLaravel(context.Background(), laravelReleaseInput{SiteID: dbTestSiteID, Release: laravelRelease}, env); err != nil {
		t.Fatal(err)
	}
	if len(log.calls) != 1 || !strings.Contains(log.calls[0].args, "artisan migrate --force") {
		t.Fatalf("migration call wrong: %+v", log.calls)
	}
}
