//go:build docker

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/domains"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

func TestDockerGeneratedConfigs(t *testing.T) {
	const siteID = "f00df00df00df00df00df00df00df00d"
	ctx := context.Background()
	payload := json.RawMessage(`{"site_id":"` + siteID + `"}`)
	username := "tp_" + siteID[:16]

	_ = runCommand(ctx, "/usr/sbin/userdel", username)
	_ = os.RemoveAll(filepath.Join(siteRootPath, siteID))
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join("/etc/nginx/sites-enabled", "tp-"+siteID+".conf"))
		_ = os.Remove(filepath.Join("/etc/nginx/sites-enabled", ".tp-"+siteID+".conf.rollback"))
		_ = os.Remove(filepath.Join("/etc/php/8.3/fpm/pool.d", "tp_"+siteID[:16]+".conf"))
		_ = os.RemoveAll(filepath.Join(siteRootPath, siteID))
		_ = runCommand(ctx, "/usr/sbin/userdel", username)
	})

	if _, err := ensureIdentity(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureDirectories(ctx, payload, siteRootPath); err != nil {
		t.Fatal(err)
	}
	if err := setDirectoryOwner(siteID, siteRootPath); err != nil {
		t.Fatal(err)
	}
	if err := runCommand(ctx, "/usr/sbin/runuser", "-u", "www-data", "--", "/usr/bin/test", "-x", filepath.Join(siteRootPath, siteID, "public")); err != nil {
		t.Fatalf("www-data cannot traverse the public root: %v", err)
	}

	phpConfig, err := panelruntime.RenderPool(siteID, panelruntime.DefaultPHPConfig("8.3"))
	if err != nil {
		t.Fatal(err)
	}
	runWithoutSystemd := func(ctx context.Context, name string, args ...string) error {
		if name == "/usr/bin/systemctl" {
			return nil
		}
		return runCommand(ctx, name, args...)
	}
	if err := activatePHPPool(ctx, phpPoolInput{SiteID: siteID, Version: "8.3", Config: string(phpConfig)}, "/etc/php/8.3/fpm/pool.d", runWithoutSystemd); err != nil {
		t.Fatal(err)
	}

	site := sites.Site{ID: siteID, Kind: sites.KindPHP, PrimaryDomain: "docker.test", HTTPPort: 18080, HTTPSPort: 18443, Public: true, PHPVersion: "8.3"}
	nginxConfig, err := domains.RenderNginx(site, []domains.Hostname{"docker.test"})
	if err != nil {
		t.Fatal(err)
	}
	env := nginxEnvironment{
		root: "/etc/nginx/sites-enabled",
		run:  runWithoutSystemd,
		health: func(context.Context, string, int) error {
			return nil
		},
	}
	if err := activateNginx(ctx, nginxActivateInput{SiteID: siteID, Config: string(nginxConfig), HealthHost: "docker.test", HealthPort: 18080}, env); err != nil {
		t.Fatal(err)
	}
}
