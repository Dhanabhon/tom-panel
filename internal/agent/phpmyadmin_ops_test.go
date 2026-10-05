package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func phpmyadminArchiveFixture(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	files := map[string]string{
		"phpMyAdmin-5.2.2/index.php":                      "<?php // entry",
		"phpMyAdmin-5.2.2/libraries/classes/Core.php":     "<?php // core",
		"phpMyAdmin-5.2.2/themes/original/css/custom.css": "body{}",
	}
	for name, content := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

type phpmyadminHarness struct {
	env      phpmyadminEnvironment
	ufwCalls []ufwInput
	nginxDir string
	authDir  string
}

func newPHPMyAdminHarness(t *testing.T) *phpmyadminHarness {
	t.Helper()
	archive := phpmyadminArchiveFixture(t)
	sum := sha256.Sum256(archive)
	nginxDir := t.TempDir()
	authDir := t.TempDir()
	runner := &fakeRunner{}
	harness := &phpmyadminHarness{nginxDir: nginxDir, authDir: authDir}
	harness.env = phpmyadminEnvironment{
		installRoot: filepath.Join(t.TempDir(), "phpmyadmin"),
		authRoot:    authDir,
		version:     "5.2.2",
		expectedSHA: hex.EncodeToString(sum[:]),
		download: func(context.Context) ([]byte, error) {
			return archive, nil
		},
		ufwEnsure: func(_ context.Context, input ufwInput) error {
			harness.ufwCalls = append(harness.ufwCalls, input)
			return nil
		},
		ufwRemove: func(_ context.Context, input ufwInput) error {
			harness.ufwCalls = append(harness.ufwCalls, input)
			return nil
		},
	}
	harness.env.nginx = nginxEnvironment{root: nginxDir, run: runner.run}
	return harness
}

func TestPHPMyAdminInstallVerifiesChecksum(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	result, err := installPHPMyAdmin(context.Background(), phpmyadminInstallInput{Version: "5.2.2"}, harness.env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(result.InstallPath, "index.php")); err != nil {
		t.Fatalf("installed entry missing: %v", err)
	}
	second, err := installPHPMyAdmin(context.Background(), phpmyadminInstallInput{Version: "5.2.2"}, harness.env)
	if err != nil || second.InstallPath != result.InstallPath {
		t.Fatalf("reinstall not idempotent: %+v %v", second, err)
	}
	harness.env.expectedSHA = "deadbeef"
	if _, err := installPHPMyAdmin(context.Background(), phpmyadminInstallInput{Version: "5.2.2"}, harness.env); err == nil {
		// Reinstall is a no-op when index.php exists, so force a fresh root.
		fresh := harness.env
		fresh.installRoot = filepath.Join(t.TempDir(), "phpmyadmin2")
		if _, err := installPHPMyAdmin(context.Background(), phpmyadminInstallInput{Version: "5.2.2"}, fresh); err == nil {
			t.Fatal("checksum mismatch accepted")
		}
	}
	if _, err := installPHPMyAdmin(context.Background(), phpmyadminInstallInput{Version: "9.9.9"}, harness.env); err == nil {
		t.Fatal("unpinned version accepted")
	}
}

func TestPrivatePHPMyAdminOpensNoFirewall(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	result, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "private", Port: 8091,
	}, harness.env)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "listen 127.0.0.1:8091;") {
		t.Fatalf("private mode must bind loopback: %s", config)
	}
	if strings.Contains(string(config), "ssl_certificate") || strings.Contains(string(config), "auth_basic") {
		t.Fatalf("private mode must not add TLS or basic auth: %s", config)
	}
	if len(harness.ufwCalls) != 0 {
		t.Fatalf("private mode opened firewall rules: %+v", harness.ufwCalls)
	}
}

func TestPublicPHPMyAdminRequiresTLSAuthAndRateLimit(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	result, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "public_subdomain", Hostname: "db.example.test", Port: 443,
		BasicUser: "admin", BasicSecret: "db-admin-password-1",
	}, harness.env)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"443 ssl", "server_name db.example.test;", "limit_req", "auth_basic", "ssl_certificate"} {
		if !strings.Contains(string(config), required) {
			t.Fatalf("public config missing %q:\n%s", required, config)
		}
	}
	if len(harness.ufwCalls) != 0 {
		t.Fatalf("subdomain mode must reuse 443 without new firewall rules: %+v", harness.ufwCalls)
	}
	entries, err := os.ReadDir(harness.authDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("basic auth file missing: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(harness.authDir, entries[0].Name()))
	if err != nil || !strings.HasPrefix(string(stored), "admin:$2") {
		t.Fatalf("htpasswd malformed: %q %v", stored, err)
	}
	if strings.Contains(string(stored), "db-admin-password-1") {
		t.Fatal("basic auth secret stored in plaintext")
	}
}

func TestPublicPortModeOpensOnlyItsPort(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	_, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "public_port", Hostname: "db.example.test", Port: 8443,
		BasicUser: "admin", BasicSecret: "db-admin-password-1",
	}, harness.env)
	if err != nil {
		t.Fatal(err)
	}
	if len(harness.ufwCalls) != 1 || harness.ufwCalls[0].Port != 8443 || harness.ufwCalls[0].SiteID != dbTestSiteID {
		t.Fatalf("public port firewall calls: %+v", harness.ufwCalls)
	}
}

func TestPublicModeWithoutCredentialsIsRejected(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	if _, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "public_port", Hostname: "db.example.test", Port: 8443,
	}, harness.env); err == nil {
		t.Fatal("public mode accepted without basic auth credentials")
	}
}

func TestDisableRemovesOnlyOwnedResources(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	_, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "public_port", Hostname: "db.example.test", Port: 8443,
		BasicUser: "admin", BasicSecret: "db-admin-password-1",
	}, harness.env)
	if err != nil {
		t.Fatal(err)
	}
	// Drop an unmanaged file into the nginx root that must survive.
	innocent := filepath.Join(harness.nginxDir, "customer.conf")
	if err := os.WriteFile(innocent, []byte("server {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := disablePHPMyAdmin(context.Background(), phpmyadminDisableInput{SiteID: dbTestSiteID, Port: 8443}, harness.env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(harness.nginxDir, "tompanel-phpmyadmin-"+dbTestSiteID+".conf")); !os.IsNotExist(err) {
		t.Fatal("managed phpmyadmin config survived disable")
	}
	if _, err := os.Stat(innocent); err != nil {
		t.Fatalf("unmanaged config was removed: %v", err)
	}
	if len(harness.ufwCalls) != 2 {
		t.Fatalf("disable must remove the owned firewall rule: %+v", harness.ufwCalls)
	}
	if harness.ufwCalls[1].Port != 8443 {
		t.Fatalf("disable removed the wrong firewall rule: %+v", harness.ufwCalls)
	}
}

func TestNginxConfigRefusesUnmanagedReplacement(t *testing.T) {
	harness := newPHPMyAdminHarness(t)
	name := "tompanel-phpmyadmin-" + dbTestSiteID + ".conf"
	if err := os.WriteFile(filepath.Join(harness.nginxDir, name), []byte("# customer managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := activatePHPMyAdmin(context.Background(), phpmyadminActivateInput{
		SiteID: dbTestSiteID, Mode: "private", Port: 8091,
	}, harness.env); err == nil {
		t.Fatal("replaced an unmanaged phpmyadmin config")
	}
}
