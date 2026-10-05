package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type endpointCertRecorder struct {
	nginxRuns     []string
	ufwCalls      []string
	failNginxTest bool
}

func (r *endpointCertRecorder) run(ctx context.Context, name string, args ...string) error {
	r.nginxRuns = append(r.nginxRuns, name+" "+strings.Join(args, " "))
	if r.failNginxTest && name == "/usr/sbin/nginx" && len(args) > 0 && args[0] == "-t" {
		return errors.New("nginx -t failed")
	}
	return nil
}

func (r *endpointCertRecorder) allow(ctx context.Context, port int, comment string) error {
	r.ufwCalls = append(r.ufwCalls, comment)
	return nil
}

func endpointCertHarness(t *testing.T) (*endpointCertEnvironment, *endpointCertRecorder) {
	t.Helper()
	base := t.TempDir()
	recorder := &endpointCertRecorder{}
	env := &endpointCertEnvironment{
		webrootNginxConf: "tompanel-acme-webroot.conf",
		nginx: nginxEnvironment{
			root: filepath.Join(base, "nginx"),
			run:  recorder.run,
		},
		ufwAllow: recorder.allow,
	}
	if err := os.MkdirAll(env.nginx.root, 0o755); err != nil {
		t.Fatal(err)
	}
	original := siteRootPath
	siteRootPath = base
	t.Cleanup(func() { siteRootPath = original })
	return env, recorder
}

func TestPanelEndpointSiteIDIsValidIdentifier(t *testing.T) {
	if !validSiteID(panelEndpointSiteID) {
		t.Fatalf("panel endpoint id %q is not a valid site identifier", panelEndpointSiteID)
	}
}

func TestValidateEndpointIssue(t *testing.T) {
	good, err := validateEndpointIssue(endpointIssueInput{
		Hostname: "Panel.Example.com", Email: "tom@example.com", Challenge: "dns-01", APIToken: "token-123",
	})
	if err != nil || good != "panel.example.com" {
		t.Fatalf("validate: %q %v", good, err)
	}
	for _, input := range []endpointIssueInput{
		{Hostname: "not a hostname", Email: "tom@example.com", Challenge: "http-01"},
		{Hostname: "panel.example.com", Email: "not-an-email", Challenge: "http-01"},
		{Hostname: "panel.example.com", Email: "tom@example.com", Challenge: "dns"},
	} {
		if _, err := validateEndpointIssue(input); err == nil {
			t.Fatalf("accepted %+v", input)
		}
	}
}

func TestEnsureACMEWebrootWritesManagedVhostAndOpensPort(t *testing.T) {
	env, recorder := endpointCertHarness(t)
	if err := ensureACMEWebroot(context.Background(), "panel.example.com", *env); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(env.nginx.root, "tompanel-acme-webroot.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(conf), "# Managed by TomPanel: acme-webroot\n") {
		t.Fatalf("vhost missing marker: %s", conf)
	}
	if !strings.Contains(string(conf), "server_name panel.example.com;") ||
		!strings.Contains(string(conf), "location /.well-known/acme-challenge/") {
		t.Fatalf("vhost content wrong: %s", conf)
	}
	if len(recorder.ufwCalls) != 1 || recorder.ufwCalls[0] != "TomPanel:acme-webroot" {
		t.Fatalf("ufw calls: %v", recorder.ufwCalls)
	}
	joined := strings.Join(recorder.nginxRuns, ";")
	if !strings.Contains(joined, "nginx -t") || !strings.Contains(joined, "systemctl reload nginx") {
		t.Fatalf("nginx validation/reload missing: %s", joined)
	}
}

func TestEnsureACMEWebrootRefusesUnmanagedAndRollsBack(t *testing.T) {
	env, _ := endpointCertHarness(t)
	name := filepath.Join(env.nginx.root, "tompanel-acme-webroot.conf")
	if err := os.WriteFile(name, []byte("# customer managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureACMEWebroot(context.Background(), "panel.example.com", *env); err == nil {
		t.Fatal("replaced an unmanaged acme webroot config")
	}
	content, _ := os.ReadFile(name)
	if string(content) != "# customer managed\n" {
		t.Fatalf("unmanaged config was modified: %s", content)
	}
	// A managed replacement that fails nginx -t must roll back to the old body.
	if err := os.WriteFile(name, []byte("# Managed by TomPanel: acme-webroot\nold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := &endpointCertRecorder{failNginxTest: true}
	env.nginx.run = recorder.run
	if err := ensureACMEWebroot(context.Background(), "panel.example.com", *env); err == nil {
		t.Fatal("failing nginx -t accepted")
	}
	content, _ = os.ReadFile(name)
	if !strings.HasPrefix(string(content), "# Managed by TomPanel: acme-webroot\nold\n") {
		t.Fatalf("rollback did not restore the previous config: %s", content)
	}
}

func TestMirrorEndpointCertificateConfinesAndSetsPermissions(t *testing.T) {
	base := t.TempDir()
	siteID := panelEndpointSiteID
	original := certificateRoot
	certificateRoot = filepath.Join(base, "certificates")
	t.Cleanup(func() { certificateRoot = original })
	sourceDir := filepath.Join(certificateRoot, siteID)
	if err := os.MkdirAll(sourceDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "fullchain.pem"), []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "privkey.pem"), []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The destination constant is /etc/tompanel/endpoint on real hosts; the
	// mirror reads it from the same constant, so point it at the fixture too.
	previousEndpointDir := endpointCertDir
	endpointCertDir = filepath.Join(base, "endpoint")
	t.Cleanup(func() { endpointCertDir = previousEndpointDir })

	result, err := mirrorEndpointCertificate(siteID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificatePath != filepath.Join(base, "endpoint", "fullchain.pem") {
		t.Fatalf("result path: %s", result.CertificatePath)
	}
	fullchain, err := os.ReadFile(filepath.Join(base, "endpoint", "fullchain.pem"))
	if err != nil || string(fullchain) != "CERT" {
		t.Fatalf("certificate not mirrored: %q %v", fullchain, err)
	}
	keyInfo, err := os.Stat(filepath.Join(base, "endpoint", "privkey.pem"))
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions: %v %v", keyInfo.Mode().Perm(), err)
	}
	for _, leftover := range []string{".fullchain.candidate", ".privkey.candidate"} {
		if _, err := os.Stat(filepath.Join(base, "endpoint", leftover)); !os.IsNotExist(err) {
			t.Fatalf("candidate %s leaked", leftover)
		}
	}
	// A site with no activated certificate must fail, not mirror empty files.
	if _, err := mirrorEndpointCertificate(strings.Repeat("a", 32)); err == nil {
		t.Fatal("mirrored a site with no activated certificate")
	}
}
