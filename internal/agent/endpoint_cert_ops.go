package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

// The panel endpoint is not a site, so its certificate reuses the existing
// lego pipeline under a reserved, deterministic site identifier and installs
// into /etc/tompanel/endpoint where the panel's Nginx configuration points.
// This file performs no process execution of its own: issuance and site
// activation go through the existing audited helpers.

// endpointCertDir holds the activated panel certificate pair; a variable so
// tests can point it at a fixture.
var endpointCertDir = "/etc/tompanel/endpoint"

// panelEndpointSiteID is a reserved, deterministic identifier (SHA-256 of
// "tompanel/panel-endpoint", truncated to the 32-hex identifier rule).
var panelEndpointSiteID = func() string {
	sum := sha256.Sum256([]byte("tompanel/panel-endpoint"))
	return hex.EncodeToString(sum[:])[:32]
}()

type endpointIssueInput struct {
	Hostname  string `json:"hostname"`
	Email     string `json:"email"`
	Challenge string `json:"challenge"` // http-01 | dns-01
	APIToken  string `json:"api_token,omitempty"`
}

type endpointIssueResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type endpointCertEnvironment struct {
	webrootNginxConf string
	nginx            nginxEnvironment
	ufwAllow         func(ctx context.Context, port int, comment string) error
}

func defaultEndpointCertEnvironment() endpointCertEnvironment {
	return endpointCertEnvironment{
		webrootNginxConf: "tompanel-acme-webroot.conf",
		nginx:            defaultNginxEnvironment(),
		ufwAllow: func(ctx context.Context, port int, comment string) error {
			return runCommand(ctx, "/usr/sbin/ufw", "allow", strconv.Itoa(port)+"/tcp", "comment", comment)
		},
	}
}

func validateEndpointIssue(input endpointIssueInput) (string, error) {
	normalized, err := sites.NormalizeHostname(input.Hostname)
	if err != nil {
		return "", errors.New("endpoint hostname is invalid")
	}
	if email := strings.TrimSpace(input.Email); email == "" || len(email) > 254 || !strings.Contains(email, "@") {
		return "", errors.New("endpoint ACME email is invalid")
	}
	if input.Challenge != "http-01" && input.Challenge != "dns-01" {
		return "", errors.New("endpoint challenge is unsupported")
	}
	return normalized, nil
}

// issueEndpointCertificate provisions the challenge path, runs the existing
// lego pipeline for the panel hostname, activates the pair through the
// existing site certificate flow, and mirrors it into the endpoint directory.
func issueEndpointCertificate(ctx context.Context, input endpointIssueInput, env endpointCertEnvironment) (endpointIssueResult, error) {
	normalized, err := validateEndpointIssue(input)
	if err != nil {
		return endpointIssueResult{}, err
	}
	if input.Challenge == "http-01" {
		if err := ensureACMEWebroot(ctx, normalized, env); err != nil {
			return endpointIssueResult{}, err
		}
	}
	payload, err := json.Marshal(siteInput{SiteID: panelEndpointSiteID})
	if err != nil {
		return endpointIssueResult{}, err
	}
	if _, err := ensureDirectories(ctx, payload, siteRootPath); err != nil {
		return endpointIssueResult{}, fmt.Errorf("prepare panel webroot: %w", err)
	}
	issued, err := issueCertificate(ctx, certificateIssueInput{
		SiteID:    panelEndpointSiteID,
		Hostnames: []string{normalized},
		Challenge: input.Challenge,
		Email:     strings.TrimSpace(input.Email),
		APIToken:  input.APIToken,
	})
	if err != nil {
		return endpointIssueResult{}, err
	}
	if _, err := activateCertificate(ctx, certificateActivateInput{
		SiteID:          panelEndpointSiteID,
		CertificatePath: issued.CertificatePath,
		PrivateKeyPath:  issued.PrivateKeyPath,
	}); err != nil {
		return endpointIssueResult{}, err
	}
	return mirrorEndpointCertificate(panelEndpointSiteID)
}

// mirrorEndpointCertificate atomically copies the activated site-certificate
// pair into the endpoint directory with private-key-safe permissions.
func mirrorEndpointCertificate(siteID string) (endpointIssueResult, error) {
	sourceDir := filepath.Join(certificateRoot, siteID)
	fullchain, err := os.ReadFile(filepath.Join(sourceDir, "fullchain.pem"))
	if err != nil {
		return endpointIssueResult{}, fmt.Errorf("read activated certificate: %w", err)
	}
	privkey, err := os.ReadFile(filepath.Join(sourceDir, "privkey.pem"))
	if err != nil {
		return endpointIssueResult{}, fmt.Errorf("read activated key: %w", err)
	}
	if err := os.MkdirAll(endpointCertDir, 0o755); err != nil {
		return endpointIssueResult{}, err
	}
	root, err := os.OpenRoot(endpointCertDir)
	if err != nil {
		return endpointIssueResult{}, err
	}
	defer root.Close()
	if err := root.WriteFile(".fullchain.candidate", fullchain, 0o644); err != nil {
		return endpointIssueResult{}, err
	}
	defer root.Remove(".fullchain.candidate")
	if err := root.WriteFile(".privkey.candidate", privkey, 0o600); err != nil {
		return endpointIssueResult{}, err
	}
	defer root.Remove(".privkey.candidate")
	if err := root.Rename(".fullchain.candidate", "fullchain.pem"); err != nil {
		return endpointIssueResult{}, err
	}
	if err := root.Rename(".privkey.candidate", "privkey.pem"); err != nil {
		return endpointIssueResult{}, err
	}
	return endpointIssueResult{
		CertificatePath: filepath.Join(endpointCertDir, "fullchain.pem"),
		PrivateKeyPath:  filepath.Join(endpointCertDir, "privkey.pem"),
	}, nil
}

// ensureACMEWebroot writes the managed port-80 challenge vhost for the panel
// hostname. Same marker, validate-before-activate, and rollback rules as
// every other Nginx configuration.
func ensureACMEWebroot(ctx context.Context, hostname string, env endpointCertEnvironment) error {
	webroot := filepath.Join(siteRootPath, panelEndpointSiteID, "public")
	if err := os.MkdirAll(webroot, 0o750); err != nil {
		return fmt.Errorf("create acme webroot: %w", err)
	}
	if env.ufwAllow != nil {
		if err := env.ufwAllow(ctx, 80, "TomPanel:acme-webroot"); err != nil {
			return fmt.Errorf("allow acme webroot port: %w", err)
		}
	}
	root, err := os.OpenRoot(env.nginx.root)
	if err != nil {
		return fmt.Errorf("open nginx config root: %w", err)
	}
	defer root.Close()
	name := env.webrootNginxConf
	marker := "# Managed by TomPanel: acme-webroot\n"
	content := marker + "server {\n" +
		"    listen 80;\n" +
		"    server_name " + hostname + ";\n" +
		"    location /.well-known/acme-challenge/ { root " + webroot + "; }\n" +
		"}\n"
	if old, readErr := root.ReadFile(name); readErr == nil && !strings.HasPrefix(string(old), marker) {
		return errors.New("refusing to replace an unmanaged acme webroot config")
	}
	old, _ := root.ReadFile(name)
	temporary := "." + name + ".candidate"
	if err := root.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write acme webroot config: %w", err)
	}
	defer root.Remove(temporary)
	if err := root.Rename(temporary, name); err != nil {
		return fmt.Errorf("activate acme webroot config: %w", err)
	}
	restore := func() error {
		if len(old) > 0 {
			return root.WriteFile(name, old, 0o644)
		}
		return root.Remove(name)
	}
	if err := env.nginx.run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		return errors.Join(fmt.Errorf("validate acme webroot config: %w", err), restore())
	}
	if err := env.nginx.run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return errors.Join(fmt.Errorf("reload nginx for acme webroot: %w", err), restore())
	}
	return nil
}
