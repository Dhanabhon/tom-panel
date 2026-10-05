package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

const (
	legoPath     = "/usr/local/bin/lego"
	acmeRootPath = "/var/lib/tompanel/acme"
)

// certificateRoot holds every activated site certificate; a variable so
// tests can point it at a fixture.
var certificateRoot = "/etc/tompanel/certificates"

type certificateIssueInput struct {
	SiteID    string   `json:"site_id"`
	Hostnames []string `json:"hostnames"`
	Challenge string   `json:"challenge"`
	Email     string   `json:"email"`
	APIToken  string   `json:"api_token,omitempty"`
}

type certificateIssueResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	NotBefore       int64  `json:"not_before"`
	NotAfter        int64  `json:"not_after"`
}

type certificateActivateInput struct {
	SiteID          string `json:"site_id"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type certificateActivateResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

func buildLegoCommand(input certificateIssueInput) ([]string, []string, error) {
	if !validSiteID(input.SiteID) || input.Email == "" || len(input.Hostnames) == 0 || len(input.Hostnames) > 20 {
		return nil, nil, errors.New("certificate.issue payload is invalid")
	}
	address, err := mail.ParseAddress(input.Email)
	if err != nil || address.Address != input.Email || len(input.Email) > 254 {
		return nil, nil, errors.New("certificate email is invalid")
	}
	seen := make(map[string]bool, len(input.Hostnames))
	args := []string{"run", "--accept-tos", "--email", input.Email, "--path", filepath.Join(acmeRootPath, input.SiteID)}
	for _, hostname := range input.Hostnames {
		wildcard := strings.HasPrefix(hostname, "*.")
		plain := strings.TrimPrefix(hostname, "*.")
		normalized, err := sites.NormalizeHostname(plain)
		if err != nil || normalized != plain || seen[hostname] {
			return nil, nil, errors.New("certificate hostname set is invalid")
		}
		seen[hostname] = true
		if wildcard && input.Challenge == "http-01" {
			return nil, nil, errors.New("HTTP-01 does not support wildcard certificates")
		}
		args = append(args, "--domains", hostname)
	}
	var environment []string
	switch input.Challenge {
	case "http-01":
		args = append(args, "--http", "--http.webroot", filepath.Join(siteRootPath, input.SiteID, "public"))
	case "cloudflare":
		if input.APIToken == "" || len(input.APIToken) > 512 {
			return nil, nil, errors.New("Cloudflare token is invalid")
		}
		args = append(args, "--dns", "cloudflare")
		environment = []string{"CF_DNS_API_TOKEN=" + input.APIToken}
	default:
		return nil, nil, errors.New("certificate challenge is unsupported")
	}
	return args, environment, nil
}

func issueCertificate(ctx context.Context, input certificateIssueInput) (certificateIssueResult, error) {
	args, environment, err := buildLegoCommand(input)
	if err != nil {
		return certificateIssueResult{}, err
	}
	command := exec.CommandContext(ctx, legoPath, args...)
	command.Stdin = nil
	command.Env = append(os.Environ(), environment...)
	if output, err := command.CombinedOutput(); err != nil {
		return certificateIssueResult{}, fmt.Errorf("lego failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	filename := strings.ReplaceAll(input.Hostnames[0], "*", "_")
	base := filepath.Join(acmeRootPath, input.SiteID, "certificates")
	certificatePath := filepath.Join(base, filename+".crt")
	privateKeyPath := filepath.Join(base, filename+".key")
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return certificateIssueResult{}, fmt.Errorf("read issued certificate: %w", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return certificateIssueResult{}, errors.New("lego returned an invalid certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificateIssueResult{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	return certificateIssueResult{
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		NotBefore: certificate.NotBefore.Unix(), NotAfter: certificate.NotAfter.Unix(),
	}, nil
}

func activateCertificate(ctx context.Context, input certificateActivateInput) (certificateActivateResult, error) {
	return activateCertificateWith(ctx, input, acmeRootPath, certificateRoot, runCommand)
}

func activateCertificateWith(ctx context.Context, input certificateActivateInput, sourceRoot, activeRoot string, run func(context.Context, string, ...string) error) (certificateActivateResult, error) {
	if !validSiteID(input.SiteID) || !confinedCertificateSource(sourceRoot, input.SiteID, input.CertificatePath) || !confinedCertificateSource(sourceRoot, input.SiteID, input.PrivateKeyPath) {
		return certificateActivateResult{}, errors.New("certificate.activate payload is invalid")
	}
	certificatePEM, err := os.ReadFile(input.CertificatePath)
	if err != nil {
		return certificateActivateResult{}, err
	}
	privateKeyPEM, err := os.ReadFile(input.PrivateKeyPath)
	if err != nil {
		return certificateActivateResult{}, err
	}
	if _, err := tls.X509KeyPair(certificatePEM, privateKeyPEM); err != nil {
		return certificateActivateResult{}, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	if err := os.MkdirAll(activeRoot, 0o755); err != nil {
		return certificateActivateResult{}, err
	}
	root, err := os.OpenRoot(activeRoot)
	if err != nil {
		return certificateActivateResult{}, err
	}
	defer root.Close()
	if err := root.MkdirAll(input.SiteID, 0o700); err != nil {
		return certificateActivateResult{}, err
	}
	certName, keyName := filepath.Join(input.SiteID, "fullchain.pem"), filepath.Join(input.SiteID, "privkey.pem")
	oldCert, certErr := root.ReadFile(certName)
	oldKey, keyErr := root.ReadFile(keyName)
	if certErr != nil && !errors.Is(certErr, os.ErrNotExist) || keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return certificateActivateResult{}, errors.New("read active certificate pair")
	}
	hadCert, hadKey := certErr == nil, keyErr == nil
	certTemp, keyTemp := certName+".new", keyName+".new"
	if err := root.WriteFile(certTemp, certificatePEM, 0o644); err != nil {
		return certificateActivateResult{}, err
	}
	defer root.Remove(certTemp)
	if err := root.WriteFile(keyTemp, privateKeyPEM, 0o600); err != nil {
		return certificateActivateResult{}, err
	}
	defer root.Remove(keyTemp)
	if err := root.Rename(certTemp, certName); err != nil {
		return certificateActivateResult{}, err
	}
	if err := root.Rename(keyTemp, keyName); err != nil {
		if hadCert {
			_ = root.WriteFile(certName, oldCert, 0o644)
		} else {
			_ = root.Remove(certName)
		}
		return certificateActivateResult{}, err
	}
	restore := func() error {
		var failures []error
		if hadCert {
			failures = append(failures, root.WriteFile(certName, oldCert, 0o644))
		} else if err := root.Remove(certName); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
		if hadKey {
			failures = append(failures, root.WriteFile(keyName, oldKey, 0o600))
		} else if err := root.Remove(keyName); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
		return errors.Join(failures...)
	}
	if err := run(ctx, "/usr/sbin/nginx", "-t"); err != nil {
		return certificateActivateResult{}, errors.Join(err, restore())
	}
	if err := run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		restoreErr := restore()
		reloadErr := run(ctx, "/usr/bin/systemctl", "reload", "nginx")
		return certificateActivateResult{}, errors.Join(err, restoreErr, reloadErr)
	}
	return certificateActivateResult{
		CertificatePath: filepath.Join(activeRoot, certName),
		PrivateKeyPath:  filepath.Join(activeRoot, keyName),
	}, nil
}

func confinedCertificateSource(root, siteID, path string) bool {
	want := filepath.Join(root, siteID, "certificates") + string(os.PathSeparator)
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, want) && (strings.HasSuffix(clean, ".crt") || strings.HasSuffix(clean, ".key"))
}
