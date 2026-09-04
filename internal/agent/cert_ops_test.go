package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateIssueRejectsWildcardHTTP(t *testing.T) {
	_, _, err := buildLegoCommand(certificateIssueInput{
		SiteID: "0123456789abcdef0123456789abcdef", Hostnames: []string{"*.example.com"},
		Challenge: "http-01", Email: "admin@example.com",
	})
	if err == nil {
		t.Fatal("HTTP-01 wildcard request accepted")
	}
}

func TestCertificateIssueRejectsDisplayNameEmail(t *testing.T) {
	_, _, err := buildLegoCommand(certificateIssueInput{
		SiteID: "0123456789abcdef0123456789abcdef", Hostnames: []string{"example.com"},
		Challenge: "http-01", Email: "Admin <admin@example.com>",
	})
	if err == nil {
		t.Fatal("display-name email accepted")
	}
}

func TestCertificateActivationRestoresPreviousPairWhenNginxRejects(t *testing.T) {
	const siteID = "0123456789abcdef0123456789abcdef"
	sourceRoot, activeRoot := t.TempDir(), t.TempDir()
	newCert, newKey := testCertificatePair(t, 2)
	oldCert, oldKey := testCertificatePair(t, 1)
	sourceDir := filepath.Join(sourceRoot, siteID, "certificates")
	activeDir := filepath.Join(activeRoot, siteID)
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(activeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	newCertPath, newKeyPath := filepath.Join(sourceDir, "new.crt"), filepath.Join(sourceDir, "new.key")
	if err := os.WriteFile(newCertPath, newCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newKeyPath, newKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, "fullchain.pem"), oldCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, "privkey.pem"), oldKey, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := activateCertificateWith(context.Background(), certificateActivateInput{
		SiteID: siteID, CertificatePath: newCertPath, PrivateKeyPath: newKeyPath,
	}, sourceRoot, activeRoot, func(context.Context, string, ...string) error {
		return errors.New("nginx rejected certificate")
	})
	if err == nil {
		t.Fatal("nginx validation failure was ignored")
	}
	gotCert, _ := os.ReadFile(filepath.Join(activeDir, "fullchain.pem"))
	gotKey, _ := os.ReadFile(filepath.Join(activeDir, "privkey.pem"))
	if string(gotCert) != string(oldCert) || string(gotKey) != string(oldKey) {
		t.Fatal("previous certificate pair was not restored")
	}
}

func testCertificatePair(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Unix(1_000_000, 0), NotAfter: time.Unix(9_000_000, 0),
		DNSNames: []string{"example.com"}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}

func TestCertificateIssueKeepsCloudflareTokenOutOfArguments(t *testing.T) {
	const token = "cloudflare-secret-token"
	args, environment, err := buildLegoCommand(certificateIssueInput{
		SiteID:    "0123456789abcdef0123456789abcdef",
		Hostnames: []string{"example.com", "*.example.com"}, Challenge: "cloudflare",
		Email: "admin@example.com", APIToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), token) {
		t.Fatal("Cloudflare token appeared in command arguments")
	}
	if len(environment) != 1 || environment[0] != "CF_DNS_API_TOKEN="+token {
		t.Fatalf("environment = %#v", environment)
	}
	if got := strings.Join(args, " "); !strings.Contains(got, "--dns cloudflare") || !strings.Contains(got, "--domains *.example.com") {
		t.Fatalf("lego arguments = %q", got)
	}
}
