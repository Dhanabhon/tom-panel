package domains

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func openDomainTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	site, err := sites.NewRepository(database).Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "site.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return database, site.ID
}

func TestRenewFailureKeepsValidCertificate(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	service.now = func() time.Time { return time.Unix(2_000_000, 0).UTC() }
	service.agentCall = func(context.Context, string, any, any) error {
		return errors.New("ACME unavailable")
	}
	original := Certificate{
		ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SiteID: siteID,
		Hostnames: []string{"site.example.com"}, Challenge: ChallengeHTTP01,
		CertificatePath: "/etc/tompanel/certificates/old/fullchain.pem",
		PrivateKeyPath:  "/etc/tompanel/certificates/old/privkey.pem",
		State:           CertificateActive, NotAfter: service.now().Add(24 * time.Hour),
	}
	if err := service.saveCertificate(context.Background(), original); err != nil {
		t.Fatal(err)
	}

	if err := service.RenewDue(context.Background(), 48*time.Hour); err == nil {
		t.Fatal("renewal failure was ignored")
	}
	got, err := service.Certificate(context.Background(), original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertificatePath != original.CertificatePath || got.PrivateKeyPath != original.PrivateKeyPath || !got.NotAfter.Equal(original.NotAfter) {
		t.Fatalf("renewal failure replaced valid material: %#v", got)
	}
	if got.State != CertificateRenewalFailed {
		t.Fatalf("certificate state = %q, want %q", got.State, CertificateRenewalFailed)
	}
}

func TestIssueCertificateSendsExactNormalizedHostnameSet(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	var issued certificateIssueInput
	var operations []string
	service.agentCall = func(_ context.Context, operation string, input, output any) error {
		operations = append(operations, operation)
		switch operation {
		case "certificate.issue":
			encoded, _ := json.Marshal(input)
			if err := json.Unmarshal(encoded, &issued); err != nil {
				t.Fatal(err)
			}
			response := output.(*certificateIssueResult)
			*response = certificateIssueResult{
				CertificatePath: "/staging/fullchain.pem", PrivateKeyPath: "/staging/privkey.pem",
				NotBefore: 1_900_000, NotAfter: 9_000_000,
			}
		case "certificate.activate":
			response := output.(*certificateActivateResult)
			*response = certificateActivateResult{CertificatePath: "/active/fullchain.pem", PrivateKeyPath: "/active/privkey.pem"}
		default:
			t.Fatalf("unexpected operation %q", operation)
		}
		return nil
	}
	_, err := service.IssueCertificate(context.Background(), CertificateRequest{
		SiteID: siteID, Hostnames: []string{"WWW.site.example.com.", "site.example.com", "site.example.com"},
		Challenge: ChallengeHTTP01, Email: "admin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `["site.example.com","www.site.example.com"]`
	got, _ := json.Marshal(issued.Hostnames)
	if string(got) != want {
		t.Fatalf("issued hostnames = %s, want %s", got, want)
	}
	if string(mustJSON(operations)) != `["certificate.issue","certificate.activate"]` {
		t.Fatalf("operations = %v", operations)
	}
}

func TestIssueCertificateRecordsPendingOwnershipBeforeAgentCall(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	service.agentCall = func(context.Context, string, any, any) error {
		return errors.New("agent unavailable")
	}
	_, err := service.IssueCertificate(context.Background(), CertificateRequest{
		SiteID: siteID, Hostnames: []string{"site.example.com"}, Challenge: ChallengeHTTP01, Email: "admin@example.com",
	})
	if err == nil {
		t.Fatal("agent failure was ignored")
	}
	var count int
	var state CertificateState
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*), COALESCE(max(state), '') FROM certificates WHERE site_id = ?`, siteID).Scan(&count, &state)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 || state != CertificatePending {
		t.Fatalf("pending ownership count=%d state=%q", count, state)
	}
}

func TestCloudflareCertificateAcceptsNormalizedWildcard(t *testing.T) {
	got, err := normalizeHostnameSet([]string{"*.BÜCHER.example."})
	if err != nil {
		t.Fatal(err)
	}
	if string(mustJSON(got)) != `["*.xn--bcher-kva.example"]` {
		t.Fatalf("wildcard hostname set = %s", mustJSON(got))
	}
}

func TestCloudflareCertificateOmitsZoneIDFromStrictAgentPayload(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	if err := service.ConfigureCloudflare(context.Background(), "zone-12345678", "token"); err != nil {
		t.Fatal(err)
	}
	service.agentCall = func(_ context.Context, operation string, input, output any) error {
		payload, _ := json.Marshal(input)
		if bytes.Contains(payload, []byte("zone_id")) {
			t.Fatalf("strict agent payload contains unsupported zone_id: %s", payload)
		}
		switch operation {
		case "certificate.issue":
			response := output.(*certificateIssueResult)
			*response = certificateIssueResult{CertificatePath: "/staging/cert", PrivateKeyPath: "/staging/key", NotBefore: 1, NotAfter: 2}
		case "certificate.activate":
			response := output.(*certificateActivateResult)
			*response = certificateActivateResult{CertificatePath: "/active/cert", PrivateKeyPath: "/active/key"}
		}
		return nil
	}
	_, err := service.IssueCertificate(context.Background(), CertificateRequest{
		SiteID: siteID, Hostnames: []string{"site.example.com"}, Challenge: ChallengeCloudflare, Email: "admin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
