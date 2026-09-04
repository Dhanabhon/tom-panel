package domains

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestDeleteDNSRefusesExternalRecord(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	called := false
	service.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not call provider")
	})}
	record := DNSRecord{
		ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SiteID: siteID, Type: "A",
		Hostname: "site.example.com", Content: "192.0.2.10", Provider: "cloudflare",
		ProviderID: "cf-1", Managed: false,
	}
	if err := service.saveDNSRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteDNS(context.Background(), record.ID); !errors.Is(err, ErrExternalResource) {
		t.Fatalf("DeleteDNS() error = %v, want %v", err, ErrExternalResource)
	}
	if called {
		t.Fatal("provider was called for an external record")
	}
}

func TestCheckDNSMatchesOnlyExpectedAddress(t *testing.T) {
	database, _ := openDomainTestStore(t)
	service := NewService(database, nil)
	service.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
	}
	matched, err := service.CheckDNS(context.Background(), DNSInstruction{
		Hostname: "site.example.com", Type: "A", Value: "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("unexpected DNS address was accepted")
	}
}

func TestManualDNSReturnsExactInstructions(t *testing.T) {
	instructions, err := ManualDNS("BÜCHER.example.", "A", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if instructions.Hostname != "xn--bcher-kva.example" || instructions.Type != "A" || instructions.Value != "192.0.2.10" {
		t.Fatalf("ManualDNS() = %#v", instructions)
	}
}

func TestDeleteDNSKeepsOwnershipWhenCloudflareReportsFailure(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	if err := service.ConfigureCloudflare(context.Background(), "zone-12345678", "token"); err != nil {
		t.Fatal(err)
	}
	service.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return cloudflareTestResponse(`{"success":false,"errors":[{"message":"denied"}]}`), nil
	})}
	record := DNSRecord{ID: "cccccccccccccccccccccccccccccccc", SiteID: siteID, Type: "A",
		Hostname: "site.example.com", Content: "192.0.2.10", Provider: "cloudflare", ProviderID: "cf-1", Managed: true}
	if err := service.saveDNSRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteDNS(context.Background(), record.ID); err == nil {
		t.Fatal("Cloudflare success=false was accepted")
	}
	if _, err := service.dnsRecord(context.Background(), record.ID); err != nil {
		t.Fatalf("local ownership record was removed: %v", err)
	}
}

func TestCreateDNSCompensatesWhenPersistenceFails(t *testing.T) {
	database, siteID := openDomainTestStore(t)
	service := NewService(database, nil)
	if err := service.ConfigureCloudflare(context.Background(), "zone-12345678", "token"); err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER reject_dns BEFORE INSERT ON dns_records BEGIN SELECT RAISE(FAIL, 'rejected'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var methods []string
	service.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		if request.Method == http.MethodPost {
			return cloudflareTestResponse(`{"success":true,"result":{"id":"cf-created"}}`), nil
		}
		return cloudflareTestResponse(`{"success":true,"result":{"id":"cf-created"}}`), nil
	})}
	_, err := service.CreateDNS(context.Background(), DNSRecord{
		SiteID: siteID, Type: "A", Hostname: "site.example.com", Content: "192.0.2.10",
	})
	if err == nil {
		t.Fatal("persistence failure was ignored")
	}
	if strings.Join(methods, ",") != "POST,DELETE" {
		t.Fatalf("provider methods = %v, want compensating delete", methods)
	}
}

func cloudflareTestResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
