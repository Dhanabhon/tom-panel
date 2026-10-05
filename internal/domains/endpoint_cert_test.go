package domains

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

const endpointTestMasterKey = "0123456789abcdef0123456789abcdef"

func endpointCertService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte(endpointTestMasterKey), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "state.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(database, nil)
}

type endpointCallCapture struct {
	operation string
	payload   map[string]any
}

func captureEndpointCalls(service *Service) *[]endpointCallCapture {
	calls := &[]endpointCallCapture{}
	service.agentCall = func(ctx context.Context, operation string, input, output any) error {
		encoded, _ := json.Marshal(input)
		var decoded map[string]any
		_ = json.Unmarshal(encoded, &decoded)
		*calls = append(*calls, endpointCallCapture{operation: operation, payload: decoded})
		return nil
	}
	return calls
}

func TestEndpointCertificatePicksDNS01WhenCloudflareConfigured(t *testing.T) {
	service := endpointCertService(t)
	if err := service.ConfigureCloudflare(context.Background(), "zone-1234567890", "cloudflare-api-token-12345"); err != nil {
		t.Fatal(err)
	}
	calls := captureEndpointCalls(service)
	if err := service.IssueEndpointCertificate(context.Background(), "Panel.Example.com", "tom@example.com"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0].operation != "endpoint.issue_certificate" {
		t.Fatalf("calls: %+v", *calls)
	}
	payload := (*calls)[0].payload
	if payload["challenge"] != "dns-01" {
		t.Fatalf("challenge = %v, want dns-01", payload["challenge"])
	}
	if payload["hostname"] != "panel.example.com" {
		t.Fatalf("hostname not normalized: %v", payload["hostname"])
	}
	if payload["api_token"] != "cloudflare-api-token-12345" {
		t.Fatalf("token missing from protected payload: %v", payload["api_token"])
	}
}

func TestEndpointCertificateFallsBackToHTTP01(t *testing.T) {
	service := endpointCertService(t)
	calls := captureEndpointCalls(service)
	if err := service.IssueEndpointCertificate(context.Background(), "panel.example.com", "tom@example.com"); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].payload["challenge"] != "http-01" {
		t.Fatalf("challenge = %v, want http-01", (*calls)[0].payload["challenge"])
	}
	if token, ok := (*calls)[0].payload["api_token"]; ok && token != "" {
		t.Fatalf("token present without cloudflare: %v", token)
	}
}

func TestEndpointCertificateRejectsBadInput(t *testing.T) {
	service := endpointCertService(t)
	calls := captureEndpointCalls(service)
	for _, attempt := range []struct{ hostname, email string }{
		{"not a hostname", "tom@example.com"},
		{"panel.example.com", "not-an-email"},
		{"panel.example.com", ""},
	} {
		if err := service.IssueEndpointCertificate(context.Background(), attempt.hostname, attempt.email); err == nil {
			t.Fatalf("accepted %+v", attempt)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("invalid input reached the agent: %+v", *calls)
	}
}

func TestCloudflareConfiguredReflectsStore(t *testing.T) {
	service := endpointCertService(t)
	if service.CloudflareConfigured(context.Background()) {
		t.Fatal("cloudflare reported configured without storage")
	}
	if err := service.ConfigureCloudflare(context.Background(), "zone-1234567890", "cloudflare-api-token-12345"); err != nil {
		t.Fatal(err)
	}
	if !service.CloudflareConfigured(context.Background()) {
		t.Fatal("cloudflare configuration not detected")
	}
}
