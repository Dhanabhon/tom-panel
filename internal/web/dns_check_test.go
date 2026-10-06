package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/auth"
)

func dnsCheckGet(t *testing.T, handler http.Handler, session auth.Session, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestDNSCheckRejectsMissingHostname(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	recorder := dnsCheckGet(t, harness.handler, harness.session, "/api/dns-check")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "hostname is required") {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestDNSCheckRejectsMalformedHostname(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	for _, bad := range []string{"not+valid", "a", "-bad.com"} {
		recorder := dnsCheckGet(t, harness.handler, harness.session, "/api/dns-check?hostname="+bad)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("hostname %q accepted: status=%d", bad, recorder.Code)
		}
	}
}

func TestDNSCheckReturnsStructuredResponse(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	recorder := dnsCheckGet(t, harness.handler, harness.session, "/api/dns-check?hostname=example.com")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response not JSON: %v\nbody=%s", err, recorder.Body.String())
	}
	for _, key := range []string{"hostname", "status", "message", "server_ip"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("response missing %q: %+v", key, payload)
		}
	}
	if payload["status"] != "ok" && payload["status"] != "mismatch" && payload["status"] != "no_dns" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
}
