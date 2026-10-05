package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/integrations"
	"github.com/Dhanabhon/tom-panel/internal/operations"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func newSettingsHarness(t *testing.T) (*settingsHarness, string) {
	t.Helper()
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	integrationService := integrations.NewService(database, nil, func(context.Context, string, any, any) error { return nil })
	endpoint := operations.NewEndpointChanger(database, nil)
	if err := endpoint.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewSettingsHandlers(authService, integrationService, endpoint, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	dir := filepath.Join(t.TempDir(), "state.db")
	return &settingsHarness{
		handler: handlers.Handler(), session: session, authService: authService,
		integrations: integrationService, store: database,
	}, dir
}

type settingsHarness struct {
	handler      http.Handler
	session      auth.Session
	authService  *auth.Service
	integrations *integrations.Service
	store        *store.Store
}

func (h *settingsHarness) stepUp(t *testing.T) {
	t.Helper()
	enrollment, err := h.authService.ResetTOTP(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	h.session = loginDashboardUser(t, h.authService, enrollment.RecoveryCodes[0])
	code := webTOTPCode(enrollment.TOTPSecret, time.Unix(1_800_000_000, 0))
	if err := h.authService.StepUp(context.Background(), h.session.ID, "correct horse battery staple", code); err != nil {
		t.Fatal(err)
	}
}

func (h *settingsHarness) post(path, values string) *httptest.ResponseRecorder {
	values += "&csrf_token=" + h.session.CSRFToken
	request := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://panel.example")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: h.session.CSRFToken})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func (h *settingsHarness) get(t *testing.T, path string) string {
	request := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d", path, recorder.Code)
	}
	return recorder.Body.String()
}

func TestSettingsPageShowsStatesNotSecrets(t *testing.T) {
	harness, databasePath := newSettingsHarness(t)
	body := harness.get(t, "/settings")
	if !strings.Contains(body, "not configured") {
		t.Fatal("empty states missing")
	}
	harness.stepUp(t)
	recorder := harness.post("/settings/s3", "endpoint=&region=auto&bucket=backups&prefix=tompanel&age_recipient=age1qy3pzneqysq5qkgg8n2s9kf0lr9fzl5encl3fjpynjgz6tanfsqzqe29k&access_key=AKIAEXAMPLE123&secret_key=super-secret-key-456")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	body = harness.get(t, "/settings")
	if strings.Contains(body, "super-secret-key-456") || strings.Contains(body, "AKIAEXAMPLE123") {
		t.Fatal("stored secret rendered back")
	}
	if !strings.Contains(body, "configured") {
		t.Fatal("configured state missing")
	}
	var stored strings.Builder
	for _, suffix := range []string{"", "-wal", "-shm"} {
		content, err := os.ReadFile(databasePath + suffix)
		if err == nil {
			stored.Write(content)
		}
	}
	if strings.Contains(stored.String(), "super-secret-key-456") {
		t.Fatal("secret persisted in plaintext")
	}
}

func TestSettingsSaveRequiresStepUp(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	recorder := harness.post("/settings/smtp", "host=smtp.example.com&port=587&from=p@example.com&password=mail-secret-123")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
}

func TestSettingsRejectsInvalidProviders(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/settings/s3", "bucket=b&access_key=a&secret_key=s&age_recipient=bad")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "invalid") {
		t.Fatalf("invalid s3 accepted: status=%d", recorder.Code)
	}
	recorder = harness.post("/settings/smtp", "host=&port=587&from=p@example.com&password=mail-secret-123")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "invalid") {
		t.Fatalf("invalid smtp accepted: status=%d", recorder.Code)
	}
}

func TestEndpointChangeQueuesJobAndRefusesSiteHostname(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	harness.stepUp(t)
	// 4884 is the shipped default: no standard service association, so the
	// panel stays out of automated port sweeps.
	recorder := harness.post("/settings/endpoint", "mode=public&hostname=panel.example.com&port=4884&acme_email=tom@example.com")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	// Cloudflare proxy limits the origin to its supported HTTPS ports.
	recorder = harness.post("/settings/endpoint", "mode=public&hostname=panel.example.com&port=4884&cloudflare_proxy=on")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "refused") {
		t.Fatalf("cloudflare port rule not enforced for 4884: status=%d", recorder.Code)
	}
	recorder = harness.post("/settings/endpoint", "mode=public&hostname=panel.example.com&port=8443&cloudflare_proxy=on&acme_email=tom@example.com")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("cloudflare-compatible port 8443 refused: status=%d", recorder.Code)
	}
	// Port 443 remains a deliberate choice without the proxy.
	recorder = harness.post("/settings/endpoint", "mode=public&hostname=panel.example.com&port=443&acme_email=tom@example.com")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("port 443 should remain allowed: status=%d", recorder.Code)
	}
}

func TestS3SettingsRoundTripForBackups(t *testing.T) {
	harness, _ := newSettingsHarness(t)
	harness.stepUp(t)
	if err := harness.integrations.SaveS3(context.Background(), backups.RemoteSettings{
		Region: "auto", Bucket: "bucket", AccessKeyID: "AKIA1", SecretKey: "very-long-secret-key",
		AgeRecipient: "age1qy3pzneqysq5qkgg8n2s9kf0lr9fzl5encl3fjpynjgz6tanfsqzqe29k", Prefix: "tompanel",
	}); err != nil {
		t.Fatal(err)
	}
	settings, ok, err := harness.integrations.S3(context.Background())
	if err != nil || !ok {
		t.Fatalf("round trip failed: %+v %v", settings, err)
	}
	if settings.SecretKey != "very-long-secret-key" || settings.Bucket != "bucket" {
		t.Fatalf("decrypted settings wrong: %+v", settings)
	}
	if harness.integrations.CloudflareConfigured(context.Background()) {
		t.Fatal("cloudflare reported configured without storage")
	}
}
