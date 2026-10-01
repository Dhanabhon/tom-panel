package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

type databaseHarness struct {
	handler     http.Handler
	session     auth.Session
	databases   *databases.Service
	authService *auth.Service
	site        sites.Site
	store       *store.Store
	repository  *sites.Repository
}

func newDatabaseHarness(t *testing.T) *databaseHarness {
	t.Helper()
	store, authService, _, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(store)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "db.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := databases.NewService(store, func(context.Context, string, any, any) error { return nil })
	handlers, err := NewDatabaseHandlers(authService, repository, service, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	return &databaseHarness{
		handler: handlers.Handler(), session: loginDashboardUser(t, authService, recoveryCode),
		databases: service, authService: authService, site: site, store: store, repository: repository,
	}
}

func (h *databaseHarness) stepUp(t *testing.T) {
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

func (h *databaseHarness) post(path, values string) *httptest.ResponseRecorder {
	values += "&csrf_token=" + h.session.CSRFToken
	req := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: h.session.CSRFToken})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

func TestDatabasePageRendersEmptyState(t *testing.T) {
	harness := newDatabaseHarness(t)
	req := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+harness.site.ID+"/databases", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Create database") {
		t.Fatal("empty state missing")
	}
}

func TestDatabaseCreateRequiresStepUp(t *testing.T) {
	harness := newDatabaseHarness(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/databases/create", "suffix=shop")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestDatabaseCreateShowsCredentialOnce(t *testing.T) {
	harness := newDatabaseHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/databases/create", "suffix=shop")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "data-one-time-password") {
		t.Fatal("credential reveal missing")
	}
	if strings.Count(body, "tp_"+harness.site.ID[:16]) < 1 {
		t.Fatal("derived username missing")
	}
	// A second render of the same page must not show the credential again.
	req := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+harness.site.ID+"/databases", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	second := httptest.NewRecorder()
	harness.handler.ServeHTTP(second, req)
	if strings.Contains(second.Body.String(), "data-one-time-password") {
		t.Fatal("credential persisted into the ordinary page")
	}
}

func TestDatabaseRotationFailureKeepsOldCredentialMessage(t *testing.T) {
	harness := newDatabaseHarness(t)
	harness.stepUp(t)
	if _, _, err := harness.databases.Create(context.Background(), harness.site.ID, "shop"); err != nil {
		t.Fatal(err)
	}
	failing := databases.NewService(harness.store, func(context.Context, string, any, any) error {
		return context.DeadlineExceeded
	})
	failingHandlers, err := NewDatabaseHandlers(harness.authService, harness.repository, failing, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	values := "suffix=shop&csrf_token=" + harness.session.CSRFToken
	request := httptest.NewRequest(http.MethodPost, "https://panel.example/sites/"+harness.site.ID+"/databases/rotate", strings.NewReader(values))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://panel.example")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: harness.session.CSRFToken})
	recorder := httptest.NewRecorder()
	failingHandlers.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "previous credential still works") {
		t.Fatal("rotation failure message missing")
	}
}

func TestPHPMyAdminConfigurePrivateShowsNoBasicAuth(t *testing.T) {
	harness := newDatabaseHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/databases/phpmyadmin", "mode=private")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	endpoint, err := harness.databases.Endpoint(context.Background(), harness.site.ID)
	if err != nil || endpoint.Mode != databases.ModePrivate {
		t.Fatalf("endpoint: %+v %v", endpoint, err)
	}
}

func TestPHPMyAdminPublicShowsBasicAuthOnce(t *testing.T) {
	harness := newDatabaseHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/databases/phpmyadmin", "mode=public_subdomain&hostname=db.example.com")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	if !strings.Contains(recorder.Body.String(), "Basic Auth password") {
		t.Fatal("basic auth reveal missing")
	}
}
