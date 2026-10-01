package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/apps"
	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type wordpressHarness struct {
	handler     http.Handler
	session     auth.Session
	authService *auth.Service
	provisioner *apps.WordPressProvisioner
	manager     *jobs.Manager
	site        sites.Site
}

func newWordPressHarness(t *testing.T) *wordpressHarness {
	t.Helper()
	store, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(store)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "wp.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	databaseService := databases.NewService(store, func(context.Context, string, any, any) error { return nil })
	provisioner := apps.NewWordPressProvisioner(store, repository, func(context.Context, string, any, any) error { return nil })
	provisioner.SetDatabaseProvider(databaseService)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewWordPressHandlers(authService, repository, provisioner, databaseService, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	return &wordpressHarness{
		handler: handlers.Handler(), session: loginDashboardUser(t, authService, recoveryCode),
		authService: authService, provisioner: provisioner, manager: manager, site: site,
	}
}

func (h *wordpressHarness) stepUp(t *testing.T) {
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

func (h *wordpressHarness) post(path, values string) *httptest.ResponseRecorder {
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

func TestWordPressPageOffersInstallForPHPSites(t *testing.T) {
	harness := newWordPressHarness(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+harness.site.ID+"/wordpress", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Install WordPress") {
		t.Fatal("install form missing for a php site")
	}
}

func TestWordPressInstallRequiresStepUpAndShowsSecretsOnce(t *testing.T) {
	harness := newWordPressHarness(t)
	path := "/sites/" + harness.site.ID + "/wordpress/install"
	if recorder := harness.post(path, "admin_user=tom&admin_email=tom@example.test&title=Site"); recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
	harness.stepUp(t)
	recorder := harness.post(path, "admin_user=tom&admin_email=tom@example.test&title=Site")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	body := recorder.Body.String()
	if strings.Count(body, "data-one-time-password") < 2 {
		t.Fatal("admin and database password reveals missing")
	}
	// Follow-up page render must not leak credentials again.
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+harness.site.ID+"/wordpress", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	second := httptest.NewRecorder()
	harness.handler.ServeHTTP(second, request)
	if strings.Contains(second.Body.String(), "data-one-time-password") {
		t.Fatal("credentials persisted into the ordinary page")
	}
	queued, err := harness.manager.List(context.Background(), 10)
	if err != nil || len(queued) != 1 || queued[0].Kind != apps.WordPressInstallJobKind {
		t.Fatalf("install job not queued: %+v %v", queued, err)
	}
}

func TestWordPressUpdateRequiresInstallation(t *testing.T) {
	harness := newWordPressHarness(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/wordpress/update", "")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "not installed") {
		t.Fatalf("update before install: status=%d", recorder.Code)
	}
}

func TestWordPressStaticSiteSeesNoInstallControls(t *testing.T) {
	store, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(store)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "plain.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	databaseService := databases.NewService(store, nil)
	provisioner := apps.NewWordPressProvisioner(store, repository, nil)
	handlers, err := NewWordPressHandlers(authService, repository, provisioner, databaseService, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+site.ID+"/wordpress", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	handlers.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "Install WordPress") || strings.Contains(body, "Deploy Laravel") {
		t.Fatalf("misleading controls rendered: %s", body)
	}
}
