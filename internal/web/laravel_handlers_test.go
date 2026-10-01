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

type laravelHarness struct {
	handler     http.Handler
	session     auth.Session
	authService *auth.Service
	provisioner *apps.LaravelProvisioner
	manager     *jobs.Manager
	site        sites.Site
}

func newLaravelHarness(t *testing.T) *laravelHarness {
	t.Helper()
	store, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(store)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "app.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	databaseService := databases.NewService(store, func(context.Context, string, any, any) error { return nil })
	provisioner := apps.NewLaravelProvisioner(store, repository, func(context.Context, string, any, any) error { return nil })
	provisioner.SetDatabaseProvider(databaseService)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewLaravelHandlers(authService, repository, provisioner, databaseService, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	return &laravelHarness{
		handler: handlers.Handler(), session: loginDashboardUser(t, authService, recoveryCode),
		authService: authService, provisioner: provisioner, manager: manager, site: site,
	}
}

func (h *laravelHarness) stepUp(t *testing.T) {
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

func (h *laravelHarness) post(path, values string) *httptest.ResponseRecorder {
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

func TestLaravelInstallRequiresStepUpAndRejectsLocalTransport(t *testing.T) {
	harness := newLaravelHarness(t)
	path := "/sites/" + harness.site.ID + "/laravel/install"
	if recorder := harness.post(path, "repository=https://github.com/tom/app.git&branch=main"); recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
	harness.stepUp(t)
	recorder := harness.post(path, "repository=file:///tmp/repo&branch=main")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "HTTPS or SSH") {
		t.Fatalf("local transport accepted: status=%d", recorder.Code)
	}
}

func TestLaravelInstallShowsDatabaseSecretOnce(t *testing.T) {
	harness := newLaravelHarness(t)
	harness.stepUp(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/laravel/install", "repository=https://github.com/tom/app.git&branch=main")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	if !strings.Contains(recorder.Body.String(), "data-one-time-password") {
		t.Fatal("database secret reveal missing")
	}
	queued, err := harness.manager.List(context.Background(), 10)
	if err != nil || len(queued) != 1 || queued[0].Kind != apps.LaravelInstallJobKind {
		t.Fatalf("install job not queued: %+v %v", queued, err)
	}
}

func TestLaravelDeployRequiresConfirmationAndInstallation(t *testing.T) {
	harness := newLaravelHarness(t)
	recorder := harness.post("/sites/"+harness.site.ID+"/laravel/deploy", "")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "confirmation checkbox") {
		t.Fatalf("unconfirmed deploy accepted: status=%d", recorder.Code)
	}
	recorder = harness.post("/sites/"+harness.site.ID+"/laravel/deploy", "confirmed=on")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "not installed") {
		t.Fatalf("deploy before install accepted: status=%d", recorder.Code)
	}
}

func TestLaravelDeployRunsAfterInstall(t *testing.T) {
	harness := newLaravelHarness(t)
	harness.stepUp(t)
	if _, err := harness.provisioner.PrepareInstall(context.Background(), harness.site.ID, "https://github.com/tom/app.git", "main", false); err != nil {
		t.Fatal(err)
	}
	if err := harness.provisioner.SetLaravelState(context.Background(), harness.site.ID, "active"); err != nil {
		t.Fatal(err)
	}
	recorder := harness.post("/sites/"+harness.site.ID+"/laravel/deploy", "confirmed=on&run_migrations=on")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	queued, err := harness.manager.List(context.Background(), 10)
	if err != nil || len(queued) != 1 || queued[0].Kind != apps.LaravelDeployJobKind {
		t.Fatalf("deploy job not queued: %+v %v", queued, err)
	}
	var hasMigrate, hasActivate bool
	for _, step := range queued[0].Steps {
		if step.Key == "laravel.migrate" {
			hasMigrate = true
		}
		if step.Key == "laravel.activate_release" {
			hasActivate = true
		}
	}
	if !hasMigrate || !hasActivate {
		t.Fatalf("deploy steps missing: %+v", queued[0].Steps)
	}
}

func TestLaravelStaticSiteSeesNoInstallControls(t *testing.T) {
	store, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(store)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "plain2.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	provisioner := apps.NewLaravelProvisioner(store, repository, nil)
	handlers, err := NewLaravelHandlers(authService, repository, provisioner, databases.NewService(store, nil), manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/sites/"+site.ID+"/laravel", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	handlers.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "Install Laravel") || strings.Contains(body, "Deploy new release") {
		t.Fatalf("misleading controls rendered: %s", body)
	}
}
