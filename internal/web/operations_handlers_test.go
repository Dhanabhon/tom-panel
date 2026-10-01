package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/operations"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type operationsHarness struct {
	handler  http.Handler
	session  auth.Session
	services *operations.ServiceManager
	site     sites.Site
}

func newOperationsHarness(t *testing.T) *operationsHarness {
	t.Helper()
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "ops.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	services := operations.NewServiceManager(database, func(_ context.Context, operation string, _, output any) error {
		if operation == "service.inspect" {
			if target, ok := output.(*struct {
				Active bool   `json:"active"`
				State  string `json:"state"`
			}); ok {
				target.Active, target.State = true, "active/running"
			}
		}
		return nil
	})
	logs := operations.NewLogReader(func(_ context.Context, _ string, _, output any) error {
		if target, ok := output.(*struct {
			Lines []string `json:"lines"`
		}); ok {
			target.Lines = []string{"2026-10-01 ERROR password=hunter2 leaked", "2026-10-01 INFO healthy"}
		}
		return nil
	})
	handlers, err := NewOperationsHandlers(authService, repository, database, services, logs, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	return &operationsHarness{
		handler: handlers.Handler(), session: loginDashboardUser(t, authService, recoveryCode),
		services: services, site: site,
	}
}

func (h *operationsHarness) get(path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestServicesPageShowsImpactBeforeRestart(t *testing.T) {
	harness := newOperationsHarness(t)
	recorder := harness.get("/services")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "nginx.service") || !strings.Contains(body, "ops.example.com") {
		t.Fatalf("impact report missing: %s", body)
	}
	if !strings.Contains(body, "data-confirm") {
		t.Fatal("restart confirmation missing")
	}
}

func TestServiceRestartRequiresStepUpAndAllowlist(t *testing.T) {
	harness := newOperationsHarness(t)
	values := "csrf_token=" + harness.session.CSRFToken
	request := httptest.NewRequest(http.MethodPost, "https://panel.example/services/nginx/restart", strings.NewReader(values))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://panel.example")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: harness.session.ID})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: harness.session.CSRFToken})
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("pre-step-up status = %d", recorder.Code)
	}
	if err := harness.services.Restart(context.Background(), "sshd"); err == nil {
		t.Fatal("unmanaged unit accepted")
	}
}

func TestSystemPageShowsMetricsWithoutControls(t *testing.T) {
	harness := newOperationsHarness(t)
	recorder := harness.get("/system")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "CPU") || !strings.Contains(body, "Memory") {
		t.Fatal("metrics missing")
	}
	if strings.Contains(body, "apt upgrade") || strings.Contains(body, "reboot now") {
		t.Fatal("arbitrary update controls rendered")
	}
}

func TestActivityPageSeparatesJobsAndAudit(t *testing.T) {
	harness := newOperationsHarness(t)
	recorder := harness.get("/activity")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "job") && !strings.Contains(recorder.Body.String(), "audit") {
		t.Fatal("activity kinds missing")
	}
}

func TestSiteLogsRedactSecrets(t *testing.T) {
	harness := newOperationsHarness(t)
	recorder := harness.get("/sites/" + harness.site.ID + "/logs?source=app")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "hunter2") {
		t.Fatal("secret rendered in log view")
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatal("redaction marker missing")
	}
}
