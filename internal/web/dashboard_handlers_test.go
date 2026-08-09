package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestJobSSERequiresSession(t *testing.T) {
	database, service, manager, _ := newDashboardRuntime(t)
	handler := NewJobsHandlers(database, service, manager).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/jobs/job-id/events", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestJobSSEReloadStartsWithPersistedState(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	id, err := manager.Enqueue(context.Background(), jobs.Definition{Kind: "test", Input: json.RawMessage(`{}`), Steps: []jobs.Step{webTestStep()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, service, recoveryCode)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/jobs/"+id+"/events", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	NewJobsHandlers(database, service, manager).Handler().ServeHTTP(cancelOnFlush{ResponseRecorder: recorder, cancel: cancel}, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, id) || !strings.Contains(body, string(jobs.StatusSucceeded)) {
		t.Fatalf("SSE body = %q", body)
	}
}

func TestDashboardReloadShowsDurableJob(t *testing.T) {
	_, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	id, err := manager.Enqueue(context.Background(), jobs.Definition{Kind: "test", Input: json.RawMessage(`{}`), Steps: []jobs.Step{webTestStep()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, service, recoveryCode)
	handler, err := NewDashboardHandlers(service, manager, "test-vps")
	if err != nil {
		t.Fatal(err)
	}

	for reload := 0; reload < 2; reload++ {
		req := httptest.NewRequest(http.MethodGet, "https://panel.example/", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
		recorder := httptest.NewRecorder()
		handler.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("reload %d status = %d, body = %q", reload, recorder.Code, recorder.Body)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, id) || !strings.Contains(body, string(jobs.StatusSucceeded)) {
			t.Fatalf("reload %d body omitted durable job: %q", reload, body)
		}
	}
}

func TestLoginPageHasPasswordThenTOTPFlow(t *testing.T) {
	_, service, manager, _ := newDashboardRuntime(t)
	handler, err := NewDashboardHandlers(service, manager, "test-vps")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	body := recorder.Body.String()
	for _, required := range []string{`name="username"`, `name="password"`, `name="code"`, `autocomplete="one-time-code"`} {
		if !strings.Contains(body, required) {
			t.Fatalf("login page omitted %q", required)
		}
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestSetupPageNeverRendersFragmentToken(t *testing.T) {
	_, service, manager, _ := newDashboardRuntime(t)
	handler, err := NewDashboardHandlers(service, manager, "test-vps")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/setup?token=must-not-render", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	if strings.Contains(recorder.Body.String(), "must-not-render") {
		t.Fatal("setup token was rendered into HTML")
	}
}

func TestDashboardRedirectsUnauthenticatedBrowserToLogin(t *testing.T) {
	_, service, manager, _ := newDashboardRuntime(t)
	handler, err := NewDashboardHandlers(service, manager, "test-vps")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("response = %d Location %q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestAuditEventRedactsDemoInput(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	session := loginDashboardUser(t, service, recoveryCode)
	manager.Redactor().Register("registered-secret")
	form := strings.NewReader("message=registered-secret&csrf_token=" + session.CSRFToken)
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/jobs/demo", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: session.CSRFToken})
	recorder := httptest.NewRecorder()
	NewJobsHandlers(database, service, manager).Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	var details string
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT detail_json FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&details)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "registered-secret") || !strings.Contains(details, "[REDACTED]") {
		t.Fatalf("audit details = %q", details)
	}
}

func newDashboardRuntime(t *testing.T) (*store.Store, *auth.Service, *jobs.Manager, string) {
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
	service := auth.New(database, func() time.Time { return time.Unix(1_800_000_000, 0) })
	token, err := service.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.CompleteSetup(context.Background(), token, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return database, service, jobs.NewManager(database), enrollment.RecoveryCodes[0]
}

func loginDashboardUser(t *testing.T, service *auth.Service, recoveryCode string) auth.Session {
	t.Helper()
	challenge, err := service.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.VerifyTOTP(context.Background(), challenge, recoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func registerWebTestJob(t *testing.T, manager *jobs.Manager) {
	t.Helper()
	if err := manager.Register("test", func(input json.RawMessage) (jobs.Definition, error) {
		return jobs.Definition{Kind: "test", Input: input, Steps: []jobs.Step{webTestStep()}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register("demo", func(input json.RawMessage) (jobs.Definition, error) {
		return jobs.Definition{Kind: "demo", Input: input, Steps: []jobs.Step{webTestStep()}}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func webTestStep() jobs.Step {
	return jobs.Step{Key: "run", Run: func(context.Context) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	}}
}

type cancelOnFlush struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (r cancelOnFlush) Flush() {
	r.ResponseRecorder.Flush()
	r.cancel()
}
