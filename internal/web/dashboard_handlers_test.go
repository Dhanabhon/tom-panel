package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
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
		if !strings.Contains(body, id) || !strings.Contains(body, string(jobs.StatusSucceeded)) || !strings.Contains(body, `data-job-revision="`) {
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
	for _, required := range []string{`method="post"`, `action="/login"`, `name="username"`, `name="password"`, `name="code"`, `autocomplete="one-time-code"`} {
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
	for _, required := range []string{`method="post"`, `action="/setup"`} {
		if !strings.Contains(recorder.Body.String(), required) {
			t.Fatalf("setup form omitted %q", required)
		}
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

func TestEnqueueRollsBackWhenAuditInsertFails(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	rejectAuditWrites(t, database)
	session := loginDashboardUser(t, service, recoveryCode)
	recorder := postJobForm(t, NewJobsHandlers(database, service, manager).Handler(), session, "/jobs/demo", "message=safe")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	got, err := manager.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("jobs after audit rollback = %#v", got)
	}
}

func TestCancelRollsBackWhenAuditInsertFails(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	def, err := manager.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := manager.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	rejectAuditWrites(t, database)
	session := loginDashboardUser(t, service, recoveryCode)
	recorder := postJobForm(t, NewJobsHandlers(database, service, manager).Handler(), session, "/jobs/"+id+"/cancel", "")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	job, err := manager.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != jobs.StatusQueued {
		t.Fatalf("status after audit rollback = %q", job.Status)
	}
}

func TestSSESkipsEventsNotNewerThanSnapshot(t *testing.T) {
	if sseEventAfter(7, jobs.Event{Revision: 7}) {
		t.Fatal("event at snapshot revision was accepted")
	}
	if sseEventAfter(7, jobs.Event{Revision: 6}) {
		t.Fatal("event older than snapshot was accepted")
	}
	if !sseEventAfter(7, jobs.Event{Revision: 8}) {
		t.Fatal("new event was rejected")
	}
}

func TestOpenSSEClosesAfterSessionRevocation(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	registerWebTestJob(t, manager)
	def, err := manager.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := manager.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, service, recoveryCode)
	routes := NewJobsHandlers(database, service, manager)
	routes.sessionCheckInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/jobs/"+id+"/events", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	writer := newFlushSignalRecorder()
	done := make(chan struct{})
	go func() {
		routes.Handler().ServeHTTP(writer, req)
		close(done)
	}()
	select {
	case <-writer.flushed:
	case <-time.After(time.Second):
		t.Fatal("SSE did not open")
	}
	if err := service.Logout(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE remained open after logout")
	}
}

func TestFailureCodeAndRedactionReachSSEWithoutLeakingDashboard(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	step := jobs.Step{Key: "run", Run: func(context.Context) (json.RawMessage, error) {
		return nil, &agentapi.Error{Code: "operation_not_allowed", Message: "password=correct horse battery staple\nordinary failure"}
	}}
	if err := manager.Register("demo", func(input json.RawMessage) (jobs.Definition, error) {
		return jobs.Definition{Kind: "demo", Input: input, Steps: []jobs.Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := manager.Build("demo", json.RawMessage(`{"message":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := manager.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); !errors.Is(err, jobs.ErrStepFailed) {
		t.Fatalf("run error = %v", err)
	}
	session := loginDashboardUser(t, service, recoveryCode)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/jobs/"+id+"/events", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	NewJobsHandlers(database, service, manager).Handler().ServeHTTP(cancelOnFlush{ResponseRecorder: recorder, cancel: cancel}, req)
	sse := recorder.Body.String()
	if !strings.Contains(sse, `"error_code":"agent_operation_not_allowed"`) || !strings.Contains(sse, "ordinary failure") || strings.Contains(sse, "horse battery staple") {
		t.Fatalf("SSE failure payload = %q", sse)
	}

	dashboard, err := NewDashboardHandlers(service, manager, "test-vps")
	if err != nil {
		t.Fatal(err)
	}
	dashboardRequest := httptest.NewRequest(http.MethodGet, "https://panel.example/?job="+id, nil)
	dashboardRequest.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	dashboardRecorder := httptest.NewRecorder()
	dashboard.Handler().ServeHTTP(dashboardRecorder, dashboardRequest)
	body := dashboardRecorder.Body.String()
	if !strings.Contains(body, "ordinary failure") || strings.Contains(body, "horse battery staple") {
		t.Fatalf("rendered failure state = %q", body)
	}
	if !strings.Contains(body, "/jobs/"+id+"/retry") || strings.Contains(body, "/jobs/"+id+"/cancel") {
		t.Fatalf("failed job controls = %q", body)
	}
}

func TestFailedJobRetryRouteIsAudited(t *testing.T) {
	database, service, manager, recoveryCode := newDashboardRuntime(t)
	step := jobs.Step{Key: "run", Run: func(context.Context) (json.RawMessage, error) {
		return nil, errors.New("failed")
	}}
	if err := manager.Register("test", func(input json.RawMessage) (jobs.Definition, error) {
		return jobs.Definition{Kind: "test", Input: input, Steps: []jobs.Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := manager.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := manager.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); !errors.Is(err, jobs.ErrStepFailed) {
		t.Fatalf("run error = %v", err)
	}
	session := loginDashboardUser(t, service, recoveryCode)
	recorder := postJobForm(t, NewJobsHandlers(database, service, manager).Handler(), session, "/jobs/"+id+"/retry", "")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body)
	}
	job, err := manager.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != jobs.StatusQueued || job.Error != "" || job.ErrorCode != "" {
		t.Fatalf("retried job = %#v", job)
	}
	var action string
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow("SELECT action FROM audit_events WHERE target_id = ? ORDER BY id DESC LIMIT 1", id).Scan(&action)
	}); err != nil {
		t.Fatal(err)
	}
	if action != "job.retry.requested" {
		t.Fatalf("retry audit action = %q", action)
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

func rejectAuditWrites(t *testing.T, database *store.Store) {
	t.Helper()
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, 'audit rejected'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func postJobForm(t *testing.T, handler http.Handler, session auth.Session, path, values string) *httptest.ResponseRecorder {
	t.Helper()
	if values != "" {
		values += "&"
	}
	values += "csrf_token=" + session.CSRFToken
	req := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: session.CSRFToken})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

type cancelOnFlush struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (r cancelOnFlush) Flush() {
	r.ResponseRecorder.Flush()
	r.cancel()
}

type flushSignalRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once    sync.Once
}

func newFlushSignalRecorder() *flushSignalRecorder {
	return &flushSignalRecorder{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{})}
}

func (r *flushSignalRecorder) Flush() {
	r.ResponseRecorder.Flush()
	r.once.Do(func() { close(r.flushed) })
}
