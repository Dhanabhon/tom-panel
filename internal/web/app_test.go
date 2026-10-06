package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestHealthz(t *testing.T) {
	app := newTestApp(t)

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if body := recorder.Body.String(); body != `{"status":"ok","worker":{"status":"ok"}}` {
		t.Fatalf("body = %q", body)
	}
}

func TestIncompatibleDurableJobDoesNotRemoveHealthOrReadOnlyUI(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO jobs(id, kind, input_json, status, revision, created_at, updated_at) VALUES ('incompatible', 'removed-kind', ?, 'queued', 1, 1, 1)`, []byte(`{}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{StateDir: dir, AgentSocket: filepath.Join(dir, "agent.sock")})
	if err != nil {
		t.Fatalf("application did not start: %v", err)
	}
	defer app.Close()

	for _, check := range []struct {
		path string
		body string
	}{
		{path: "/healthz", body: `"status":"degraded"`},
		{path: "/healthz", body: `"error_code":"incompatible_state"`},
		{path: "/login", body: "Welcome back"},
	} {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, check.path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), check.body) {
			t.Fatalf("GET %s = (%d, %q), want 200 containing %q", check.path, recorder.Code, recorder.Body, check.body)
		}
	}
}

func TestHandlerReturnsNotFoundForUnregisteredRoutes(t *testing.T) {
	app := newTestApp(t)

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestStatePathsUseFixedProductionKeyAndIsolatedDevelopmentKey(t *testing.T) {
	database, key, err := statePaths(config.Config{StateDir: "/var/lib/tompanel"})
	if err != nil {
		t.Fatal(err)
	}
	if database != "/var/lib/tompanel/tompanel.db" || key != "/etc/tompanel/master.key" {
		t.Fatalf("production paths = (%q, %q)", database, key)
	}
	database, key, err = statePaths(config.Config{StateDir: "/tmp/tompanel-test"})
	if err != nil {
		t.Fatal(err)
	}
	if database != "/tmp/tompanel-test/tompanel.db" || key != "/tmp/tompanel-test/master.key" {
		t.Fatalf("development paths = (%q, %q)", database, key)
	}
}

func TestAppIntegratesLoginStaticAndAuthenticatedRoutes(t *testing.T) {
	app := newTestApp(t)
	checks := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/login", wantStatus: http.StatusOK, wantBody: `/static/tompanel-logo.svg`},
		{path: "/setup", wantStatus: http.StatusOK, wantBody: "Secure this server"},
		{path: "/static/app.css", wantStatus: http.StatusOK, wantBody: "--accent"},
		{path: "/static/tompanel-logo.svg", wantStatus: http.StatusOK, wantBody: "<svg"},
		{path: "/static/tompanel-icon.svg", wantStatus: http.StatusOK, wantBody: "<svg"},
		{path: "/jobs/job-id/events", wantStatus: http.StatusUnauthorized, wantBody: "authentication required"},
	}
	for _, check := range checks {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, check.path, nil))
		if recorder.Code != check.wantStatus || !strings.Contains(recorder.Body.String(), check.wantBody) {
			t.Fatalf("GET %s = (%d, %q), want status %d containing %q", check.path, recorder.Code, recorder.Body, check.wantStatus, check.wantBody)
		}
	}
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{StateDir: dir, AgentSocket: filepath.Join(dir, "agent.sock")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	return app
}
