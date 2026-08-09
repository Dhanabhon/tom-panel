package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/config"
)

func TestHealthz(t *testing.T) {
	app := newTestApp(t)

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if body := recorder.Body.String(); body != `{"status":"ok"}` {
		t.Fatalf("body = %q", body)
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
		{path: "/login", wantStatus: http.StatusOK, wantBody: "Welcome back"},
		{path: "/setup", wantStatus: http.StatusOK, wantBody: "Secure this server"},
		{path: "/static/app.css", wantStatus: http.StatusOK, wantBody: "--accent"},
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
