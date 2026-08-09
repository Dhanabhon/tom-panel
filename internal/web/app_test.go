package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/config"
)

func TestHealthz(t *testing.T) {
	app, err := New(config.Config{})
	if err != nil {
		t.Fatal(err)
	}

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
	app, err := New(config.Config{})
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
