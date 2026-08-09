package web

import (
	"net/http"

	"github.com/Dhanabhon/tom-panel/internal/config"
)

// App is TomPanel's HTTP application.
type App struct {
	cfg config.Config
}

// New builds the HTTP application.
func New(cfg config.Config) (*App, error) {
	return &App{cfg: cfg}, nil
}

// Handler returns the application's HTTP handler.
func (a *App) Handler() http.Handler {
	return http.HandlerFunc(a.serveHTTP)
}

func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	http.NotFound(w, r)
}
