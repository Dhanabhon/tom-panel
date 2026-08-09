package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
	webassets "github.com/Dhanabhon/tom-panel/web"
)

// App is TomPanel's HTTP application.
type App struct {
	cfg     config.Config
	handler http.Handler
}

// New builds the HTTP application.
func New(cfg config.Config) (*App, error) {
	databasePath, keyPath, err := statePaths(cfg)
	if err != nil {
		return nil, err
	}
	database, err := store.Open(context.Background(), databasePath, keyPath)
	if err != nil {
		return nil, err
	}
	service := auth.New(database, time.Now)
	agent := agentapi.NewClient(cfg.AgentSocket)
	manager := jobs.NewManager(database)
	if err := registerDemoJob(manager, agent); err != nil {
		return nil, err
	}
	if err := manager.ResumeIncomplete(context.Background()); err != nil {
		return nil, err
	}

	dashboard, err := NewDashboardHandlers(service, manager, serverName())
	if err != nil {
		return nil, err
	}
	authHandlers := NewAuthHandlers(service).Handler()
	jobRoutes := NewJobsHandlers(database, service, manager)
	jobHandlers := jobRoutes.Handler()
	staticFS, err := fs.Sub(webassets.FS, "static")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", serveHealth)
	mux.HandleFunc("/healthz", http.NotFound)
	for _, pattern := range []string{"POST /setup", "POST /login", "POST /login/totp", "POST /logout", "POST /step-up"} {
		mux.Handle(pattern, authHandlers)
	}
	mux.Handle("POST /jobs/demo", jobHandlers)
	mux.Handle("POST /jobs/{jobID}/cancel", jobHandlers)
	mux.Handle("GET /jobs/{jobID}/events", jobHandlers)
	mux.Handle("GET /static/", http.StripPrefix("/static/", securityHeaders(http.FileServerFS(staticFS))))
	mux.Handle("/", dashboard.Handler())
	go jobRoutes.runQueued()
	return &App{cfg: cfg, handler: mux}, nil
}

// Handler returns the application's HTTP handler.
func (a *App) Handler() http.Handler { return a.handler }

func statePaths(cfg config.Config) (string, string, error) {
	if cfg.StateDir == "" {
		return "", "", errors.New("state directory is required")
	}
	if filepath.Clean(cfg.StateDir) == "/var/lib/tompanel" {
		return "/var/lib/tompanel/tompanel.db", "/etc/tompanel/master.key", nil
	}
	return filepath.Join(cfg.StateDir, "tompanel.db"), filepath.Join(cfg.StateDir, "master.key"), nil
}

func registerDemoJob(manager *jobs.Manager, agent *agentapi.Client) error {
	return manager.Register("demo", func(input json.RawMessage) (jobs.Definition, error) {
		var request struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(input, &request); err != nil || request.Message == "" {
			return jobs.Definition{}, errors.New("demo input is invalid")
		}
		return jobs.Definition{Kind: "demo", Input: append(json.RawMessage(nil), input...), Steps: []jobs.Step{
			{Key: "inspect-agent", Run: func(ctx context.Context) (json.RawMessage, error) {
				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				var result json.RawMessage
				if err := agent.Call(ctx, "system.inspect", struct{}{}, &result); err != nil {
					return nil, err
				}
				return result, nil
			}},
			{Key: "run-demo", Run: func(ctx context.Context) (json.RawMessage, error) {
				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				var result json.RawMessage
				if err := agent.Call(ctx, "job.demo", request, &result); err != nil {
					return nil, err
				}
				return result, nil
			}},
		}}, nil
	})
}

func serveHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func serverName() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "TomPanel server"
	}
	return name
}
