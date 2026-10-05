package web

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/apps"
	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/domains"
	"github.com/Dhanabhon/tom-panel/internal/files"
	"github.com/Dhanabhon/tom-panel/internal/integrations"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/operations"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
	webassets "github.com/Dhanabhon/tom-panel/web"
)

// App is TomPanel's HTTP application.
type App struct {
	cfg     config.Config
	handler http.Handler
	jobs    *jobs.Manager
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
	repository := sites.NewRepository(database)
	runtimeService := panelruntime.NewService(database)
	domainService := domains.NewService(database, agent)
	provisioner := sites.NewProvisioner(repository, runtimeService, agent, func(site sites.Site) ([]byte, error) {
		return domains.RenderNginx(site, []domains.Hostname{domains.Hostname(site.PrimaryDomain)})
	})
	if err := registerDemoJob(manager, agent); err != nil {
		return nil, err
	}
	if err := provisioner.Register(manager); err != nil {
		return nil, err
	}
	if err := manager.ResumeIncomplete(context.Background()); err != nil {
		return nil, err
	}

	dashboard, err := NewDashboardHandlers(service, manager, database, serverName())
	if err != nil {
		return nil, err
	}
	authHandlers := NewAuthHandlers(service).Handler()
	jobRoutes := NewJobsHandlers(database, service, manager)
	jobHandlers := jobRoutes.Handler()
	domainRoutes, err := NewDomainHandlers(service, domainService, serverName())
	if err != nil {
		return nil, err
	}
	runtimeRoutes, err := NewRuntimeHandlers(service, runtimeService, serverName())
	if err != nil {
		return nil, err
	}
	databaseService := databases.NewService(database, agent.Call)
	wordPressProvisioner := apps.NewWordPressProvisioner(database, repository, agent.Call)
	wordPressProvisioner.SetDatabaseProvider(databaseService)
	databaseService.SetAppConfigUpdater(wordPressProvisioner.UpdateDBConfig)
	if err := wordPressProvisioner.Register(manager); err != nil {
		return nil, err
	}
	laravelProvisioner := apps.NewLaravelProvisioner(database, repository, agent.Call)
	laravelProvisioner.SetDatabaseProvider(databaseService)
	if err := laravelProvisioner.Register(manager); err != nil {
		return nil, err
	}
	siteRoutes, err := NewSiteHandlers(service, repository, runtimeService, provisioner, manager, serverName())
	if err != nil {
		return nil, err
	}
	siteRoutes.SetApplicationProviders(wordPressProvisioner, laravelProvisioner)
	fileService := files.NewService(files.DefaultLimits(), files.SiteRootResolver("/srv/tompanel/sites"))
	accessService := files.NewAccessService(database, agent.Call)
	fileRoutes, err := NewFileHandlers(service, repository, fileService, accessService, serverName())
	if err != nil {
		return nil, err
	}
	databaseRoutes, err := NewDatabaseHandlers(service, repository, databaseService, serverName())
	if err != nil {
		return nil, err
	}
	wordPressRoutes, err := NewWordPressHandlers(service, repository, wordPressProvisioner, databaseService, manager, serverName())
	if err != nil {
		return nil, err
	}
	laravelRoutes, err := NewLaravelHandlers(service, repository, laravelProvisioner, databaseService, manager, serverName())
	if err != nil {
		return nil, err
	}
	backupService := backups.NewService(database, agent.Call)
	deleteProvisioner := sites.NewDeleteProvisioner(database, repository, agent.Call, domainService)
	deleteProvisioner.SetBackupFinalizer(func(ctx context.Context, siteID string) error {
		_, _, err := backupService.Create(ctx, siteID, string(backups.KindFinal))
		return err
	})
	if err := deleteProvisioner.Register(manager); err != nil {
		return nil, err
	}
	backupRoutes, err := NewBackupHandlers(service, repository, backupService, deleteProvisioner, manager, serverName())
	if err != nil {
		return nil, err
	}
	operationsService := operations.NewServiceManager(database, agent.Call)
	operationsLogs := operations.NewLogReader(agent.Call)
	operationsRoutes, err := NewOperationsHandlers(service, repository, database, operationsService, operationsLogs, manager, serverName())
	if err != nil {
		return nil, err
	}
	integrationService := integrations.NewService(database, domainService, agent.Call)
	backupService.SetRemoteProvider(func(ctx context.Context) (backups.RemoteSettings, bool) {
		settings, ok, err := integrationService.S3(ctx)
		if err != nil {
			return backups.RemoteSettings{}, false
		}
		return settings, ok
	})
	endpointChanger := operations.NewEndpointChanger(database, agent.Call)
	if err := endpointChanger.Register(manager); err != nil {
		return nil, err
	}
	settingsRoutes, err := NewSettingsHandlers(service, integrationService, endpointChanger, manager, serverName())
	if err != nil {
		return nil, err
	}
	releaseKey, err := pinnedReleaseKey()
	if err != nil {
		return nil, err
	}
	updater := operations.NewUpdater(database, agent.Call, releaseKey)
	if err := updater.Register(manager); err != nil {
		return nil, err
	}
	updateRoutes, err := NewUpdateHandlers(service, updater, manager)
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(webassets.FS, "static")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", serveHealth(manager))
	mux.HandleFunc("/healthz", http.NotFound)
	for _, pattern := range []string{"POST /setup", "POST /login", "POST /login/totp", "POST /logout", "POST /step-up"} {
		mux.Handle(pattern, authHandlers)
	}
	mux.Handle("POST /jobs/demo", jobHandlers)
	mux.Handle("POST /jobs/{jobID}/cancel", jobHandlers)
	mux.Handle("POST /jobs/{jobID}/retry", jobHandlers)
	mux.Handle("GET /jobs/{jobID}/events", jobHandlers)
	mux.Handle("GET /domains", domainRoutes.Handler())
	mux.Handle("GET /sites", siteRoutes.Handler())
	mux.Handle("GET /sites/new", siteRoutes.Handler())
	mux.Handle("POST /sites", siteRoutes.Handler())
	mux.Handle("GET /sites/{siteID}", siteRoutes.Handler())
	mux.Handle("GET /sites/{siteID}/applications", siteRoutes.Handler())
	mux.Handle("POST /sites/{siteID}/disable", siteRoutes.Handler())
	mux.Handle("POST /sites/{siteID}/enable", siteRoutes.Handler())
	mux.Handle("GET /sites/{siteID}/runtime", runtimeRoutes.Handler())
	for _, pattern := range []string{
		"GET /sites/{siteID}/files", "GET /sites/{siteID}/files/list", "GET /sites/{siteID}/files/download",
		"POST /sites/{siteID}/files/create", "POST /sites/{siteID}/files/save", "POST /sites/{siteID}/files/upload",
		"POST /sites/{siteID}/files/rename", "POST /sites/{siteID}/files/copy", "POST /sites/{siteID}/files/trash",
		"POST /sites/{siteID}/files/trash/restore", "POST /sites/{siteID}/files/archive", "POST /sites/{siteID}/files/extract",
		"POST /sites/{siteID}/access/sftp/enable", "POST /sites/{siteID}/access/sftp/disable",
		"POST /sites/{siteID}/access/sftp/password", "POST /sites/{siteID}/access/sftp/keys/add", "POST /sites/{siteID}/access/sftp/keys/remove",
	} {
		mux.Handle(pattern, fileRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /sites/{siteID}/databases",
		"POST /sites/{siteID}/databases/create", "POST /sites/{siteID}/databases/rotate",
		"POST /sites/{siteID}/databases/delete", "POST /sites/{siteID}/databases/backup",
		"POST /sites/{siteID}/databases/restore", "POST /sites/{siteID}/databases/phpmyadmin",
		"POST /sites/{siteID}/databases/phpmyadmin/disable",
	} {
		mux.Handle(pattern, databaseRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /sites/{siteID}/wordpress",
		"POST /sites/{siteID}/wordpress/install", "POST /sites/{siteID}/wordpress/update",
		"POST /sites/{siteID}/wordpress/policy", "POST /sites/{siteID}/wordpress/cron",
		"POST /sites/{siteID}/wordpress/cache/clear", "POST /sites/{siteID}/wordpress/redis",
	} {
		mux.Handle(pattern, wordPressRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /sites/{siteID}/laravel",
		"POST /sites/{siteID}/laravel/install", "POST /sites/{siteID}/laravel/deploy",
		"POST /sites/{siteID}/laravel/workers",
	} {
		mux.Handle(pattern, laravelRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /sites/{siteID}/backups", "POST /sites/{siteID}/backups/create",
		"POST /sites/{siteID}/backups/restore", "POST /sites/{siteID}/backups/delete",
		"POST /sites/{siteID}/delete",
	} {
		mux.Handle(pattern, backupRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /services", "POST /services/{key}/restart",
		"GET /activity", "GET /system", "GET /sites/{siteID}/logs",
	} {
		mux.Handle(pattern, operationsRoutes.Handler())
	}
	for _, pattern := range []string{
		"GET /settings", "POST /settings/cloudflare", "POST /settings/s3", "POST /settings/smtp",
		"POST /settings/endpoint", "POST /settings/cloudflare/test",
		"POST /settings/s3/test", "POST /settings/smtp/test",
	} {
		mux.Handle(pattern, settingsRoutes.Handler())
	}
	for _, pattern := range []string{
		"POST /updates/tompanel", "POST /updates/packages", "POST /updates/tools",
	} {
		mux.Handle(pattern, updateRoutes.Handler())
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", securityHeaders(http.FileServerFS(staticFS))))
	mux.Handle("/", dashboard.Handler())
	if err := manager.Start(context.Background()); err != nil {
		return nil, err
	}
	return &App{cfg: cfg, handler: mux, jobs: manager}, nil
}

// Handler returns the application's HTTP handler.
func (a *App) Handler() http.Handler { return a.handler }

// Close stops the background job worker.
func (a *App) Close() {
	if a.jobs != nil {
		a.jobs.Stop()
	}
}

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
			{Key: "inspect-agent", Reconcile: safeDemoRetry, Run: func(ctx context.Context) (json.RawMessage, error) {
				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				var result json.RawMessage
				if err := agent.Call(ctx, "system.inspect", struct{}{}, &result); err != nil {
					return nil, err
				}
				return result, nil
			}},
			{Key: "run-demo", Reconcile: safeDemoRetry, Run: func(ctx context.Context) (json.RawMessage, error) {
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

func safeDemoRetry(context.Context) (jobs.Reconciliation, error) {
	return jobs.Reconciliation{Outcome: jobs.ReconcileRetry}, nil
}

func serveHealth(manager *jobs.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		worker := manager.WorkerHealth()
		status := "ok"
		if worker.Status != "ok" {
			status = "degraded"
		}
		payload, _ := json.Marshal(struct {
			Status string            `json:"status"`
			Worker jobs.WorkerHealth `json:"worker"`
		}{Status: status, Worker: worker})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}
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

// pinnedReleaseKey reads the Ed25519 release verification key. Updates stay
// disabled until the operator installs the published key.
func pinnedReleaseKey() (ed25519.PublicKey, error) {
	encoded := strings.TrimSpace(os.Getenv("TOMPANEL_RELEASE_KEY"))
	if encoded == "" {
		return ed25519.PublicKey{}, nil
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("release key is malformed")
	}
	return ed25519.PublicKey(decoded), nil
}
