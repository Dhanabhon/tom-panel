package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/apps"
	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

// LaravelHandlers serves the fixed Laravel deployment pipeline of a site.
type LaravelHandlers struct {
	auth        *auth.Service
	repository  *sites.Repository
	provisioner *apps.LaravelProvisioner
	databases   *databases.Service
	jobs        *jobs.Manager
	serverName  string
	templates   *template.Template
	mux         *http.ServeMux
}

type laravelPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, JobID string
	Site                                                        sites.Site
	SiteKind                                                    string
	Installation                                                *apps.LaravelInstallation
	Credentials                                                 *apps.LaravelOneTimeCredentials
	Notice, Warning                                             string
}

// NewLaravelHandlers wires the Laravel routes for one site scope.
func NewLaravelHandlers(authService *auth.Service, repository *sites.Repository, provisioner *apps.LaravelProvisioner, databaseService *databases.Service, manager *jobs.Manager, serverName string) (*LaravelHandlers, error) {
	if authService == nil || repository == nil || provisioner == nil || manager == nil {
		return nil, errors.New("laravel handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &LaravelHandlers{
		auth: authService, repository: repository, provisioner: provisioner,
		databases: databaseService, jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	session := authService.RequireSession
	stepUp := func(next http.Handler) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("GET /sites/{siteID}/laravel", session(http.HandlerFunc(h.page)))
	h.mux.Handle("POST /sites/{siteID}/laravel/install", stepUp(http.HandlerFunc(h.install)))
	h.mux.Handle("POST /sites/{siteID}/laravel/deploy", session(authService.RequireCSRF(http.HandlerFunc(h.deploy))))
	h.mux.Handle("POST /sites/{siteID}/laravel/workers", session(authService.RequireCSRF(http.HandlerFunc(h.workers))))
	return h, nil
}

func (h *LaravelHandlers) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setPageSecurityHeaders(w)
		cookie, err := r.Cookie(auth.SessionCookieName)
		if err != nil || !h.auth.SessionValid(r.Context(), cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h.mux.ServeHTTP(w, r)
	})
}

func (h *LaravelHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *LaravelHandlers) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
	site, err := h.repository.Get(r.Context(), r.PathValue("siteID"))
	if errors.Is(err, sites.ErrSiteNotFound) {
		http.NotFound(w, r)
		return site, false
	}
	if err != nil {
		http.Error(w, "site could not be loaded", http.StatusInternalServerError)
		return site, false
	}
	return site, true
}

func (h *LaravelHandlers) snapshot(r *http.Request, site sites.Site, credentials *apps.LaravelOneTimeCredentials, notice, warning string) laravelPageData {
	data := laravelPageData{
		Title: site.PrimaryDomain + " · Laravel · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "applications",
		Credentials: credentials, Notice: notice, Warning: warning, JobID: r.URL.Query().Get("job"),
		SiteKind: string(site.Kind),
	}
	if session, ok := auth.CurrentSession(r.Context()); ok {
		data.CSRFToken = session.CSRFToken
	}
	if installation, err := h.provisioner.Installation(r.Context(), site.ID); err == nil {
		data.Installation = &installation
	}
	return data
}

func (h *LaravelHandlers) page(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	h.render(w, "site_laravel", h.snapshot(r, site, nil, strings.TrimSpace(r.URL.Query().Get("notice")), ""))
}

func (h *LaravelHandlers) install(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	repository := strings.TrimSpace(r.PostForm.Get("repository"))
	branch := strings.TrimSpace(r.PostForm.Get("branch"))
	if branch == "" {
		branch = "main"
	}
	nodeBuild := r.PostForm.Get("node_build") == "on"
	credentials, err := h.provisioner.PrepareInstall(r.Context(), site.ID, repository, branch, nodeBuild)
	if err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Laravel could not be prepared: "+describeLaravelError(err)))
		return
	}
	h.audit(r, site.ID, "laravel.prepared", map[string]string{"repository": repository, "branch": branch})
	definition, err := h.provisioner.BuildInstallJob(site.ID)
	if err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Laravel job could not be created: "+describeLaravelError(err)))
		return
	}
	jobID, err := h.enqueueWithAudit(r, definition, "laravel.install.enqueued", site.ID)
	if err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Laravel job could not be queued."))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := h.snapshot(r, site, &credentials, "Copy the database password now. It will not be shown again.", "")
	data.JobID = jobID
	h.render(w, "site_laravel", data)
}

func (h *LaravelHandlers) deploy(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirmed") != "on" {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Deployment requires the confirmation checkbox."))
		return
	}
	runMigrations := r.PostForm.Get("run_migrations") == "on"
	definition, err := h.provisioner.BuildDeployJob(site.ID, runMigrations)
	if err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Deployment job could not be created: "+describeLaravelError(err)))
		return
	}
	jobID, err := h.enqueueWithAudit(r, definition, "laravel.deploy.enqueued", site.ID)
	if err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Deployment job could not be queued."))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/laravel?job="+jobID, http.StatusSeeOther)
}

func (h *LaravelHandlers) workers(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	enabled := r.PostForm.Get("enabled") == "on"
	if err := h.provisioner.SetWorkers(r.Context(), site.ID, enabled); err != nil {
		h.render(w, "site_laravel", h.snapshot(r, site, nil, "", "Workers could not be changed: "+describeLaravelError(err)))
		return
	}
	h.audit(r, site.ID, "laravel.workers.changed", map[string]bool{"enabled": enabled})
	http.Redirect(w, r, "/sites/"+site.ID+"/laravel?notice=Worker+units+updated", http.StatusSeeOther)
}

func (h *LaravelHandlers) enqueueWithAudit(r *http.Request, definition jobs.Definition, action, siteID string) (string, error) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return "", errors.New("authentication required")
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: siteID})
	jobID, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID, Action: action, Detail: detail,
	})
	if err != nil {
		return "", err
	}
	h.jobs.Wake()
	return jobID, nil
}

func (h *LaravelHandlers) audit(r *http.Request, siteID, action string, detail any) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return
	}
	encoded, _ := json.Marshal(detail)
	_ = h.databases.WriteAudit(r.Context(), siteID, databases.AuditEvent{
		AdminID: session.AdminID, Action: action, Detail: encoded,
	})
}

func describeLaravelError(err error) string {
	switch {
	case errors.Is(err, apps.ErrUnsafeGitTransport):
		return "only HTTPS or SSH Git repositories are allowed"
	case errors.Is(err, apps.ErrAlreadyInstalled):
		return "Laravel is already installed for this site"
	case errors.Is(err, apps.ErrInstallationNotFound):
		return "Laravel is not installed yet"
	case errors.Is(err, apps.ErrMissingLockfile):
		return "package-lock.json is required for node builds"
	default:
		return "operation failed"
	}
}
