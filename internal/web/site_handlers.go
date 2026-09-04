package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type SiteHandlers struct {
	auth        *auth.Service
	repository  *sites.Repository
	runtime     *panelruntime.Service
	provisioner *sites.Provisioner
	jobs        *jobs.Manager
	serverName  string
	templates   *template.Template
	mux         *http.ServeMux
}

type sitesPageData struct {
	Title, ServerName, CurrentNav, CSRFToken string
	Sites                                    []sites.Site
}

type sitePageData struct {
	Title, ServerName, CurrentNav, CSRFToken, JobID string
	Site                                            sites.Site
}

func NewSiteHandlers(authService *auth.Service, repository *sites.Repository, runtimeService *panelruntime.Service, provisioner *sites.Provisioner, manager *jobs.Manager, serverName string) (*SiteHandlers, error) {
	if authService == nil || repository == nil || runtimeService == nil || manager == nil {
		return nil, errors.New("site handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &SiteHandlers{
		auth: authService, repository: repository, runtime: runtimeService, provisioner: provisioner,
		jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	h.mux.Handle("GET /sites", authService.RequireSession(http.HandlerFunc(h.index)))
	h.mux.Handle("GET /sites/new", authService.RequireSession(http.HandlerFunc(h.createPage)))
	h.mux.Handle("POST /sites", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.create))))
	h.mux.Handle("GET /sites/{siteID}", authService.RequireSession(http.HandlerFunc(h.overview)))
	h.mux.Handle("POST /sites/{siteID}/disable", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.disable))))
	h.mux.Handle("POST /sites/{siteID}/enable", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.enable))))
	return h, nil
}

func (h *SiteHandlers) Handler() http.Handler {
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

func (h *SiteHandlers) index(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	items, err := h.repository.List(r.Context())
	if err != nil {
		http.Error(w, "sites could not be loaded", http.StatusInternalServerError)
		return
	}
	h.render(w, "sites", sitesPageData{
		Title: "Sites · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CSRFToken: session.CSRFToken, Sites: items,
	})
}

func (h *SiteHandlers) createPage(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	h.render(w, "site_create", sitesPageData{
		Title: "Create site · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CSRFToken: session.CSRFToken,
	})
}

func (h *SiteHandlers) overview(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	site, err := h.repository.Get(r.Context(), r.PathValue("siteID"))
	if errors.Is(err, sites.ErrSiteNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "site could not be loaded", http.StatusInternalServerError)
		return
	}
	h.render(w, "site_overview", sitePageData{
		Title: site.PrimaryDomain + " · TomPanel", ServerName: h.serverName, CurrentNav: "sites",
		CSRFToken: session.CSRFToken, JobID: r.URL.Query().Get("job"), Site: site,
	})
}

func (h *SiteHandlers) create(w http.ResponseWriter, r *http.Request) {
	if h.provisioner == nil || !parseSmallForm(w, r) {
		if h.provisioner == nil {
			http.Error(w, "site provisioning is unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	httpPort, err := formPort(r, "http_port", 80)
	if err != nil {
		http.Error(w, "HTTP port is invalid", http.StatusBadRequest)
		return
	}
	httpsPort, err := formPort(r, "https_port", 443)
	if err != nil {
		http.Error(w, "HTTPS port is invalid", http.StatusBadRequest)
		return
	}
	input := sites.CreateInput{
		Kind: sites.Kind(r.PostForm.Get("kind")), PrimaryDomain: r.PostForm.Get("primary_domain"),
		HTTPPort: httpPort, HTTPSPort: httpsPort, Public: r.PostForm.Get("public") == "on",
	}
	switch input.Kind {
	case sites.KindPHP:
		input.PHPVersion = r.PostForm.Get("php_version")
	case sites.KindReverseProxy:
		input.ProxyTarget = strings.TrimSpace(r.PostForm.Get("proxy_target"))
	}
	site, err := h.repository.Create(r.Context(), input)
	if err != nil {
		http.Error(w, "site settings are invalid or already in use", http.StatusBadRequest)
		return
	}
	if input.Kind == sites.KindPHP {
		if err := h.runtime.SaveConfig(r.Context(), site.ID, panelruntime.DefaultPHPConfig(input.PHPVersion)); err != nil {
			_ = h.repository.SetState(r.Context(), site.ID, sites.StateFailed)
			http.Error(w, "PHP runtime could not be saved", http.StatusInternalServerError)
			return
		}
	}
	definition, err := h.provisioner.BuildProvisionJob(site.ID)
	if err != nil {
		_ = h.repository.SetState(r.Context(), site.ID, sites.StateFailed)
		http.Error(w, "site job could not be created", http.StatusInternalServerError)
		return
	}
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	jobID, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID, Action: "site.provision.enqueued", Detail: detail,
	})
	if err != nil {
		_ = h.repository.SetState(r.Context(), site.ID, sites.StateFailed)
		http.Error(w, "site job could not be queued", http.StatusInternalServerError)
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/sites/"+site.ID+"?job="+jobID, http.StatusSeeOther)
}

func (h *SiteHandlers) disable(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, false)
}

func (h *SiteHandlers) enable(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, true)
}

func (h *SiteHandlers) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if h.provisioner == nil {
		http.Error(w, "site provisioning is unavailable", http.StatusServiceUnavailable)
		return
	}
	definition, err := h.provisioner.BuildSetEnabledJob(r.PathValue("siteID"), enabled)
	if err != nil {
		http.Error(w, "site state does not allow this operation", http.StatusConflict)
		return
	}
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID  string `json:"site_id"`
		Enabled bool   `json:"enabled"`
	}{SiteID: r.PathValue("siteID"), Enabled: enabled})
	jobID, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID, Action: "site.enabled.changed", Detail: detail,
	})
	if err != nil {
		http.Error(w, "site job could not be queued", http.StatusInternalServerError)
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/sites/"+r.PathValue("siteID")+"?job="+jobID, http.StatusSeeOther)
}

func (h *SiteHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func formPort(r *http.Request, name string, fallback int) (int, error) {
	value := strings.TrimSpace(r.PostForm.Get(name))
	if value == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port is outside 1-65535")
	}
	return port, nil
}
