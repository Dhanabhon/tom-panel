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

// WordPressHandlers serves the managed WordPress lifecycle of a site.
type WordPressHandlers struct {
	auth        *auth.Service
	repository  *sites.Repository
	provisioner *apps.WordPressProvisioner
	databases   *databases.Service
	jobs        *jobs.Manager
	serverName  string
	templates   *template.Template
	mux         *http.ServeMux
}

type wordpressPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, JobID string
	Site                                            sites.Site
	SiteKind                                        string
	Installation                                    *apps.Installation
	Credentials                                     *apps.OneTimeInstallCredentials
	Notice, Warning                                 string
}

// NewWordPressHandlers wires the WordPress routes for one site scope.
func NewWordPressHandlers(authService *auth.Service, repository *sites.Repository, provisioner *apps.WordPressProvisioner, databaseService *databases.Service, manager *jobs.Manager, serverName string) (*WordPressHandlers, error) {
	if authService == nil || repository == nil || provisioner == nil || manager == nil {
		return nil, errors.New("wordpress handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &WordPressHandlers{
		auth: authService, repository: repository, provisioner: provisioner, databases: databaseService,
		jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	session := authService.RequireSession
	stepUp := func(next http.Handler) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("GET /sites/{siteID}/wordpress", session(http.HandlerFunc(h.page)))
	h.mux.Handle("POST /sites/{siteID}/wordpress/install", stepUp(http.HandlerFunc(h.install)))
	h.mux.Handle("POST /sites/{siteID}/wordpress/update", session(authService.RequireCSRF(http.HandlerFunc(h.update))))
	h.mux.Handle("POST /sites/{siteID}/wordpress/policy", session(authService.RequireCSRF(http.HandlerFunc(h.policy))))
	h.mux.Handle("POST /sites/{siteID}/wordpress/cron", session(authService.RequireCSRF(http.HandlerFunc(h.cron))))
	h.mux.Handle("POST /sites/{siteID}/wordpress/cache/clear", session(authService.RequireCSRF(http.HandlerFunc(h.clearCache))))
	h.mux.Handle("POST /sites/{siteID}/wordpress/redis", stepUp(http.HandlerFunc(h.redis)))
	return h, nil
}

func (h *WordPressHandlers) Handler() http.Handler {
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

func (h *WordPressHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *WordPressHandlers) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
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

func (h *WordPressHandlers) snapshot(r *http.Request, site sites.Site, credentials *apps.OneTimeInstallCredentials, notice, warning string) wordpressPageData {
	data := wordpressPageData{
		Title: site.PrimaryDomain + " · WordPress · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "applications",
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

func (h *WordPressHandlers) page(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	h.render(w, "site_wordpress", h.snapshot(r, site, nil, strings.TrimSpace(r.URL.Query().Get("notice")), ""))
}

func (h *WordPressHandlers) install(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	adminUser := strings.TrimSpace(r.PostForm.Get("admin_user"))
	adminEmail := strings.TrimSpace(r.PostForm.Get("admin_email"))
	title := strings.TrimSpace(r.PostForm.Get("title"))
	if adminUser == "" || adminEmail == "" || title == "" {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Administrator username, email, and site title are required."))
		return
	}
	credentials, err := h.provisioner.PrepareInstall(r.Context(), site.ID, adminUser, adminEmail, title)
	if err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "WordPress could not be prepared: "+describeWordPressError(err)))
		return
	}
	h.audit(r, site.ID, "wordpress.prepared", map[string]string{"admin_user": adminUser})
	definition, err := h.provisioner.BuildInstallJob(site.ID, title)
	if err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "WordPress job could not be created: "+describeWordPressError(err)))
		return
	}
	jobID, err := h.enqueueWithAudit(r, definition, "wordpress.install.enqueued", site.ID)
	if err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "WordPress job could not be queued."))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := h.snapshot(r, site, &credentials, "Copy the WordPress administrator and database passwords now. They will not be shown again.", "")
	data.JobID = jobID
	h.render(w, "site_wordpress", data)
}

func (h *WordPressHandlers) update(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	definition, err := h.provisioner.BuildUpdateJob(site.ID)
	if err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Update job could not be created: "+describeWordPressError(err)))
		return
	}
	jobID, err := h.enqueueWithAudit(r, definition, "wordpress.update.enqueued", site.ID)
	if err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Update job could not be queued."))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/wordpress?job="+jobID, http.StatusSeeOther)
}

func (h *WordPressHandlers) policy(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	policy := apps.WordPressPolicy{
		MinorCore: r.PostForm.Get("minor_core") == "on",
		MajorCore: r.PostForm.Get("major_core") == "on",
		Plugins:   r.PostForm.Get("plugins") == "on",
		Themes:    r.PostForm.Get("themes") == "on",
	}
	if err := h.provisioner.SetPolicy(r.Context(), site.ID, policy); err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Policy could not be saved: "+describeWordPressError(err)))
		return
	}
	h.audit(r, site.ID, "wordpress.policy.changed", map[string]bool{"minor": policy.MinorCore, "major": policy.MajorCore, "plugins": policy.Plugins, "themes": policy.Themes})
	http.Redirect(w, r, "/sites/"+site.ID+"/wordpress?notice=Update+policy+saved", http.StatusSeeOther)
}

func (h *WordPressHandlers) cron(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	enabled := r.PostForm.Get("enabled") == "on"
	if err := h.provisioner.SetSystemCron(r.Context(), site.ID, enabled); err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Cron mode could not be changed: "+describeWordPressError(err)))
		return
	}
	h.audit(r, site.ID, "wordpress.cron.changed", map[string]bool{"system": enabled})
	http.Redirect(w, r, "/sites/"+site.ID+"/wordpress?notice=Cron+mode+updated", http.StatusSeeOther)
}

func (h *WordPressHandlers) clearCache(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if err := h.provisioner.ClearCache(r.Context(), site.ID); err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Cache could not be cleared: "+describeWordPressError(err)))
		return
	}
	h.audit(r, site.ID, "wordpress.cache.cleared", nil)
	http.Redirect(w, r, "/sites/"+site.ID+"/wordpress?notice=Cache+cleared", http.StatusSeeOther)
}

func (h *WordPressHandlers) redis(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	enabled := r.PostForm.Get("enabled") == "on"
	password := ""
	if enabled {
		generated, err := apps.GenerateWordPressSecrets()
		if err != nil {
			h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Redis credential could not be generated."))
			return
		}
		password = generated
	}
	if err := h.provisioner.ConfigureRedis(r.Context(), site.ID, enabled, password); err != nil {
		h.render(w, "site_wordpress", h.snapshot(r, site, nil, "", "Redis could not be configured: "+describeWordPressError(err)))
		return
	}
	h.audit(r, site.ID, "wordpress.redis.changed", map[string]bool{"enabled": enabled})
	if !enabled {
		http.Redirect(w, r, "/sites/"+site.ID+"/wordpress?notice=Redis+object+cache+disabled", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.render(w, "site_wordpress", h.snapshot(r, site, &apps.OneTimeInstallCredentials{DBPassword: password}, "Copy the Redis object cache password now.", ""))
}

func (h *WordPressHandlers) enqueueWithAudit(r *http.Request, definition jobs.Definition, action, siteID string) (string, error) {
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

func (h *WordPressHandlers) audit(r *http.Request, siteID, action string, detail any) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return
	}
	encoded, _ := json.Marshal(detail)
	_ = h.databases.WriteAudit(r.Context(), siteID, databases.AuditEvent{
		AdminID: session.AdminID, Action: action, Detail: encoded,
	})
}

func describeWordPressError(err error) string {
	switch {
	case errors.Is(err, apps.ErrAlreadyInstalled):
		return "WordPress is already installed for this site"
	case errors.Is(err, apps.ErrInstallationNotFound):
		return "WordPress is not installed yet"
	case errors.Is(err, databases.ErrSuffixTaken):
		return "the dedicated WordPress database already exists"
	default:
		return "operation failed"
	}
}
