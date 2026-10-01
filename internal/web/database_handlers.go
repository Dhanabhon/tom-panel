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
	"github.com/Dhanabhon/tom-panel/internal/databases"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

// DatabaseHandlers serves the per-site MariaDB and phpMyAdmin workspace.
type DatabaseHandlers struct {
	auth       *auth.Service
	repository *sites.Repository
	databases  *databases.Service
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type databasesPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, JobID string
	Site                                            sites.Site
	Databases                                       []databases.Database
	Backups                                         []databases.Backup
	Endpoint                                        *databases.Endpoint
	OneTimeCredential                               *databases.Credential
	Notice, Warning                                 string
}

// NewDatabaseHandlers wires the database routes for one site scope.
func NewDatabaseHandlers(authService *auth.Service, repository *sites.Repository, service *databases.Service, serverName string) (*DatabaseHandlers, error) {
	if authService == nil || repository == nil || service == nil {
		return nil, errors.New("database handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &DatabaseHandlers{
		auth: authService, repository: repository, databases: service,
		serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	session := authService.RequireSession
	stepUp := func(next http.Handler) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("GET /sites/{siteID}/databases", session(http.HandlerFunc(h.page)))
	h.mux.Handle("POST /sites/{siteID}/databases/create", stepUp(http.HandlerFunc(h.create)))
	h.mux.Handle("POST /sites/{siteID}/databases/rotate", stepUp(http.HandlerFunc(h.rotate)))
	h.mux.Handle("POST /sites/{siteID}/databases/delete", stepUp(http.HandlerFunc(h.delete)))
	h.mux.Handle("POST /sites/{siteID}/databases/backup", session(authService.RequireCSRF(http.HandlerFunc(h.backup))))
	h.mux.Handle("POST /sites/{siteID}/databases/restore", session(authService.RequireCSRF(http.HandlerFunc(h.restore))))
	h.mux.Handle("POST /sites/{siteID}/databases/phpmyadmin", stepUp(http.HandlerFunc(h.configurePHPMyAdmin)))
	h.mux.Handle("POST /sites/{siteID}/databases/phpmyadmin/disable", stepUp(http.HandlerFunc(h.disablePHPMyAdmin)))
	return h, nil
}

func (h *DatabaseHandlers) Handler() http.Handler {
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

func (h *DatabaseHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *DatabaseHandlers) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
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

func (h *DatabaseHandlers) snapshot(r *http.Request, site sites.Site, credential *databases.Credential, notice, warning string) databasesPageData {
	data := databasesPageData{
		Title: site.PrimaryDomain + " · Databases · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "databases",
		Notice: notice, Warning: warning,
		OneTimeCredential: credential,
	}
	if session, ok := auth.CurrentSession(r.Context()); ok {
		data.CSRFToken = session.CSRFToken
	}
	data.Databases, _ = h.databases.List(r.Context(), site.ID)
	data.Backups, _ = h.databases.ListBackups(r.Context(), site.ID, defaultBackupSuffix(r))
	if endpoint, err := h.databases.Endpoint(r.Context(), site.ID); err == nil {
		data.Endpoint = &endpoint
	}
	return data
}

func defaultBackupSuffix(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("suffix"))
}

func (h *DatabaseHandlers) page(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	data := h.snapshot(r, site, nil, strings.TrimSpace(r.URL.Query().Get("notice")), "")
	h.render(w, "site_databases", data)
}

func (h *DatabaseHandlers) create(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(r.PostForm.Get("suffix"))
	_, credential, err := h.databases.Create(r.Context(), site.ID, suffix)
	if err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "Database could not be created: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "database.created", map[string]string{"suffix": suffix})
	w.Header().Set("Cache-Control", "no-store")
	h.render(w, "site_databases", h.snapshot(r, site, &credential, "Copy the database password now. It will not be shown again.", ""))
}

func (h *DatabaseHandlers) rotate(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(r.PostForm.Get("suffix"))
	credential, err := h.databases.RotateCredential(r.Context(), site.ID, suffix, r.PostForm.Get("update_app") == "on")
	if err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "Rotation failed; the previous credential still works: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "database.rotated", map[string]string{"suffix": suffix})
	w.Header().Set("Cache-Control", "no-store")
	h.render(w, "site_databases", h.snapshot(r, site, &credential, "Copy the new database password now. The previous user was retired.", ""))
}

func (h *DatabaseHandlers) delete(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(r.PostForm.Get("suffix"))
	if err := h.databases.Delete(r.Context(), site.ID, suffix); err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "Database could not be deleted: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "database.deleted", map[string]string{"suffix": suffix})
	http.Redirect(w, r, "/sites/"+site.ID+"/databases?notice=Database+deleted", http.StatusSeeOther)
}

func (h *DatabaseHandlers) backup(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(r.PostForm.Get("suffix"))
	if _, err := h.databases.Backup(r.Context(), site.ID, suffix); err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "Backup failed: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "database.backed_up", map[string]string{"suffix": suffix})
	http.Redirect(w, r, "/sites/"+site.ID+"/databases?suffix="+suffix+"&notice=Backup+created", http.StatusSeeOther)
}

func (h *DatabaseHandlers) restore(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(r.PostForm.Get("suffix"))
	if err := h.databases.Restore(r.Context(), site.ID, suffix, r.PostForm.Get("backup")); err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "Restore failed: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "database.restored", map[string]string{"suffix": suffix})
	http.Redirect(w, r, "/sites/"+site.ID+"/databases?suffix="+suffix+"&notice=Restore+finished", http.StatusSeeOther)
}

func (h *DatabaseHandlers) configurePHPMyAdmin(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	mode := databases.PHPMyAdminMode(r.PostForm.Get("mode"))
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("port")))
	_, credential, err := h.databases.ConfigurePHPMyAdmin(r.Context(), site.ID, mode, r.PostForm.Get("hostname"), port)
	if err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "phpMyAdmin could not be configured: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "phpmyadmin.configured", map[string]string{"mode": string(mode)})
	w.Header().Set("Cache-Control", "no-store")
	if credential.Password != "" {
		h.render(w, "site_databases", h.snapshot(r, site, &credential, "phpMyAdmin enabled. Copy the HTTP Basic Auth password now.", ""))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/databases?notice=phpMyAdmin+enabled", http.StatusSeeOther)
}

func (h *DatabaseHandlers) disablePHPMyAdmin(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if err := h.databases.DisablePHPMyAdmin(r.Context(), site.ID); err != nil {
		h.render(w, "site_databases", h.snapshot(r, site, nil, "", "phpMyAdmin could not be disabled: "+describeDatabaseError(err)))
		return
	}
	h.audit(r, site.ID, "phpmyadmin.disabled", nil)
	http.Redirect(w, r, "/sites/"+site.ID+"/databases?notice=phpMyAdmin+disabled", http.StatusSeeOther)
}

func (h *DatabaseHandlers) audit(r *http.Request, siteID, action string, detail any) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return
	}
	encoded, _ := json.Marshal(detail)
	_ = h.databases.WriteAudit(r.Context(), siteID, databases.AuditEvent{
		AdminID: session.AdminID, Action: action, Detail: encoded,
	})
}

func describeDatabaseError(err error) string {
	switch {
	case errors.Is(err, databases.ErrSuffixTaken):
		return "that name already exists"
	case errors.Is(err, databases.ErrDatabaseNotFound):
		return "database not found"
	case errors.Is(err, databases.ErrBackupNotFound):
		return "backup not found"
	case errors.Is(err, databases.ErrPortUnavailable):
		return "the port is already used by another endpoint"
	case errors.Is(err, databases.ErrUnsafeSuffix), errors.Is(err, databases.ErrUnsafeIdentifier):
		return "the database name is invalid"
	default:
		return "operation failed"
	}
}
