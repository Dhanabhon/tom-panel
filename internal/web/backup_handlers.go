package web

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

// BackupHandlers serves the per-site recovery workspace and the guarded
// site deletion flow.
type BackupHandlers struct {
	auth       *auth.Service
	repository *sites.Repository
	backups    *backups.Service
	deleter    *sites.DeleteProvisioner
	jobs       *jobs.Manager
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type backupsPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, JobID string
	Site                                                        sites.Site
	SiteKind                                                    string
	Backups                                                     []backups.Backup
	LocalOnlyWarning                                            bool
	Notice, Warning                                             string
}

// NewBackupHandlers wires the backup routes for one site scope.
func NewBackupHandlers(authService *auth.Service, repository *sites.Repository, backupService *backups.Service, deleter *sites.DeleteProvisioner, manager *jobs.Manager, serverName string) (*BackupHandlers, error) {
	if authService == nil || repository == nil || backupService == nil || manager == nil {
		return nil, errors.New("backup handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &BackupHandlers{
		auth: authService, repository: repository, backups: backupService, deleter: deleter,
		jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	session := authService.RequireSession
	stepUp := func(next http.Handler) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("GET /sites/{siteID}/backups", session(http.HandlerFunc(h.page)))
	h.mux.Handle("POST /sites/{siteID}/backups/create", session(authService.RequireCSRF(http.HandlerFunc(h.create))))
	h.mux.Handle("POST /sites/{siteID}/backups/restore", stepUp(http.HandlerFunc(h.restore)))
	h.mux.Handle("POST /sites/{siteID}/backups/delete", stepUp(http.HandlerFunc(h.remove)))
	h.mux.Handle("POST /sites/{siteID}/delete", stepUp(http.HandlerFunc(h.deleteSite)))
	return h, nil
}

func (h *BackupHandlers) Handler() http.Handler {
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

func (h *BackupHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *BackupHandlers) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
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

func (h *BackupHandlers) snapshot(r *http.Request, site sites.Site, notice, warning string) backupsPageData {
	data := backupsPageData{
		Title: site.PrimaryDomain + " · Backups · TomPanel", ServerName: h.serverName, CurrentNav: "sites",
		CurrentTab: "backups", Notice: notice, Warning: warning, SiteKind: string(site.Kind),
		JobID: r.URL.Query().Get("job"),
	}
	if session, ok := auth.CurrentSession(r.Context()); ok {
		data.CSRFToken = session.CSRFToken
	}
	items, err := h.backups.List(r.Context(), site.ID)
	if err == nil {
		data.Backups = items
		for _, item := range items {
			if item.Storage == backups.StorageLocal {
				data.LocalOnlyWarning = true
			}
		}
	}
	return data
}

func (h *BackupHandlers) page(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	notice := strings.TrimSpace(r.URL.Query().Get("notice"))
	data := h.snapshot(r, site, notice, "")
	if data.LocalOnlyWarning {
		data.Warning = "Some backups exist only on this server. Off-server copies are required to survive a full VPS loss."
	}
	h.render(w, "backups", data)
}

func (h *BackupHandlers) create(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if _, _, err := h.backups.Create(r.Context(), site.ID, string(backups.KindManual)); err != nil {
		h.render(w, "backups", h.snapshot(r, site, "", "Backup failed: "+describeBackupError(err)))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/backups?notice=Backup+created", http.StatusSeeOther)
}

func (h *BackupHandlers) restore(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirmed") != "on" {
		h.render(w, "backups", h.snapshot(r, site, "", "Restore requires the confirmation checkbox."))
		return
	}
	if err := h.backups.Restore(r.Context(), r.PostForm.Get("backup")); err != nil {
		h.render(w, "backups", h.snapshot(r, site, "", "Restore failed and the previous state was kept: "+describeBackupError(err)))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/backups?notice=Restore+finished", http.StatusSeeOther)
}

func (h *BackupHandlers) remove(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if err := h.backups.Delete(r.Context(), r.PostForm.Get("backup"), r.PostForm.Get("force") == "on"); err != nil {
		h.render(w, "backups", h.snapshot(r, site, "", describeBackupError(err)))
		return
	}
	http.Redirect(w, r, "/sites/"+site.ID+"/backups?notice=Backup+deleted", http.StatusSeeOther)
}

func (h *BackupHandlers) deleteSite(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm_name") != site.PrimaryDomain {
		h.render(w, "backups", h.snapshot(r, site, "", "Type the exact primary domain to confirm deletion."))
		return
	}
	if r.PostForm.Get("release_dns") != "on" && r.PostForm.Get("keep_dns") != "on" {
		h.render(w, "backups", h.snapshot(r, site, "", "Choose whether TomPanel-owned DNS records should be released."))
		return
	}
	if h.deleter == nil {
		http.Error(w, "site deletion is unavailable", http.StatusServiceUnavailable)
		return
	}
	definition, err := h.deleter.BuildDeleteJob(site.ID, r.PostForm.Get("release_dns") == "on")
	if err != nil {
		h.render(w, "backups", h.snapshot(r, site, "", "Site cannot be deleted now: "+err.Error()))
		return
	}
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	jobID, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID,
		Action:  "site.delete.enqueued",
		Detail:  []byte(`{"site_id":"` + site.ID + `"}`),
	})
	if err != nil {
		h.render(w, "backups", h.snapshot(r, site, "", "Deletion job could not be queued."))
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/sites/"+site.ID+"/backups?job="+jobID+"&notice=Deletion+started", http.StatusSeeOther)
}

func describeBackupError(err error) string {
	switch {
	case errors.Is(err, backups.ErrInsufficientDisk):
		return "the backup volume is above the safety threshold"
	case errors.Is(err, backups.ErrProtectedBackup):
		return "manual backups must be deleted with the explicit override"
	case errors.Is(err, backups.ErrChecksumMismatch):
		return "the backup body no longer matches its recorded checksum"
	case errors.Is(err, backups.ErrBackupNotFound):
		return "backup not found"
	default:
		return "operation failed"
	}
}
