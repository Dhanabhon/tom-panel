package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/files"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

// FileHandlers serves the confined File Manager and SFTP access pages.
type FileHandlers struct {
	auth       *auth.Service
	repository *sites.Repository
	service    *files.Service
	access     *files.AccessService
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type filesPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, JobID string
	Site                                                        sites.Site
	Path, Parent                                                string
	Entries                                                     []files.Entry
	Trash                                                       []files.TrashEntry
	Account                                                     *files.Account
	Keys                                                        []files.Key
	OneTimePassword                                             string
	Notice, Warning                                             string
}

// NewFileHandlers wires the file manager routes for one site scope.
func NewFileHandlers(authService *auth.Service, repository *sites.Repository, service *files.Service, access *files.AccessService, serverName string) (*FileHandlers, error) {
	if authService == nil || repository == nil || service == nil || access == nil {
		return nil, errors.New("file handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &FileHandlers{
		auth: authService, repository: repository, service: service, access: access,
		serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	h.mux.Handle("GET /sites/{siteID}/files", authService.RequireSession(http.HandlerFunc(h.page)))
	h.mux.Handle("POST /sites/{siteID}/files/create", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.create))))
	h.mux.Handle("POST /sites/{siteID}/files/save", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.save))))
	h.mux.Handle("POST /sites/{siteID}/files/upload", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.upload))))
	h.mux.Handle("POST /sites/{siteID}/files/rename", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.rename))))
	h.mux.Handle("POST /sites/{siteID}/files/copy", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.copy))))
	h.mux.Handle("POST /sites/{siteID}/files/trash", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.trash))))
	h.mux.Handle("POST /sites/{siteID}/files/trash/restore", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.restore))))
	h.mux.Handle("POST /sites/{siteID}/files/archive", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.archive))))
	h.mux.Handle("POST /sites/{siteID}/files/extract", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.extract))))
	h.mux.Handle("GET /sites/{siteID}/files/download", authService.RequireSession(http.HandlerFunc(h.download)))
	h.mux.Handle("GET /sites/{siteID}/files/list", authService.RequireSession(http.HandlerFunc(h.list)))
	h.mux.Handle("POST /sites/{siteID}/access/sftp/enable", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.sftpEnable))))
	h.mux.Handle("POST /sites/{siteID}/access/sftp/disable", authService.RequireSession(authService.RequireCSRF(http.HandlerFunc(h.sftpDisable))))
	h.mux.Handle("POST /sites/{siteID}/access/sftp/password", authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(http.HandlerFunc(h.sftpPassword)))))
	h.mux.Handle("POST /sites/{siteID}/access/sftp/keys/add", authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(http.HandlerFunc(h.sftpKeyAdd)))))
	h.mux.Handle("POST /sites/{siteID}/access/sftp/keys/remove", authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(http.HandlerFunc(h.sftpKeyRemove)))))
	return h, nil
}

func (h *FileHandlers) Handler() http.Handler {
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

func (h *FileHandlers) siteID(r *http.Request) string { return r.PathValue("siteID") }

func (h *FileHandlers) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
	site, err := h.repository.Get(r.Context(), h.siteID(r))
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

func (h *FileHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *FileHandlers) page(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	dir := strings.Trim(r.URL.Query().Get("path"), "/")
	if dir == "" {
		dir = "."
	}
	entries, listErr := h.service.List(r.Context(), site.ID, dir)
	parent := "."
	if dir != "." {
		if cleaned, err := h.service.ValidateRelative(dir); err != nil {
			http.Error(w, "path is invalid", http.StatusBadRequest)
			return
		} else if cleaned != "." {
			parent = path.Dir(cleaned)
		}
	}
	trash, _ := h.service.ListTrash(r.Context(), site.ID, "")
	account, keys, _ := h.access.Get(r.Context(), site.ID)
	data := filesPageData{
		Title: site.PrimaryDomain + " · Files · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "files",
		CSRFToken: session.CSRFToken, Site: site, Path: dir, Parent: parent,
		Entries: entries, Trash: trash, Account: &account, Keys: keys,
		Notice:  strings.TrimSpace(r.URL.Query().Get("notice")),
		Warning: strings.TrimSpace(r.URL.Query().Get("warning")),
	}
	if listErr != nil {
		data.Warning = "Directory could not be listed."
	}
	h.render(w, "site_files", data)
}

func (h *FileHandlers) list(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	dir := strings.Trim(r.URL.Query().Get("path"), "/")
	if dir == "" {
		dir = "."
	}
	entries, err := h.service.List(r.Context(), site.ID, dir)
	if err != nil {
		http.Error(w, "directory could not be listed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

func (h *FileHandlers) create(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	kind := files.KindFile
	if r.PostForm.Get("kind") == "directory" {
		kind = files.KindDirectory
	}
	target := joinDir(r.PostForm.Get("path"), r.PostForm.Get("name"))
	if err := h.service.Create(r.Context(), site.ID, target, kind); err != nil {
		h.redirectWarn(w, r, site.ID, r.PostForm.Get("path"), describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, r.PostForm.Get("path"), "")
}

func (h *FileHandlers) save(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	target := r.PostForm.Get("path")
	if err := h.service.WriteText(r.Context(), site.ID, target, []byte(r.PostForm.Get("content"))); err != nil {
		h.redirectWarn(w, r, site.ID, path.Dir(target), describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, path.Dir(target), "Saved "+path.Base(target))
}

func (h *FileHandlers) upload(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.service.Limits().MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "Upload exceeds the configured size limit")
		return
	}
	dir := strings.Trim(r.PostForm.Get("path"), "/")
	if dir == "" {
		dir = "."
	}
	uploaded, header, err := r.FormFile("file")
	if err != nil {
		h.redirectWarn(w, r, site.ID, dir, "No file was uploaded")
		return
	}
	defer uploaded.Close()
	name := strings.ReplaceAll(header.Filename, "\\", "/")
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		h.redirectWarn(w, r, site.ID, dir, "Uploaded file name is invalid")
		return
	}
	target := joinDir(dir, name)
	if _, err := h.service.ValidateRelative(target); err != nil {
		h.redirectWarn(w, r, site.ID, dir, "Uploaded file name is invalid")
		return
	}
	if err := h.service.Upload(r.Context(), site.ID, target, uploaded); err != nil {
		h.redirectWarn(w, r, site.ID, dir, describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, dir, "Uploaded "+name)
}

func (h *FileHandlers) rename(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	from := r.PostForm.Get("path")
	to := joinDir(path.Dir(from), r.PostForm.Get("name"))
	if err := h.service.Rename(r.Context(), site.ID, from, to); err != nil {
		h.redirectWarn(w, r, site.ID, path.Dir(from), describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, path.Dir(to), "")
}

func (h *FileHandlers) copy(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	from := r.PostForm.Get("path")
	to := joinDir(path.Dir(from), r.PostForm.Get("name"))
	if err := h.service.Copy(r.Context(), site.ID, from, to); err != nil {
		h.redirectWarn(w, r, site.ID, path.Dir(from), describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, path.Dir(to), "")
}

func (h *FileHandlers) trash(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	target := r.PostForm.Get("path")
	if _, err := h.service.Trash(r.Context(), site.ID, target); err != nil {
		h.redirectWarn(w, r, site.ID, path.Dir(target), describeFileError(err))
		return
	}
	h.audit(r, "files.trashed", site.ID, target)
	h.redirectBack(w, r, site.ID, path.Dir(target), "Moved to trash")
}

func (h *FileHandlers) restore(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	if err := h.service.RestoreTrash(r.Context(), site.ID, r.PostForm.Get("id"), r.PostForm.Get("dest")); err != nil {
		h.redirectWarn(w, r, site.ID, ".", describeFileError(err))
		return
	}
	h.audit(r, "files.restored", site.ID, r.PostForm.Get("id"))
	h.redirectBack(w, r, site.ID, ".", "Restored from trash")
}

func (h *FileHandlers) archive(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		name = "archive-" + strconv.FormatInt(time.Now().Unix(), 10) + ".tar.gz"
	}
	if !strings.HasSuffix(name, ".tar.gz") {
		name += ".tar.gz"
	}
	dir := strings.Trim(r.PostForm.Get("path"), "/")
	if dir == "." {
		dir = ""
	}
	var sources []string
	for _, selected := range r.PostForm["selected"] {
		sources = append(sources, joinDir(dir, selected))
	}
	if len(sources) == 0 {
		h.redirectWarn(w, r, site.ID, dir, "Select at least one entry to archive")
		return
	}
	destination := joinDir(dir, name)
	if err := h.service.Archive(r.Context(), site.ID, sources, destination); err != nil {
		h.redirectWarn(w, r, site.ID, dir, describeFileError(err))
		return
	}
	h.redirectBack(w, r, site.ID, dir, "Created "+name)
}

func (h *FileHandlers) extract(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.service.Limits().MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "Archive exceeds the configured size limit")
		return
	}
	dir := strings.Trim(r.PostForm.Get("path"), "/")
	if dir == "" {
		dir = "."
	}
	uploaded, header, err := r.FormFile("file")
	if err != nil {
		h.redirectWarn(w, r, site.ID, dir, "No archive was uploaded")
		return
	}
	defer uploaded.Close()
	name := strings.TrimSuffix(path.Base(strings.ReplaceAll(header.Filename, "\\", "/")), ".tar.gz")
	if name == "" || name == "." {
		h.redirectWarn(w, r, site.ID, dir, "Archive name is invalid")
		return
	}
	if err := h.service.Extract(r.Context(), site.ID, uploaded, joinDir(dir, name), h.service.Limits()); err != nil {
		h.redirectWarn(w, r, site.ID, dir, describeFileError(err))
		return
	}
	h.audit(r, "files.extracted", site.ID, joinDir(dir, name))
	h.redirectBack(w, r, site.ID, dir, "Extracted "+name)
}

func (h *FileHandlers) download(w http.ResponseWriter, r *http.Request) {
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	target := r.URL.Query().Get("path")
	handle, err := h.service.Download(r.Context(), site.ID, target)
	if err != nil {
		status := http.StatusNotFound
		if errors.Is(err, files.ErrUnsafePath) || errors.Is(err, files.ErrNotRegularFile) {
			status = http.StatusBadRequest
		}
		http.Error(w, describeFileError(err), status)
		return
	}
	defer handle.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeDownloadName(path.Base(target))+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, handle)
}

func (h *FileHandlers) sftpEnable(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	if _, err := h.access.Enable(r.Context(), site.ID, &files.AuditEvent{
		AdminID: session.AdminID, Action: "sftp.account.enabled", Detail: detail,
	}); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "SFTP access could not be enabled")
		return
	}
	h.redirectBack(w, r, site.ID, ".", "SFTP access enabled")
}

func (h *FileHandlers) sftpDisable(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	if err := h.access.Disable(r.Context(), site.ID, &files.AuditEvent{
		AdminID: session.AdminID, Action: "sftp.account.disabled", Detail: detail,
	}); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "SFTP access could not be disabled")
		return
	}
	h.redirectBack(w, r, site.ID, ".", "SFTP access disabled")
}

func (h *FileHandlers) sftpPassword(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	password, err := h.access.RotatePassword(r.Context(), site.ID, &files.AuditEvent{
		AdminID: session.AdminID, Action: "sftp.password.rotated", Detail: detail,
	})
	if err != nil {
		h.redirectWarn(w, r, site.ID, ".", "Password could not be rotated")
		return
	}
	account, keys, _ := h.access.Get(r.Context(), site.ID)
	h.render(w, "site_files", filesPageData{
		Title: site.PrimaryDomain + " · Files · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "files",
		CSRFToken: session.CSRFToken, Site: site, Path: ".", Parent: ".",
		Entries: h.rootEntries(r, site.ID), Account: &account, Keys: keys,
		OneTimePassword: password, Notice: "Copy the new SFTP password now. It will not be shown again.",
	})
	w.Header().Set("Cache-Control", "no-store")
}

func (h *FileHandlers) sftpKeyAdd(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	publicKey := strings.TrimSpace(r.PostForm.Get("public_key"))
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	if _, err := h.access.AddKey(r.Context(), site.ID, publicKey, &files.AuditEvent{
		AdminID: session.AdminID, Action: "sftp.key.added", Detail: detail,
	}); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "Public key could not be added")
		return
	}
	h.redirectBack(w, r, site.ID, ".", "Public key authorized")
}

func (h *FileHandlers) sftpKeyRemove(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !parseSmallForm(w, r) {
		return
	}
	site, ok := h.loadSite(w, r)
	if !ok {
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
	}{SiteID: site.ID})
	if err := h.access.RemoveKey(r.Context(), site.ID, r.PostForm.Get("fingerprint"), &files.AuditEvent{
		AdminID: session.AdminID, Action: "sftp.key.removed", Detail: detail,
	}); err != nil {
		h.redirectWarn(w, r, site.ID, ".", "Public key could not be removed")
		return
	}
	h.redirectBack(w, r, site.ID, ".", "Public key removed")
}

func (h *FileHandlers) redirectBack(w http.ResponseWriter, r *http.Request, siteID, dir, notice string) {
	target := "/sites/" + siteID + "/files?path=" + strings.Trim(dir, "/")
	if notice != "" {
		target += "&notice=" + url.QueryEscape(notice)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// redirectWarn returns to the file browser with a warning banner instead of
// an unstyled plain-text error page.
func (h *FileHandlers) redirectWarn(w http.ResponseWriter, r *http.Request, siteID, dir, message string) {
	target := "/sites/" + siteID + "/files?path=" + strings.Trim(dir, "/")
	if message != "" {
		target += "&warning=" + url.QueryEscape(message)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *FileHandlers) audit(r *http.Request, action, siteID, target string) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return
	}
	detail, _ := json.Marshal(struct {
		SiteID string `json:"site_id"`
		Target string `json:"target"`
	}{SiteID: siteID, Target: target})
	_ = h.access.WriteAudit(r.Context(), siteID, files.AuditEvent{
		AdminID: session.AdminID, Action: action, Detail: detail,
	})
}

func joinDir(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return strings.Trim(dir, "/") + "/" + strings.Trim(name, "/")
}

func sanitizeDownloadName(name string) string {
	var builder strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}
	if builder.Len() == 0 {
		return "download"
	}
	return builder.String()
}

func describeFileError(err error) string {
	switch {
	case errors.Is(err, files.ErrUnsafePath):
		return "path is not allowed"
	case errors.Is(err, files.ErrTooLarge):
		return "operation exceeds the configured size limit"
	case errors.Is(err, files.ErrNotRegularFile):
		return "path is not a regular file"
	case errors.Is(err, files.ErrDestinationExists):
		return "destination already exists"
	case errors.Is(err, files.ErrUnsafeArchiveEntry):
		return "archive contains an unsafe entry"
	case errors.Is(err, files.ErrArchiveTooLarge):
		return "archive exceeds the configured limits"
	case errors.Is(err, files.ErrNotFound):
		return "path was not found"
	default:
		return "file operation failed"
	}
}

func (h *FileHandlers) rootEntries(r *http.Request, siteID string) []files.Entry {
	entries, err := h.service.List(r.Context(), siteID, ".")
	if err != nil {
		return nil
	}
	return entries
}
