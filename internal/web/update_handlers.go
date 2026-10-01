package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/operations"
)

// UpdateHandlers exposes the signed panel update and confirmed package
// flows. Every action requires step-up.
type UpdateHandlers struct {
	auth    *auth.Service
	updater *operations.Updater
	jobs    *jobs.Manager
	mux     *http.ServeMux
}

// NewUpdateHandlers wires the update routes.
func NewUpdateHandlers(authService *auth.Service, updater *operations.Updater, manager *jobs.Manager) (*UpdateHandlers, error) {
	if authService == nil || updater == nil || manager == nil {
		return nil, errors.New("update handler dependencies are required")
	}
	h := &UpdateHandlers{auth: authService, updater: updater, jobs: manager}
	h.mux = http.NewServeMux()
	guarded := func(next http.HandlerFunc) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("POST /updates/tompanel", guarded(http.HandlerFunc(h.tompanelUpdate)))
	h.mux.Handle("POST /updates/packages", guarded(http.HandlerFunc(h.packageUpdate)))
	h.mux.Handle("POST /updates/tools", guarded(http.HandlerFunc(h.toolUpdate)))
	return h, nil
}

// Handler gates every update route behind session, step-up, and CSRF.
func (h *UpdateHandlers) Handler() http.Handler {
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

func (h *UpdateHandlers) fail(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/system?warning="+strings.ReplaceAll(message, " ", "+"), http.StatusSeeOther)
}

func (h *UpdateHandlers) enqueue(w http.ResponseWriter, r *http.Request, definition jobs.Definition, action, detail string) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if _, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID, Action: action, Detail: []byte(detail),
	}); err != nil {
		h.fail(w, r, action+" job could not be queued")
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/system?notice="+strings.ReplaceAll(action, ".", "+")+"+queued", http.StatusSeeOther)
}

func (h *UpdateHandlers) tompanelUpdate(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	manifest := operations.ReleaseManifest{
		Version:   strings.TrimSpace(r.PostForm.Get("version")),
		SHA256:    strings.TrimSpace(r.PostForm.Get("sha256")),
		URL:       strings.TrimSpace(r.PostForm.Get("url")),
		Signature: strings.TrimSpace(r.PostForm.Get("signature")),
	}
	definition, err := h.updater.BuildTomPanelUpdateJob(r.Context(), manifest)
	if err != nil {
		h.fail(w, r, "Panel update rejected: "+err.Error())
		return
	}
	h.enqueue(w, r, definition, "tompanel.update.enqueued", `{"version":"`+manifest.Version+`"}`)
}

func (h *UpdateHandlers) packageUpdate(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	definition, err := h.updater.BuildPackageJob(operations.PackageUpdate{
		Packages:  strings.Fields(r.PostForm.Get("packages")),
		Confirmed: r.PostForm.Get("confirmed") == "on",
	})
	if err != nil {
		h.fail(w, r, "Package update rejected: "+err.Error())
		return
	}
	h.enqueue(w, r, definition, "package.apply.enqueued", `{}`)
}

func (h *UpdateHandlers) toolUpdate(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	definition, err := h.updater.BuildToolUpdateJob(operations.ToolUpdate{
		Tool:      strings.TrimSpace(r.PostForm.Get("tool")),
		Version:   strings.TrimSpace(r.PostForm.Get("version")),
		SHA256:    strings.TrimSpace(r.PostForm.Get("sha256")),
		Confirmed: r.PostForm.Get("confirmed") == "on",
	})
	if err != nil {
		h.fail(w, r, "Tool update rejected: "+err.Error())
		return
	}
	h.enqueue(w, r, definition, "tool.update.enqueued", `{}`)
}
