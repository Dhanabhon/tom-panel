package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	webassets "github.com/Dhanabhon/tom-panel/web"
)

type DashboardHandlers struct {
	auth       *auth.Service
	jobs       *jobs.Manager
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type loginPageData struct {
	Title      string
	ServerName string
	Setup      bool
}

type dashboardPageData struct {
	Title      string
	ServerName string
	CSRFToken  string
	Jobs       []jobs.Job
	SelectedID string
	CurrentNav string
}

func NewDashboardHandlers(service *auth.Service, manager *jobs.Manager, serverName string) (*DashboardHandlers, error) {
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &DashboardHandlers{auth: service, jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /login", h.login)
	h.mux.HandleFunc("GET /setup", h.setup)
	h.mux.HandleFunc("GET /", h.dashboardRoute)
	return h, nil
}

func pageTemplates() (*template.Template, error) {
	return template.New("pages").Funcs(template.FuncMap{
		"statusClass": statusClass,
		"statusLabel": statusLabel,
		"jobTime":     jobTime,
		"canCancel":   canCancel,
		"canRetry":    canRetry,
	}).ParseFS(webassets.FS, "templates/*.html")
}

func (h *DashboardHandlers) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setPageSecurityHeaders(w)
		h.mux.ServeHTTP(w, r)
	})
}

func (h *DashboardHandlers) login(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login", loginPageData{Title: "Sign in · TomPanel", ServerName: h.serverName})
}

func (h *DashboardHandlers) setup(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login", loginPageData{Title: "Set up · TomPanel", ServerName: h.serverName, Setup: true})
}

func (h *DashboardHandlers) dashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	recent, err := h.jobs.List(r.Context(), 20)
	if err != nil {
		http.Error(w, "dashboard could not be loaded", http.StatusInternalServerError)
		return
	}
	h.render(w, "dashboard", dashboardPageData{
		Title:      "Dashboard · TomPanel",
		ServerName: h.serverName,
		CSRFToken:  session.CSRFToken,
		Jobs:       recent,
		SelectedID: r.URL.Query().Get("job"),
		CurrentNav: "dashboard",
	})
}

func (h *DashboardHandlers) dashboardRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil || !h.auth.SessionValid(r.Context(), cookie.Value) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.auth.RequireSession(http.HandlerFunc(h.dashboard)).ServeHTTP(w, r)
}

func (h *DashboardHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func setPageSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func statusClass(status jobs.Status) string {
	switch status {
	case jobs.StatusSucceeded:
		return "good"
	case jobs.StatusFailed, jobs.StatusCancelled:
		return "bad"
	case jobs.StatusRunning, jobs.StatusCancelling:
		return "warn"
	default:
		return "neutral"
	}
}

func statusLabel(status jobs.Status) string {
	if status == "" {
		return "Unknown"
	}
	return strings.ToUpper(string(status[:1])) + strings.ReplaceAll(string(status[1:]), "_", " ")
}

func jobTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.Local().Format("2 Jan · 15:04")
}

func canCancel(status jobs.Status) bool {
	return status == jobs.StatusQueued || status == jobs.StatusRunning
}

func canRetry(status jobs.Status, code jobs.ErrorCode) bool {
	if status != jobs.StatusFailed {
		return false
	}
	switch code {
	case jobs.ErrorReconciliationRequired, jobs.ErrorReconciliationFailed, jobs.ErrorIncompatibleState:
		return false
	default:
		return true
	}
}
