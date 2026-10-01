package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

type RuntimeHandlers struct {
	auth       *auth.Service
	runtime    *panelruntime.Service
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type runtimePageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken, SiteID string
	Site                                             sites.Site
	Config                                           panelruntime.PHPConfig
}

func NewRuntimeHandlers(authService *auth.Service, runtimeService *panelruntime.Service, serverName string) (*RuntimeHandlers, error) {
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	handler := &RuntimeHandlers{auth: authService, runtime: runtimeService, serverName: serverName, templates: templates, mux: http.NewServeMux()}
	handler.mux.HandleFunc("GET /sites/{siteID}/runtime", handler.show)
	return handler, nil
}

func (h *RuntimeHandlers) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setPageSecurityHeaders(w)
		cookie, err := r.Cookie(auth.SessionCookieName)
		if err != nil || !h.auth.SessionValid(r.Context(), cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h.auth.RequireSession(h.mux).ServeHTTP(w, r)
	})
}

func (h *RuntimeHandlers) show(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	siteID := r.PathValue("siteID")
	config, err := h.runtime.Config(r.Context(), siteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	site := sites.Site{ID: siteID, PrimaryDomain: siteID}
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, "site_runtime", runtimePageData{
		Title: "PHP runtime · TomPanel", ServerName: h.serverName, CurrentNav: "sites", CurrentTab: "runtime",
		CSRFToken: session.CSRFToken, SiteID: siteID, Site: site, Config: config,
	}); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}
