package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/domains"
)

type DomainHandlers struct {
	auth       *auth.Service
	domains    *domains.Service
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type domainsPageData struct {
	Title, ServerName, CurrentNav, CSRFToken string
	Domains                                  []domains.Domain
}

func NewDomainHandlers(authService *auth.Service, domainService *domains.Service, serverName string) (*DomainHandlers, error) {
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	handler := &DomainHandlers{auth: authService, domains: domainService, serverName: serverName, templates: templates, mux: http.NewServeMux()}
	handler.mux.HandleFunc("GET /domains", handler.index)
	return handler, nil
}

func (h *DomainHandlers) Handler() http.Handler {
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

func (h *DomainHandlers) index(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	items, err := h.domains.ListDomains(r.Context())
	if err != nil {
		http.Error(w, "domains could not be loaded", http.StatusInternalServerError)
		return
	}
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, "domains", domainsPageData{
		Title: "Domains & SSL · TomPanel", ServerName: h.serverName, CurrentNav: "domains",
		CSRFToken: session.CSRFToken, Domains: items,
	}); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}
