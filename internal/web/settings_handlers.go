package web

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/integrations"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/operations"
)

// SettingsHandlers serves integrations, endpoint, and security settings.
type SettingsHandlers struct {
	auth         *auth.Service
	integrations *integrations.Service
	endpoint     *operations.EndpointChanger
	jobs         *jobs.Manager
	serverName   string
	templates    *template.Template
	mux          *http.ServeMux
}

type settingsPageData struct {
	Title, ServerName, CurrentNav, CSRFToken, Notice, Warning string
	CloudflareConfigured                                      bool
	S3Configured                                              bool
	SMTPConfigured                                            bool
	Endpoint                                                  operations.EndpointConfig
}

// NewSettingsHandlers wires the settings routes.
func NewSettingsHandlers(authService *auth.Service, integrationService *integrations.Service, endpoint *operations.EndpointChanger, manager *jobs.Manager, serverName string) (*SettingsHandlers, error) {
	if authService == nil || integrationService == nil || endpoint == nil || manager == nil {
		return nil, errors.New("settings handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &SettingsHandlers{
		auth: authService, integrations: integrationService, endpoint: endpoint,
		jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	session := authService.RequireSession
	stepUp := func(next http.Handler) http.Handler {
		return authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(next)))
	}
	h.mux.Handle("GET /settings", session(http.HandlerFunc(h.page)))
	h.mux.Handle("GET /api/dns-check", session(http.HandlerFunc(h.dnsCheck)))
	h.mux.Handle("POST /settings/cloudflare", stepUp(http.HandlerFunc(h.saveCloudflare)))
	h.mux.Handle("POST /settings/s3", stepUp(http.HandlerFunc(h.saveS3)))
	h.mux.Handle("POST /settings/smtp", stepUp(http.HandlerFunc(h.saveSMTP)))
	h.mux.Handle("POST /settings/endpoint", stepUp(http.HandlerFunc(h.changeEndpoint)))
	for _, provider := range []string{"cloudflare", "s3", "smtp"} {
		h.mux.Handle("POST /settings/"+provider+"/test", stepUp(http.HandlerFunc(h.testProvider)))
	}
	return h, nil
}

func (h *SettingsHandlers) Handler() http.Handler {
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

func (h *SettingsHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *SettingsHandlers) snapshot(r *http.Request, notice, warning string) settingsPageData {
	data := settingsPageData{
		Title: "Settings · TomPanel", ServerName: h.serverName, CurrentNav: "settings",
		Notice: notice, Warning: warning,
	}
	if session, ok := auth.CurrentSession(r.Context()); ok {
		data.CSRFToken = session.CSRFToken
	}
	data.CloudflareConfigured = h.integrations.CloudflareConfigured(r.Context())
	_, data.S3Configured, _ = h.integrations.S3(r.Context())
	_, data.SMTPConfigured, _ = h.integrations.SMTP(r.Context())
	if endpoint, err := h.endpoint.Current(r.Context()); err == nil {
		data.Endpoint = endpoint
	}
	return data
}

func (h *SettingsHandlers) page(w http.ResponseWriter, r *http.Request) {
	h.render(w, "settings", h.snapshot(r, strings.TrimSpace(r.URL.Query().Get("notice")), ""))
}

func (h *SettingsHandlers) saveCloudflare(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	zoneID := strings.TrimSpace(r.PostForm.Get("zone_id"))
	token := strings.TrimSpace(r.PostForm.Get("api_token"))
	if err := h.integrations.SaveCloudflare(r.Context(), zoneID, token); err != nil {
		h.render(w, "settings", h.snapshot(r, "", "Cloudflare settings are invalid."))
		return
	}
	http.Redirect(w, r, "/settings?notice=Cloudflare+saved", http.StatusSeeOther)
}

func (h *SettingsHandlers) saveS3(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	settings := backups.RemoteSettings{
		Endpoint:     strings.TrimSpace(r.PostForm.Get("endpoint")),
		Region:       strings.TrimSpace(r.PostForm.Get("region")),
		Bucket:       strings.TrimSpace(r.PostForm.Get("bucket")),
		Prefix:       strings.TrimSpace(r.PostForm.Get("prefix")),
		AgeRecipient: strings.TrimSpace(r.PostForm.Get("age_recipient")),
		AccessKeyID:  strings.TrimSpace(r.PostForm.Get("access_key")),
		SecretKey:    strings.TrimSpace(r.PostForm.Get("secret_key")),
	}
	if err := h.integrations.SaveS3(r.Context(), settings); err != nil {
		h.render(w, "settings", h.snapshot(r, "", "Object storage settings are invalid."))
		return
	}
	http.Redirect(w, r, "/settings?notice=Object+storage+saved", http.StatusSeeOther)
}

func (h *SettingsHandlers) saveSMTP(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("port")))
	if err != nil {
		h.render(w, "settings", h.snapshot(r, "", "SMTP port is invalid."))
		return
	}
	settings := integrations.SMTPSettings{
		Host: strings.TrimSpace(r.PostForm.Get("host")), Port: port,
		Username: strings.TrimSpace(r.PostForm.Get("username")), From: strings.TrimSpace(r.PostForm.Get("from")),
		Password: strings.TrimSpace(r.PostForm.Get("password")),
	}
	if err := h.integrations.SaveSMTP(r.Context(), settings); err != nil {
		h.render(w, "settings", h.snapshot(r, "", "SMTP settings are invalid."))
		return
	}
	http.Redirect(w, r, "/settings?notice=SMTP+saved", http.StatusSeeOther)
}

func (h *SettingsHandlers) testProvider(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	provider := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/settings/"), "/test")
	if err := h.integrations.Test(r.Context(), provider); err != nil {
		message := "connection test failed"
		var redacted *integrations.RedactedError
		if errors.As(err, &redacted) {
			message = redacted.Message
		}
		h.render(w, "settings", h.snapshot(r, "", message))
		return
	}
	http.Redirect(w, r, "/settings?notice=Connection+test+passed", http.StatusSeeOther)
}

func (h *SettingsHandlers) changeEndpoint(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	mode := r.PostForm.Get("mode")
	config := operations.EndpointConfig{Mode: mode}
	if mode == "public" {
		port, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("port")))
		if err != nil {
			h.render(w, "settings", h.snapshot(r, "", "Endpoint port is invalid."))
			return
		}
		config.Hostname = strings.TrimSpace(r.PostForm.Get("hostname"))
		config.Port = uint16(port)
		config.CloudflareProxy = r.PostForm.Get("cloudflare_proxy") == "on"
		config.AcmeEmail = strings.TrimSpace(r.PostForm.Get("acme_email"))
	}
	definition, err := h.endpoint.BuildEndpointChangeJob(r.Context(), config)
	if err != nil {
		h.render(w, "settings", h.snapshot(r, "", "Endpoint change was refused: "+err.Error()))
		return
	}
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	jobID, err := h.jobs.EnqueueWithAudit(r.Context(), definition, jobs.Audit{
		AdminID: session.AdminID,
		Action:  "endpoint.change.enqueued",
		Detail:  []byte(`{"mode":"` + mode + `"}`),
	})
	if err != nil {
		h.render(w, "settings", h.snapshot(r, "", "Endpoint job could not be queued."))
		return
	}
	h.jobs.Wake()
	_ = jobID
	http.Redirect(w, r, "/settings?notice=Endpoint+change+queued", http.StatusSeeOther)
}
