package web

import (
	"bytes"
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/operations"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

// OperationsHandlers serves services, activity, system health, and site logs.
type OperationsHandlers struct {
	auth       *auth.Service
	repository *sites.Repository
	database   *store.Store
	services   *operations.ServiceManager
	logs       *operations.LogReader
	jobs       *jobs.Manager
	serverName string
	templates  *template.Template
	mux        *http.ServeMux
}

type systemPageData struct {
	Title, ServerName, CurrentNav, CSRFToken string
	Snapshot                                 operations.Snapshot
	UpdateState                              string
	RebootRequired                           bool
	FirewallActive                           bool
	Warning                                  string
}

type servicesPageData struct {
	Title, ServerName, CurrentNav, CSRFToken, Notice string
	Services                                         []operations.ManagedService
	Warning                                          string
}

type activityRow struct {
	Kind, Status, Action, Target, When string
}

type activityPageData struct {
	Title, ServerName, CurrentNav string
	Rows                          []activityRow
}

type siteLogsPageData struct {
	Title, ServerName, CurrentNav, CurrentTab, CSRFToken string
	Site                                                 sites.Site
	Source, Search                                       string
	Events                                               []operations.LogEvent
	Warning                                              string
}

// NewOperationsHandlers wires the operational routes.
func NewOperationsHandlers(authService *auth.Service, repository *sites.Repository, database *store.Store, services *operations.ServiceManager, logs *operations.LogReader, manager *jobs.Manager, serverName string) (*OperationsHandlers, error) {
	if authService == nil || repository == nil || database == nil || services == nil || logs == nil || manager == nil {
		return nil, errors.New("operations handler dependencies are required")
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "TomPanel server"
	}
	templates, err := pageTemplates()
	if err != nil {
		return nil, err
	}
	h := &OperationsHandlers{
		auth: authService, repository: repository, database: database, services: services,
		logs: logs, jobs: manager, serverName: serverName, templates: templates, mux: http.NewServeMux(),
	}
	h.mux.Handle("GET /services", authService.RequireSession(http.HandlerFunc(h.servicesPage)))
	h.mux.Handle("POST /services/{key}/restart", authService.RequireSession(authService.RequireStepUp(authService.RequireCSRF(http.HandlerFunc(h.serviceRestart)))))
	h.mux.Handle("GET /activity", authService.RequireSession(http.HandlerFunc(h.activity)))
	h.mux.Handle("GET /system", authService.RequireSession(http.HandlerFunc(h.system)))
	h.mux.Handle("GET /sites/{siteID}/logs", authService.RequireSession(http.HandlerFunc(h.siteLogs)))
	return h, nil
}

func (h *OperationsHandlers) Handler() http.Handler {
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

func (h *OperationsHandlers) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func (h *OperationsHandlers) servicesPage(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	services, err := h.services.Inspect(r.Context())
	data := servicesPageData{
		Title: "Services · TomPanel", ServerName: h.serverName, CurrentNav: "services",
		CSRFToken: session.CSRFToken, Services: services, Notice: strings.TrimSpace(r.URL.Query().Get("notice")),
	}
	if err != nil {
		data.Warning = "Service states could not be read."
	}
	h.render(w, "services", data)
}

func (h *OperationsHandlers) serviceRestart(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := h.services.Restart(r.Context(), key); err != nil {
		http.Error(w, "service action was refused", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/services?notice="+key+"+restart+issued", http.StatusSeeOther)
}

func (h *OperationsHandlers) activity(w http.ResponseWriter, r *http.Request) {
	data := activityPageData{Title: "Activity · TomPanel", ServerName: h.serverName, CurrentNav: "activity"}
	jobRows, err := h.jobs.List(r.Context(), 30)
	if err == nil {
		for _, job := range jobRows {
			data.Rows = append(data.Rows, activityRow{
				Kind: "job", Status: string(job.Status), Action: job.Kind, Target: job.ID,
				When: job.CreatedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}
	var audit []activityRow
	err = h.database.Tx(r.Context(), func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(r.Context(), `SELECT action, coalesce(target_kind, ''), coalesce(target_id, ''), created_at
			FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 30`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row activityRow
			var createdAt int64
			if err := rows.Scan(&row.Action, &row.Target, &row.Kind, &createdAt); err != nil {
				return err
			}
			row.Kind = "audit:" + row.Kind
			row.Status = "recorded"
			row.When = time.Unix(createdAt, 0).UTC().Format("2006-01-02 15:04:05")
			audit = append(audit, row)
		}
		return rows.Err()
	})
	if err == nil {
		data.Rows = append(data.Rows, audit...)
	}
	h.render(w, "activity", data)
}

func (h *OperationsHandlers) system(w http.ResponseWriter, r *http.Request) {
	snapshot, err := operations.ReadSnapshot("/proc", "/var/lib")
	data := systemPageData{
		Title: "System · TomPanel", ServerName: h.serverName, CurrentNav: "system",
		Snapshot: snapshot, UpdateState: "read-only", RebootRequired: false, FirewallActive: true,
	}
	if err != nil {
		data.Warning = "Some metrics could not be read on this platform."
	}
	h.render(w, "system", data)
}

func (h *OperationsHandlers) siteLogs(w http.ResponseWriter, r *http.Request) {
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
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "app"
	}
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	data := siteLogsPageData{
		Title: site.PrimaryDomain + " · Logs · TomPanel", ServerName: h.serverName, CurrentNav: "sites",
		CurrentTab: "logs", CSRFToken: session.CSRFToken, Site: site, Source: source, Search: search,
	}
	events, err := h.logs.Read(r.Context(), operations.LogQuery{
		SiteID: site.ID, Domain: site.PrimaryDomain, Source: source, Search: search,
	})
	if err != nil {
		data.Warning = "Logs could not be read: " + err.Error()
	} else {
		data.Events = events
	}
	h.render(w, "site_logs", data)
}
