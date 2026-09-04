package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

func TestSitesTableLinksToOverview(t *testing.T) {
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	site, err := repository.Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "table.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := NewSiteHandlers(authService, repository, panelruntime.NewService(database), nil, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	req := httptest.NewRequest(http.MethodGet, "https://panel.example/sites", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	handlers.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "table.example.com") || !strings.Contains(body, "/sites/"+site.ID) {
		t.Fatalf("site row missing from body: %s", body)
	}
}

func TestCreateSitePersistsSiteAndDurableJob(t *testing.T) {
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	provisioner := sites.NewProvisioner(repository, panelruntime.NewService(database), nil, func(site sites.Site) ([]byte, error) {
		return []byte("# Managed by TomPanel: " + site.ID + "\nserver {}\n"), nil
	})
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	handlers, err := NewSiteHandlers(authService, repository, panelruntime.NewService(database), provisioner, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	recorder := postSiteForm(t, handlers.Handler(), session, "/sites", "kind=php&primary_domain=app.example.com&php_version=8.4")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	items, err := repository.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].PrimaryDomain != "app.example.com" {
		t.Fatalf("sites = %#v", items)
	}
	queued, err := manager.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].Kind != sites.ProvisionJobKind {
		t.Fatalf("jobs = %#v", queued)
	}
	cancel := postSiteForm(t, NewJobsHandlers(database, authService, manager).Handler(), session, "/jobs/"+queued[0].ID+"/cancel", "")
	if cancel.Code != http.StatusConflict {
		t.Fatalf("site job cancel status = %d, want %d", cancel.Code, http.StatusConflict)
	}
}

func postSiteForm(t *testing.T, handler http.Handler, session auth.Session, path, values string) *httptest.ResponseRecorder {
	t.Helper()
	values += "&csrf_token=" + session.CSRFToken
	req := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, strings.NewReader(values))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: session.CSRFToken})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}
