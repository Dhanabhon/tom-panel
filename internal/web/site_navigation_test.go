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

func navigationRuntime(t *testing.T, kind sites.Kind) (*siteNavHarness, sites.Site) {
	t.Helper()
	database, authService, manager, recoveryCode := newDashboardRuntime(t)
	repository := sites.NewRepository(database)
	input := sites.CreateInput{
		Kind: kind, PrimaryDomain: "nav.example.com", HTTPPort: 80, HTTPSPort: 443,
	}
	if kind == sites.KindPHP {
		input.PHPVersion = "8.3"
	}
	site, err := repository.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := NewSiteHandlers(authService, repository, panelruntime.NewService(database), nil, manager, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	return &siteNavHarness{t: t, handler: handlers.Handler(), session: session}, site
}

type siteNavHarness struct {
	t       *testing.T
	handler http.Handler
	session auth.Session
}

func (h *siteNavHarness) get(path string) string {
	req := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: h.session.ID})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		h.t.Fatalf("GET %s status = %d body=%s", path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func TestSiteNavigationShowsApprovedTabs(t *testing.T) {
	harness, site := navigationRuntime(t, sites.KindPHP)
	body := harness.get("/sites/" + site.ID)
	for _, tab := range []string{"Overview", "Domains &amp; SSL", "Files &amp; Access", "Runtime", "Databases", "Applications", "Backups", "Logs"} {
		if !strings.Contains(body, tab) {
			t.Fatalf("overview missing tab %q", tab)
		}
	}
	if !strings.Contains(body, `href="/sites/`+site.ID+`/files"`) {
		t.Fatal("files tab not linked")
	}
	if !strings.Contains(body, `href="/sites/`+site.ID+`/applications"`) {
		t.Fatal("applications tab not linked")
	}
	// Future slices render as clearly unavailable, never as working links.
	if strings.Contains(body, `href="/sites/`+site.ID+`/backups"`) || strings.Contains(body, `href="/sites/`+site.ID+`/logs"`) {
		t.Fatal("backups or logs tab rendered as a working link")
	}
}

func TestStaticSiteHidesApplicationMutationControls(t *testing.T) {
	harness, site := navigationRuntime(t, sites.KindStatic)
	body := harness.get("/sites/" + site.ID + "/applications")
	if strings.Contains(body, "Install WordPress") || strings.Contains(body, "Deploy Laravel") {
		t.Fatal("misleading controls rendered")
	}
	if !strings.Contains(body, "Application installers are available for PHP sites") {
		t.Fatalf("static empty state missing: %s", body)
	}
}

func TestPHPSiteApplicationsPageOffersInstallers(t *testing.T) {
	harness, site := navigationRuntime(t, sites.KindPHP)
	body := harness.get("/sites/" + site.ID + "/applications")
	if !strings.Contains(body, "Install WordPress") || !strings.Contains(body, "Deploy Laravel") {
		t.Fatal("php site missing installer entries")
	}
}

func TestTabsMarkActiveSection(t *testing.T) {
	harness, site := navigationRuntime(t, sites.KindPHP)
	body := harness.get("/sites/" + site.ID)
	if !strings.Contains(body, `class="tab active" aria-current="page" href="/sites/`+site.ID+"\"") {
		t.Fatal("overview tab not marked active")
	}
	if strings.Contains(body, `aria-current="page" href="/sites/`+site.ID+`/files"`) {
		t.Fatal("inactive tab marked current")
	}
}
