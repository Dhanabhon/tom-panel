package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/domains"
	"github.com/Dhanabhon/tom-panel/internal/sites"
)

func TestDomainsPageRequiresSessionAndRendersOwnedHostname(t *testing.T) {
	database, authService, _, recoveryCode := newDashboardRuntime(t)
	site, err := sites.NewRepository(database).Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "site.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	domainService := domains.NewService(database, nil)
	if _, err := domainService.AddHostname(context.Background(), site.ID, "www.site.example.com", 443); err != nil {
		t.Fatal(err)
	}
	handler, err := NewDomainHandlers(authService, domainService, "test-vps")
	if err != nil {
		t.Fatal(err)
	}

	unauthenticated := httptest.NewRecorder()
	handler.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/domains", nil))
	if unauthenticated.Code != http.StatusSeeOther || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated response = %d Location %q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}

	session := loginDashboardUser(t, authService, recoveryCode)
	request := httptest.NewRequest(http.MethodGet, "/domains", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "www.site.example.com") {
		t.Fatalf("authenticated response = %d %q", response.Code, response.Body)
	}
}
