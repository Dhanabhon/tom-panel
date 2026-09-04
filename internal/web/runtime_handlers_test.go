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

func TestRuntimePageRendersPersistedPHPSettings(t *testing.T) {
	database, authService, _, recoveryCode := newDashboardRuntime(t)
	site, err := sites.NewRepository(database).Create(context.Background(), sites.CreateInput{
		Kind: sites.KindPHP, PrimaryDomain: "php.example.com", HTTPPort: 80, HTTPSPort: 443, PHPVersion: "8.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeService := panelruntime.NewService(database)
	if err := runtimeService.SaveConfig(context.Background(), site.ID, panelruntime.DefaultPHPConfig("8.4")); err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeHandlers(authService, runtimeService, "test-vps")
	if err != nil {
		t.Fatal(err)
	}
	session := loginDashboardUser(t, authService, recoveryCode)
	request := httptest.NewRequest(http.MethodGet, "/sites/"+site.ID+"/runtime", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "PHP 8.4") || !strings.Contains(response.Body.String(), "256 MB") {
		t.Fatalf("runtime response = %d %q", response.Code, response.Body)
	}
}
