package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestLoginDoesNotRevealUsername(t *testing.T) {
	svc, _ := seededWebAuth(t)
	handler := NewAuthHandlers(svc).Handler()
	unknown := loginResponseFromIP(t, handler, "nobody", "wrong password", "192.0.2.40:1234")
	known := loginResponseFromIP(t, handler, "admin", "wrong password", "192.0.2.41:1234")
	if unknown.Code != known.Code || unknown.Body.String() != known.Body.String() {
		t.Fatalf("unknown response = (%d, %q), known response = (%d, %q)", unknown.Code, unknown.Body, known.Code, known.Body)
	}
}

func TestPasswordAndSetupTokenAreIgnoredInURLs(t *testing.T) {
	svc, _ := seededWebAuth(t)
	handler := NewAuthHandlers(svc).Handler()
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/login?username=admin&password=correct%20horse%20battery%20staple", nil)
	req.Header.Set("Origin", "https://panel.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("URL credentials status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	unseeded, token := newWebAuth(t)
	query := url.Values{"setup_token": {token}, "username": {"admin"}, "password": {"correct horse battery staple"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.example/setup?"+query.Encode(), nil)
	req.Header.Set("Origin", "https://panel.example")
	recorder = httptest.NewRecorder()
	NewAuthHandlers(unseeded).Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("URL setup token status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestLoginRejectsCrossOrigin(t *testing.T) {
	svc, _ := seededWebAuth(t)
	form := url.Values{"username": {"admin"}, "password": {"correct horse battery staple"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	NewAuthHandlers(svc).Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestLoginTOTPFlowSetsSessionCookies(t *testing.T) {
	svc, recoveryCode := seededWebAuth(t)
	handler := NewAuthHandlers(svc).Handler()
	login := loginResponse(t, handler, "admin", "correct horse battery staple")
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %q", login.Code, login.Body)
	}
	var response struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"challenge": {response.Challenge}, "code": {recoveryCode}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("TOTP status = %d, body = %q", recorder.Code, recorder.Body)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != auth.SessionCookieName || cookies[1].Name != auth.CSRFCookieName {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func loginResponse(t *testing.T, handler http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	return loginResponseFromIP(t, handler, username, password, "192.0.2.50:1234")
}

func loginResponseFromIP(t *testing.T, handler http.Handler, username, password, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://panel.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func seededWebAuth(t *testing.T) (*auth.Service, string) {
	t.Helper()
	svc, token := newWebAuth(t)
	enrollment, err := svc.CompleteSetup(context.Background(), token, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return svc, enrollment.RecoveryCodes[0]
}

func newWebAuth(t *testing.T) (*auth.Service, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.New(s, func() time.Time { return time.Unix(1_800_000_000, 0) })
	token, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return svc, token
}
