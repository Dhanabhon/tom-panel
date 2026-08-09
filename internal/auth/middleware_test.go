package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCSRFRejectsCrossOrigin(t *testing.T) {
	svc, _, secret := seededAuth(t)
	session := login(t, svc, secret)
	handler := svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/settings", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set(CSRFHeader, session.CSRFToken)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: session.CSRFToken})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestCSRFAcceptsSameOriginAndToken(t *testing.T) {
	svc, _, secret := seededAuth(t)
	session := login(t, svc, secret)
	handler := svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := sessionRequest(http.MethodPost, "https://panel.example/settings", session)
	req.Header.Set("Origin", "https://panel.example")
	req.Header.Set(CSRFHeader, session.CSRFToken)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestOriginAcceptsExactLoopbackHTTP(t *testing.T) {
	svc, _, _ := seededAuth(t)
	handler := svc.RequireOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/setup", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8443")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestOriginRejectsPublicHTTP(t *testing.T) {
	svc, _, _ := seededAuth(t)
	handler := svc.RequireOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://panel.example/setup", nil)
	req.Header.Set("Origin", "http://panel.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestCSRFAcceptsExactLoopbackHTTP(t *testing.T) {
	svc, _, secret := seededAuth(t)
	session := login(t, svc, secret)
	handler := svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := sessionRequest(http.MethodPost, "http://127.0.0.1:8443/settings", session)
	req.Header.Set("Origin", "http://127.0.0.1:8443")
	req.Header.Set(CSRFHeader, session.CSRFToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestCSRFRejectsMissingOrigin(t *testing.T) {
	svc, _, secret := seededAuth(t)
	session := login(t, svc, secret)
	handler := svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := sessionRequest(http.MethodPost, "https://panel.example/settings", session)
	req.Header.Set(CSRFHeader, session.CSRFToken)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestStepUpExpiresAfterFiveMinutes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc, _, secret := seededAuthAt(t, &now)
	session := login(t, svc, secret)
	now = now.Add(30 * time.Second)
	if err := svc.StepUp(context.Background(), session.ID, "correct horse battery staple", totpCode(secret, now)); err != nil {
		t.Fatal(err)
	}
	handler := svc.RequireSession(svc.RequireStepUp(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, sessionRequest(http.MethodGet, "https://panel.example/settings", session))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("fresh step-up status = %d", recorder.Code)
	}
	now = now.Add(5 * time.Minute)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, sessionRequest(http.MethodGet, "https://panel.example/settings", session))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expired step-up status = %d", recorder.Code)
	}
}

func TestSessionCookiesAreHostOnlySecureStrict(t *testing.T) {
	recorder := httptest.NewRecorder()
	SetSessionCookies(recorder, Session{ID: "session", CSRFToken: "csrf", AbsoluteExpiresAt: time.Unix(1_800_000_000, 0)})
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	sessionCookie := cookies[0]
	if sessionCookie.Name != SessionCookieName || sessionCookie.Domain != "" || sessionCookie.Path != "/" || !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie attributes = %#v", sessionCookie)
	}
	csrfCookie := cookies[1]
	if csrfCookie.Name != CSRFCookieName || csrfCookie.Domain != "" || csrfCookie.Path != "/" || !csrfCookie.Secure || csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("CSRF cookie attributes = %#v", csrfCookie)
	}
}

func sessionRequest(method, target string, session Session) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: session.CSRFToken})
	return req
}
