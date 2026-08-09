package auth

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	SessionCookieName = "__Host-tompanel_session"
	CSRFCookieName    = "__Host-tompanel_csrf"
	CSRFHeader        = "X-CSRF-Token"
)

type sessionContextKey struct{}

type requestSession struct {
	record    sessionRecord
	sessionID string
	csrfToken string
}

type SessionInfo struct {
	AdminID     int64
	CSRFToken   string
	StepUpUntil time.Time
}

func CurrentSession(ctx context.Context) (SessionInfo, bool) {
	current, ok := ctx.Value(sessionContextKey{}).(requestSession)
	if !ok {
		return SessionInfo{}, false
	}
	return SessionInfo{AdminID: current.record.adminID, CSRFToken: current.csrfToken, StepUpUntil: current.record.stepUpUntil}, true
}

func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		record, err := s.session(r.Context(), cookie.Value, true)
		if err != nil {
			ClearSessionCookies(w)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		current := requestSession{record: record, sessionID: cookie.Value}
		if csrfCookie, err := r.Cookie(CSRFCookieName); err == nil && csrfMatches(record.csrfHash, csrfCookie.Value) {
			current.csrfToken = csrfCookie.Value
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, current)))
	})
}

func (s *Service) RequireOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameAllowedOrigin(r) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		current, ok := r.Context().Value(sessionContextKey{}).(requestSession)
		if !ok || !sameAllowedOrigin(r) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		token := r.Header.Get(CSRFHeader)
		if token == "" {
			if err := r.ParseForm(); err == nil {
				token = r.PostForm.Get("csrf_token")
			}
		}
		if !csrfMatches(current.record.csrfHash, token) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) RequireStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current, ok := r.Context().Value(sessionContextKey{}).(requestSession)
		if !ok || current.record.stepUpUntil.IsZero() || !s.now().Before(current.record.stepUpUntil) {
			http.Error(w, "recent verification required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func SetSessionCookies(w http.ResponseWriter, session Session) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: session.ID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.AbsoluteExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Value: session.CSRFToken, Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: session.AbsoluteExpiresAt})
}

func ClearSessionCookies(w http.ResponseWriter) {
	expired := time.Unix(1, 0)
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expired, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expired, MaxAge: -1})
}

func csrfMatches(want []byte, token string) bool {
	if token == "" {
		return false
	}
	digest := tokenHash(token)
	return len(want) == len(digest) && subtle.ConstantTimeCompare(want, digest[:]) == 1
}

func sameAllowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" {
		ip := net.ParseIP(parsed.Hostname())
		if scheme != "http" || ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	requestAuthority, err := url.Parse(scheme + "://" + r.Host)
	if err != nil || requestAuthority.Hostname() == "" {
		return false
	}
	originPort := parsed.Port()
	if originPort == "" {
		originPort = defaultPort(scheme)
	}
	requestPort := requestAuthority.Port()
	if requestPort == "" {
		requestPort = defaultPort(scheme)
	}
	return strings.EqualFold(parsed.Hostname(), requestAuthority.Hostname()) && originPort == requestPort
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
