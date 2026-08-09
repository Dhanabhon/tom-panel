package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"github.com/Dhanabhon/tom-panel/internal/auth"
)

type AuthHandlers struct {
	auth *auth.Service
	mux  *http.ServeMux
}

func NewAuthHandlers(service *auth.Service) *AuthHandlers {
	h := &AuthHandlers{auth: service, mux: http.NewServeMux()}
	h.mux.Handle("POST /setup", service.RequireOrigin(http.HandlerFunc(h.completeSetup)))
	h.mux.Handle("POST /login", service.RequireOrigin(http.HandlerFunc(h.login)))
	h.mux.Handle("POST /login/totp", service.RequireOrigin(http.HandlerFunc(h.verifyTOTP)))
	h.mux.Handle("POST /logout", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.logout))))
	h.mux.Handle("POST /step-up", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.stepUp))))
	return h
}

func (h *AuthHandlers) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.mux.ServeHTTP(w, r)
	})
}

func (h *AuthHandlers) completeSetup(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	enrollment, err := h.auth.CompleteSetup(r.Context(), r.PostForm.Get("setup_token"), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil {
		writeAuthError(w, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, enrollment)
}

func (h *AuthHandlers) login(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	challenge, err := h.auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"), remoteIP(r.RemoteAddr))
	if err != nil {
		if retry := auth.RetryAfter(err); retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
		}
		writeAuthError(w, http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Challenge string `json:"challenge"`
	}{Challenge: challenge})
}

func (h *AuthHandlers) verifyTOTP(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	session, err := h.auth.VerifyTOTP(r.Context(), r.PostForm.Get("challenge"), r.PostForm.Get("code"))
	if err != nil {
		writeAuthError(w, http.StatusUnauthorized)
		return
	}
	auth.SetSessionCookies(w, session)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandlers) logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(auth.SessionCookieName)
	if cookie != nil {
		_ = h.auth.Logout(r.Context(), cookie.Value)
	}
	auth.ClearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandlers) stepUp(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil || h.auth.StepUp(r.Context(), cookie.Value, r.PostForm.Get("password"), r.PostForm.Get("code")) != nil {
		writeAuthError(w, http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseSmallForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeAuthError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func writeAuthError(w http.ResponseWriter, status int) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: "request could not be completed"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
