package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

type JobsHandlers struct {
	auth                 *auth.Service
	jobs                 *jobs.Manager
	mux                  *http.ServeMux
	sessionCheckInterval time.Duration
}

func NewJobsHandlers(_ *store.Store, service *auth.Service, manager *jobs.Manager) *JobsHandlers {
	h := &JobsHandlers{auth: service, jobs: manager, mux: http.NewServeMux(), sessionCheckInterval: 15 * time.Second}
	h.mux.Handle("POST /jobs/demo", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.enqueueDemo))))
	h.mux.Handle("POST /jobs/{jobID}/cancel", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.cancel))))
	h.mux.Handle("POST /jobs/{jobID}/retry", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.retry))))
	h.mux.Handle("GET /jobs/{jobID}/events", service.RequireSession(http.HandlerFunc(h.events)))
	return h
}

func (h *JobsHandlers) Handler() http.Handler { return h.mux }

func (h *JobsHandlers) enqueueDemo(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	message := strings.TrimSpace(r.PostForm.Get("message"))
	if message == "" || len(message) > 200 {
		http.Error(w, "message must be between 1 and 200 bytes", http.StatusBadRequest)
		return
	}
	input, err := json.Marshal(struct {
		Message string `json:"message"`
	}{Message: message})
	if err != nil {
		http.Error(w, "job could not be created", http.StatusInternalServerError)
		return
	}
	def, err := h.jobs.Build("demo", input)
	if err != nil {
		http.Error(w, "job could not be created", http.StatusInternalServerError)
		return
	}
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	id, err := h.jobs.EnqueueWithAudit(r.Context(), def, jobs.Audit{
		AdminID: session.AdminID,
		Action:  "job.demo.enqueued",
		Detail:  input,
	})
	if err != nil {
		http.Error(w, "job could not be created", http.StatusInternalServerError)
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/?job="+id, http.StatusSeeOther)
}

func (h *JobsHandlers) cancel(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	jobID := r.PathValue("jobID")
	if err := h.jobs.CancelWithAudit(r.Context(), jobID, jobs.Audit{
		AdminID: session.AdminID,
		Action:  "job.cancel.requested",
		Detail:  json.RawMessage(`{}`),
	}); err != nil {
		switch {
		case errors.Is(err, jobs.ErrJobNotFound):
			http.NotFound(w, r)
		case errors.Is(err, jobs.ErrCancelNotAllowed):
			http.Error(w, "job cannot be cancelled", http.StatusConflict)
		default:
			http.Error(w, "job could not be cancelled", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/?job="+jobID, http.StatusSeeOther)
}

func (h *JobsHandlers) retry(w http.ResponseWriter, r *http.Request) {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	jobID := r.PathValue("jobID")
	if err := h.jobs.RetryWithAudit(r.Context(), jobID, jobs.Audit{
		AdminID: session.AdminID,
		Action:  "job.retry.requested",
		Detail:  json.RawMessage(`{}`),
	}); err != nil {
		switch {
		case errors.Is(err, jobs.ErrJobNotFound):
			http.NotFound(w, r)
		case errors.Is(err, jobs.ErrRetryNotAllowed):
			http.Error(w, "job cannot be retried safely", http.StatusConflict)
		default:
			http.Error(w, "job could not be retried", http.StatusInternalServerError)
		}
		return
	}
	h.jobs.Wake()
	http.Redirect(w, r, "/?job="+jobID, http.StatusSeeOther)
}

func (h *JobsHandlers) events(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")
	events, unsubscribe := h.jobs.Subscribe(jobID)
	defer unsubscribe()
	snapshot, err := h.jobs.SnapshotEvent(r.Context(), jobID)
	if err != nil {
		if errors.Is(err, jobs.ErrJobNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "job stream could not be opened", http.StatusInternalServerError)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if writeSSE(w, snapshot) != nil {
		return
	}
	flusher.Flush()
	lastRevision := snapshot.Revision
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()
	sessionChecks := time.NewTicker(h.sessionCheckInterval)
	defer sessionChecks.Stop()
	sessionCookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if !sseEventAfter(lastRevision, event) {
				continue
			}
			if writeSSE(w, event) != nil {
				return
			}
			lastRevision = event.Revision
			flusher.Flush()
		case <-sessionChecks.C:
			if !h.auth.SessionValidNoTouch(r.Context(), sessionCookie.Value) {
				return
			}
		case <-keepAlive.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func sseEventAfter(revision int64, event jobs.Event) bool {
	return event.Revision > revision
}

func writeSSE(w http.ResponseWriter, event jobs.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: job\ndata: %s\n\n", event.Revision, payload)
	return err
}
