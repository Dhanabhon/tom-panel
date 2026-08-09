package web

import (
	"context"
	"database/sql"
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
	store *store.Store
	jobs  *jobs.Manager
	mux   *http.ServeMux
}

func NewJobsHandlers(database *store.Store, service *auth.Service, manager *jobs.Manager) *JobsHandlers {
	h := &JobsHandlers{store: database, jobs: manager, mux: http.NewServeMux()}
	h.mux.Handle("POST /jobs/demo", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.enqueueDemo))))
	h.mux.Handle("POST /jobs/{jobID}/cancel", service.RequireSession(service.RequireCSRF(http.HandlerFunc(h.cancel))))
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
	id, err := h.jobs.Enqueue(r.Context(), def)
	if err != nil {
		http.Error(w, "job could not be created", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), r, "job.demo.enqueued", id, input); err != nil {
		http.Error(w, "job audit event could not be recorded", http.StatusInternalServerError)
		return
	}
	go h.runQueued()
	http.Redirect(w, r, "/?job="+id, http.StatusSeeOther)
}

func (h *JobsHandlers) cancel(w http.ResponseWriter, r *http.Request) {
	if err := h.jobs.Cancel(r.Context(), r.PathValue("jobID")); err != nil {
		if errors.Is(err, jobs.ErrJobNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "job could not be cancelled", http.StatusInternalServerError)
		return
	}
	if err := h.recordAudit(r.Context(), r, "job.cancel.requested", r.PathValue("jobID"), json.RawMessage(`{}`)); err != nil {
		http.Error(w, "job audit event could not be recorded", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/?job="+r.PathValue("jobID"), http.StatusSeeOther)
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
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok || writeSSE(w, event) != nil {
				return
			}
			flusher.Flush()
		case <-keepAlive.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (h *JobsHandlers) recordAudit(ctx context.Context, r *http.Request, action, targetID string, detail json.RawMessage) error {
	session, ok := auth.CurrentSession(r.Context())
	if !ok {
		return auth.ErrInvalidSession
	}
	redactedDetail := h.jobs.Redactor().RedactJSON(detail)
	return h.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(admin_id, action, target_kind, target_id, detail_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, session.AdminID, action, "job", targetID, []byte(redactedDetail), time.Now().UTC().Unix())
		return err
	})
}

func (h *JobsHandlers) runQueued() {
	for {
		err := h.jobs.RunNext(context.Background())
		if errors.Is(err, jobs.ErrNoQueuedJobs) {
			return
		}
		if err != nil && !errors.Is(err, jobs.ErrStepFailed) {
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, event jobs.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: job\ndata: %s\n\n", payload)
	return err
}
