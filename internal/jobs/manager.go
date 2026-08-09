package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

const subscriberBuffer = 8

var (
	ErrNoQueuedJobs = errors.New("no queued jobs")
	ErrJobNotFound  = errors.New("job not found")
	ErrStepFailed   = errors.New("job step failed")
)

type buildFunc func(json.RawMessage) (Definition, error)

type Manager struct {
	store    *store.Store
	redactor *Redactor

	mu          sync.Mutex
	builders    map[string]buildFunc
	definitions map[string]Definition
	subscribers map[string]map[uint64]chan Event
	nextSubID   uint64
}

func NewManager(database *store.Store, redactors ...*Redactor) *Manager {
	redactor := NewRedactor()
	if len(redactors) > 0 && redactors[0] != nil {
		redactor = redactors[0]
	}
	return &Manager{
		store:       database,
		redactor:    redactor,
		builders:    make(map[string]buildFunc),
		definitions: make(map[string]Definition),
		subscribers: make(map[string]map[uint64]chan Event),
	}
}

func (m *Manager) Redactor() *Redactor { return m.redactor }

func (m *Manager) Register(kind string, build func(json.RawMessage) (Definition, error)) error {
	if kind == "" || build == nil {
		return errors.New("job kind and builder are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.builders[kind]; exists {
		return fmt.Errorf("job kind %q is already registered", kind)
	}
	m.builders[kind] = build
	return nil
}

func (m *Manager) Build(kind string, input json.RawMessage) (Definition, error) {
	m.mu.Lock()
	build := m.builders[kind]
	m.mu.Unlock()
	if build == nil {
		return Definition{}, fmt.Errorf("job kind %q is not registered", kind)
	}
	def, err := build(append(json.RawMessage(nil), input...))
	if err != nil {
		return Definition{}, err
	}
	if def.Kind != kind {
		return Definition{}, fmt.Errorf("job builder for %q returned kind %q", kind, def.Kind)
	}
	return def, validateDefinition(def)
}

func (m *Manager) Enqueue(ctx context.Context, def Definition) (string, error) {
	if err := validateDefinition(def); err != nil {
		return "", err
	}
	id, err := newJobID()
	if err != nil {
		return "", err
	}
	input := append(json.RawMessage(nil), def.Input...)
	now := time.Now().UTC().Unix()
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, input_json, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)`, id, def.Kind, []byte(input), StatusQueued, now, now); err != nil {
			return fmt.Errorf("insert job: %w", err)
		}
		for position, step := range def.Steps {
			if _, err := tx.ExecContext(ctx, `INSERT INTO job_steps(job_id, step_key, position, status)
				VALUES (?, ?, ?, ?)`, id, step.Key, position, StepPending); err != nil {
				return fmt.Errorf("insert job step %q: %w", step.Key, err)
			}
		}
		return nil
	}); err != nil {
		return "", err
	}
	def.Input = input
	def.Steps = append([]Step(nil), def.Steps...)
	m.mu.Lock()
	m.definitions[id] = def
	m.mu.Unlock()
	m.broadcast(Event{JobID: id, Status: StatusQueued, UpdatedAt: time.Unix(now, 0).UTC()})
	return id, nil
}

func (m *Manager) ResumeIncomplete(ctx context.Context) error {
	type persisted struct {
		id, kind string
		input    json.RawMessage
		status   Status
	}
	var pending []persisted
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, kind, input_json, status FROM jobs
			WHERE status IN (?, ?, ?, ?) ORDER BY created_at, id`, StatusQueued, StatusRunning, StatusFailed, StatusCancelling)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item persisted
			if err := rows.Scan(&item.id, &item.kind, &item.input, &item.status); err != nil {
				return err
			}
			item.input = append(json.RawMessage(nil), item.input...)
			pending = append(pending, item)
		}
		return rows.Err()
	}); err != nil {
		return fmt.Errorf("list incomplete jobs: %w", err)
	}

	for _, item := range pending {
		if item.status == StatusCancelling {
			if err := m.markCancelled(ctx, item.id); err != nil {
				return err
			}
			continue
		}
		def, err := m.Build(item.kind, item.input)
		if err != nil {
			return fmt.Errorf("rebuild job %s: %w", item.id, err)
		}
		job, err := m.Get(ctx, item.id)
		if err != nil {
			return err
		}
		if err := sameSteps(def.Steps, job.Steps); err != nil {
			return fmt.Errorf("rebuild job %s: %w", item.id, err)
		}
		m.mu.Lock()
		m.definitions[item.id] = def
		m.mu.Unlock()
		if item.status == StatusRunning || item.status == StatusFailed {
			now := time.Now().UTC().Unix()
			if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, error = NULL, finished_at = NULL
					WHERE job_id = ? AND status IN (?, ?)`, StepPending, item.id, StepRunning, StepFailed); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = NULL, updated_at = ?, finished_at = NULL WHERE id = ?`, StatusQueued, now, item.id)
				return err
			}); err != nil {
				return fmt.Errorf("resume job %s: %w", item.id, err)
			}
			m.broadcast(Event{JobID: item.id, Status: StatusQueued, UpdatedAt: time.Unix(now, 0).UTC()})
		}
	}
	return nil
}

func (m *Manager) RunNext(ctx context.Context) error {
	id, updatedAt, err := m.claimNext(ctx)
	if err != nil {
		return err
	}
	m.broadcast(Event{JobID: id, Status: StatusRunning, UpdatedAt: updatedAt})
	def, err := m.definitionFor(ctx, id)
	if err != nil {
		_ = m.failJob(ctx, id, err)
		return err
	}
	job, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := sameSteps(def.Steps, job.Steps); err != nil {
		_ = m.failJob(ctx, id, err)
		return err
	}

	for position, step := range def.Steps {
		if job.Steps[position].Status == StepSucceeded {
			continue
		}
		cancelled, err := m.cancelBetweenSteps(ctx, id)
		if err != nil {
			return err
		}
		if cancelled {
			return nil
		}
		attempt, startedAt, err := m.startStep(ctx, id, step.Key)
		if err != nil {
			return err
		}
		m.broadcast(Event{JobID: id, Status: StatusRunning, StepKey: step.Key, StepStatus: StepRunning, AttemptCount: attempt, UpdatedAt: startedAt})
		result, runErr := step.Run(ctx)
		if runErr != nil {
			message := m.redactor.Redact(runErr.Error())
			failedAt, persistErr := m.finishStepFailure(ctx, id, step.Key, message)
			if persistErr != nil {
				return persistErr
			}
			m.broadcast(Event{JobID: id, Status: StatusFailed, StepKey: step.Key, StepStatus: StepFailed, AttemptCount: attempt, Error: message, UpdatedAt: failedAt})
			return fmt.Errorf("%w: %s: %s", ErrStepFailed, step.Key, message)
		}
		redactedResult := m.redactor.redactJSON(result)
		output := m.redactor.Redact(string(redactedResult))
		finishedAt, err := m.finishStepSuccess(ctx, id, step.Key, redactedResult, output)
		if err != nil {
			return err
		}
		m.broadcast(Event{JobID: id, Status: StatusRunning, StepKey: step.Key, StepStatus: StepSucceeded, AttemptCount: attempt, RedactedOutput: output, UpdatedAt: finishedAt})
	}
	cancelled, err := m.cancelBetweenSteps(ctx, id)
	if err != nil || cancelled {
		return err
	}
	status, finishedAt, err := m.finishJobSuccess(ctx, id)
	if err != nil {
		return err
	}
	m.broadcast(Event{JobID: id, Status: status, UpdatedAt: finishedAt})
	return nil
}

func (m *Manager) Cancel(ctx context.Context, jobID string) error {
	now := time.Now().UTC().Unix()
	var status Status
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrJobNotFound
			}
			return err
		}
		switch status {
		case StatusQueued, StatusFailed:
			status = StatusCancelled
			if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status != ?`, StepCancelled, now, jobID, StepSucceeded); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = NULL, updated_at = ?, finished_at = ? WHERE id = ?`, status, now, now, jobID)
			return err
		case StatusRunning:
			status = StatusCancelling
			_, err := tx.ExecContext(ctx, "UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?", status, now, jobID)
			return err
		case StatusCancelling, StatusSucceeded, StatusCancelled:
			return nil
		default:
			return fmt.Errorf("unknown job status %q", status)
		}
	}); err != nil {
		return err
	}
	m.broadcast(Event{JobID: jobID, Status: status, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) Subscribe(jobID string) (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)
	m.mu.Lock()
	id := m.nextSubID
	m.nextSubID++
	if m.subscribers[jobID] == nil {
		m.subscribers[jobID] = make(map[uint64]chan Event)
	}
	m.subscribers[jobID][id] = ch
	m.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			m.mu.Lock()
			if subscribers := m.subscribers[jobID]; subscribers != nil {
				delete(subscribers, id)
				if len(subscribers) == 0 {
					delete(m.subscribers, jobID)
				}
			}
			close(ch)
			m.mu.Unlock()
		})
	}
}

func (m *Manager) Get(ctx context.Context, jobID string) (Job, error) {
	var job Job
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var input []byte
		var createdAt, updatedAt int64
		var startedAt, finishedAt sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT id, kind, input_json, status, coalesce(error, ''), created_at, updated_at, started_at, finished_at
			FROM jobs WHERE id = ?`, jobID).Scan(&job.ID, &job.Kind, &input, &job.Status, &job.Error, &createdAt, &updatedAt, &startedAt, &finishedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrJobNotFound
			}
			return err
		}
		job.Input = append(json.RawMessage(nil), input...)
		job.CreatedAt = time.Unix(createdAt, 0).UTC()
		job.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		job.StartedAt = nullableTime(startedAt)
		job.FinishedAt = nullableTime(finishedAt)
		rows, err := tx.QueryContext(ctx, `SELECT step_key, position, status, attempt_count, result_json, coalesce(redacted_output, ''), coalesce(error, ''), started_at, finished_at
			FROM job_steps WHERE job_id = ? ORDER BY position`, jobID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var step StepState
			var result []byte
			var stepStarted, stepFinished sql.NullInt64
			if err := rows.Scan(&step.Key, &step.Position, &step.Status, &step.AttemptCount, &result, &step.RedactedOutput, &step.Error, &stepStarted, &stepFinished); err != nil {
				return err
			}
			step.Result = append(json.RawMessage(nil), result...)
			step.StartedAt = nullableTime(stepStarted)
			step.FinishedAt = nullableTime(stepFinished)
			job.Steps = append(job.Steps, step)
		}
		return rows.Err()
	})
	return job, err
}

func (m *Manager) List(ctx context.Context, limit int) ([]Job, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	var ids []string
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id FROM jobs ORDER BY created_at DESC, id DESC LIMIT ?", limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	jobs := make([]Job, 0, len(ids))
	for _, id := range ids {
		job, err := m.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (m *Manager) SnapshotEvent(ctx context.Context, jobID string) (Event, error) {
	job, err := m.Get(ctx, jobID)
	if err != nil {
		return Event{}, err
	}
	event := Event{JobID: job.ID, Status: job.Status, Error: job.Error, UpdatedAt: job.UpdatedAt}
	for index := len(job.Steps) - 1; index >= 0; index-- {
		step := job.Steps[index]
		if step.Status != StepPending {
			event.StepKey = step.Key
			event.StepStatus = step.Status
			event.AttemptCount = step.AttemptCount
			event.RedactedOutput = step.RedactedOutput
			if event.Error == "" {
				event.Error = step.Error
			}
			break
		}
	}
	return event, nil
}

func validateDefinition(def Definition) error {
	if def.Kind == "" {
		return errors.New("job kind is required")
	}
	if len(def.Input) == 0 || !json.Valid(def.Input) {
		return errors.New("job input must be valid JSON")
	}
	seen := make(map[string]bool, len(def.Steps))
	for _, step := range def.Steps {
		if step.Key == "" || step.Run == nil {
			return errors.New("job step key and runner are required")
		}
		if seen[step.Key] {
			return fmt.Errorf("duplicate job step %q", step.Key)
		}
		seen[step.Key] = true
	}
	return nil
}

func sameSteps(definition []Step, persisted []StepState) error {
	if len(definition) != len(persisted) {
		return errors.New("persisted steps do not match registered definition")
	}
	for position, step := range definition {
		if step.Key != persisted[position].Key || persisted[position].Position != position {
			return errors.New("persisted steps do not match registered definition")
		}
	}
	return nil
}

func newJobID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate job ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func nullableTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed := time.Unix(value.Int64, 0).UTC()
	return &parsed
}

func (m *Manager) claimNext(ctx context.Context) (string, time.Time, error) {
	var id string
	now := time.Now().UTC().Unix()
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT id FROM jobs WHERE status = ? ORDER BY created_at, id LIMIT 1", StatusQueued).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNoQueuedJobs
			}
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, started_at = coalesce(started_at, ?), updated_at = ? WHERE id = ? AND status = ?`, StatusRunning, now, now, id, StatusQueued)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrNoQueuedJobs
		}
		return nil
	})
	return id, time.Unix(now, 0).UTC(), err
}

func (m *Manager) definitionFor(ctx context.Context, id string) (Definition, error) {
	m.mu.Lock()
	def, ok := m.definitions[id]
	m.mu.Unlock()
	if ok {
		return def, nil
	}
	job, err := m.Get(ctx, id)
	if err != nil {
		return Definition{}, err
	}
	def, err = m.Build(job.Kind, job.Input)
	if err == nil {
		m.mu.Lock()
		m.definitions[id] = def
		m.mu.Unlock()
	}
	return def, err
}

func (m *Manager) startStep(ctx context.Context, jobID, key string) (int, time.Time, error) {
	now := time.Now().UTC().Unix()
	var attempts int
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, attempt_count = attempt_count + 1, error = NULL, started_at = ?, finished_at = NULL
			WHERE job_id = ? AND step_key = ? AND status != ?`, StepRunning, now, jobID, key, StepSucceeded)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return errors.New("job step could not start")
		}
		if err := tx.QueryRowContext(ctx, "SELECT attempt_count FROM job_steps WHERE job_id = ? AND step_key = ?", jobID, key).Scan(&attempts); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE jobs SET updated_at = ? WHERE id = ?", now, jobID)
		return err
	})
	return attempts, time.Unix(now, 0).UTC(), err
}

func (m *Manager) finishStepSuccess(ctx context.Context, jobID, key string, result json.RawMessage, output string) (time.Time, error) {
	now := time.Now().UTC().Unix()
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, result_json = ?, redacted_output = ?, error = NULL, finished_at = ?
			WHERE job_id = ? AND step_key = ? AND status = ?`, StepSucceeded, []byte(result), output, now, jobID, key, StepRunning); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE jobs SET updated_at = ? WHERE id = ?", now, jobID)
		return err
	})
	return time.Unix(now, 0).UTC(), err
}

func (m *Manager) finishStepFailure(ctx context.Context, jobID, key, message string) (time.Time, error) {
	now := time.Now().UTC().Unix()
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, error = ?, redacted_output = ?, finished_at = ? WHERE job_id = ? AND step_key = ?`, StepFailed, message, message, now, jobID, key); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = ?, updated_at = ?, finished_at = ? WHERE id = ?`, StatusFailed, message, now, now, jobID)
		return err
	})
	return time.Unix(now, 0).UTC(), err
}

func (m *Manager) finishJobSuccess(ctx context.Context, jobID string) (Status, time.Time, error) {
	now := time.Now().UTC().Unix()
	status := StatusSucceeded
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var current Status
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&current); err != nil {
			return err
		}
		switch current {
		case StatusRunning:
			status = StatusSucceeded
		case StatusCancelling:
			status = StatusCancelled
		default:
			return fmt.Errorf("job %s cannot finish from %q", jobID, current)
		}
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = NULL, updated_at = ?, finished_at = ? WHERE id = ?`, status, now, now, jobID)
		return err
	})
	return status, time.Unix(now, 0).UTC(), err
}

func (m *Manager) failJob(ctx context.Context, jobID string, cause error) error {
	message := m.redactor.Redact(cause.Error())
	now := time.Now().UTC().Unix()
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = ?, updated_at = ?, finished_at = ? WHERE id = ?`, StatusFailed, message, now, now, jobID)
		return err
	}); err != nil {
		return err
	}
	m.broadcast(Event{JobID: jobID, Status: StatusFailed, Error: message, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) cancelBetweenSteps(ctx context.Context, jobID string) (bool, error) {
	var status Status
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status)
	}); err != nil {
		return false, err
	}
	if status != StatusCancelling {
		return false, nil
	}
	return true, m.markCancelled(ctx, jobID)
}

func (m *Manager) markCancelled(ctx context.Context, jobID string) error {
	now := time.Now().UTC().Unix()
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status != ?`, StepCancelled, now, jobID, StepSucceeded); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error = NULL, updated_at = ?, finished_at = ? WHERE id = ?`, StatusCancelled, now, now, jobID)
		return err
	}); err != nil {
		return err
	}
	m.broadcast(Event{JobID: jobID, Status: StatusCancelled, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) broadcast(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, subscriber := range m.subscribers[event.JobID] {
		select {
		case subscriber <- event:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- event:
			default:
			}
		}
	}
}
