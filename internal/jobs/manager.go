package jobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

const (
	subscriberBuffer = 8
	workerBackoffMin = 10 * time.Millisecond
	workerBackoffMax = 250 * time.Millisecond
)

var (
	ErrNoQueuedJobs     = errors.New("no queued jobs")
	ErrJobNotFound      = errors.New("job not found")
	ErrStepFailed       = errors.New("job step failed")
	ErrCancelNotAllowed = errors.New("job cannot be cancelled")
	ErrRetryNotAllowed  = errors.New("job cannot be retried")
	errJobCancelled     = errors.New("job cancelled before step start")
	errQuarantined      = errors.New("job quarantined")
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

	workerMu     sync.Mutex
	workerWake   chan struct{}
	workerCancel context.CancelFunc
	workerDone   chan struct{}
	workerHealth WorkerHealth
}

func NewManager(database *store.Store, redactors ...*Redactor) *Manager {
	redactor := NewRedactor()
	if len(redactors) > 0 && redactors[0] != nil {
		redactor = redactors[0]
	}
	return &Manager{
		store:        database,
		redactor:     redactor,
		builders:     make(map[string]buildFunc),
		definitions:  make(map[string]Definition),
		subscribers:  make(map[string]map[uint64]chan Event),
		workerWake:   make(chan struct{}, 1),
		workerHealth: WorkerHealth{Status: "ok"},
	}
}

func (m *Manager) Redactor() *Redactor { return m.redactor }

func (m *Manager) WorkerHealth() WorkerHealth {
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	return m.workerHealth
}

func (m *Manager) setWorkerHealth(health WorkerHealth) {
	m.workerMu.Lock()
	m.workerHealth = health
	m.workerMu.Unlock()
}

func (m *Manager) clearTransientWorkerHealth() {
	m.workerMu.Lock()
	if m.workerHealth.ErrorCode == ErrorInternal {
		m.workerHealth = WorkerHealth{Status: "ok"}
	}
	m.workerMu.Unlock()
}

func (m *Manager) Start(ctx context.Context) error {
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.workerCancel != nil {
		return errors.New("job worker is already running")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.workerCancel = cancel
	m.workerDone = done
	go m.runWorker(workerCtx, done)
	m.wakeLocked()
	return nil
}

func (m *Manager) Wake() {
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	m.wakeLocked()
}

func (m *Manager) wakeLocked() {
	select {
	case m.workerWake <- struct{}{}:
	default:
	}
}

func (m *Manager) Stop() {
	m.workerMu.Lock()
	cancel, done := m.workerCancel, m.workerDone
	if cancel == nil {
		m.workerMu.Unlock()
		return
	}
	cancel()
	m.workerMu.Unlock()
	<-done
	m.workerMu.Lock()
	if m.workerDone == done {
		m.workerCancel = nil
		m.workerDone = nil
	}
	m.workerMu.Unlock()
}

func (m *Manager) runWorker(ctx context.Context, done chan struct{}) {
	defer close(done)
	backoff := workerBackoffMin
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.workerWake:
		}
		for {
			err := m.RunNext(ctx)
			if errors.Is(err, ErrNoQueuedJobs) {
				m.clearTransientWorkerHealth()
				break
			}
			if ctx.Err() != nil {
				return
			}
			switch {
			case err == nil, errors.Is(err, ErrStepFailed):
				m.setWorkerHealth(WorkerHealth{Status: "ok"})
				backoff = workerBackoffMin
				continue
			case errors.Is(err, errQuarantined):
				backoff = workerBackoffMin
				continue
			default:
				m.setWorkerHealth(WorkerHealth{Status: "degraded", ErrorCode: ErrorInternal})
				for {
					timer := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
					if backoff < workerBackoffMax {
						backoff *= 2
						if backoff > workerBackoffMax {
							backoff = workerBackoffMax
						}
					}
					if recoveryErr := m.ResumeIncomplete(ctx); recoveryErr == nil {
						break
					}
					if ctx.Err() != nil {
						return
					}
				}
			}
		}
	}
}

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
	input = append(json.RawMessage(nil), input...)
	def, err := build(input)
	if err != nil {
		return Definition{}, err
	}
	if def.Kind != kind {
		return Definition{}, fmt.Errorf("job builder for %q returned kind %q", kind, def.Kind)
	}
	if !bytes.Equal(def.Input, input) {
		return Definition{}, errors.New("job builder changed immutable input")
	}
	return def, validateDefinition(def)
}

func (m *Manager) Enqueue(ctx context.Context, def Definition) (string, error) {
	return m.enqueue(ctx, def, nil)
}

func (m *Manager) EnqueueWithAudit(ctx context.Context, def Definition, audit Audit) (string, error) {
	return m.enqueue(ctx, def, &audit)
}

func (m *Manager) enqueue(ctx context.Context, def Definition, audit *Audit) (string, error) {
	if err := validateDefinition(def); err != nil {
		return "", err
	}
	input := m.redactor.RedactJSON(def.Input)
	rebuilt, err := m.Build(def.Kind, input)
	if err != nil {
		return "", err
	}
	if err := sameStepLayout(def.Steps, rebuilt.Steps); err != nil {
		return "", err
	}
	if audit != nil {
		if err := validateAudit(*audit); err != nil {
			return "", err
		}
	}
	id, err := newJobID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Unix()
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, input_json, status, revision, created_at, updated_at)
			VALUES (?, ?, ?, ?, 1, ?, ?)`, id, rebuilt.Kind, []byte(input), StatusQueued, now, now); err != nil {
			return fmt.Errorf("insert job: %w", err)
		}
		for position, step := range rebuilt.Steps {
			if _, err := tx.ExecContext(ctx, `INSERT INTO job_steps(job_id, step_key, position, status)
				VALUES (?, ?, ?, ?)`, id, step.Key, position, StepPending); err != nil {
				return fmt.Errorf("insert job step %q: %w", step.Key, err)
			}
		}
		if audit != nil {
			if err := m.insertAuditTx(ctx, tx, id, *audit, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", err
	}
	rebuilt.Input = append(json.RawMessage(nil), input...)
	rebuilt.Steps = append([]Step(nil), rebuilt.Steps...)
	m.mu.Lock()
	m.definitions[id] = rebuilt
	m.mu.Unlock()
	m.broadcast(Event{JobID: id, Status: StatusQueued, Revision: 1, UpdatedAt: time.Unix(now, 0).UTC()})
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
			WHERE status IN (?, ?, ?) ORDER BY created_at, id`, StatusQueued, StatusRunning, StatusCancelling)
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
			if quarantineErr := m.quarantineJob(ctx, item.id, ErrorIncompatibleState, fmt.Errorf("rebuild job: %w", err)); quarantineErr != nil {
				return fmt.Errorf("quarantine incompatible job %s: %w", item.id, quarantineErr)
			}
			continue
		}
		job, err := m.Get(ctx, item.id)
		if err != nil {
			return err
		}
		if err := sameSteps(def.Steps, job.Steps); err != nil {
			if quarantineErr := m.quarantineJob(ctx, item.id, ErrorIncompatibleState, err); quarantineErr != nil {
				return fmt.Errorf("quarantine incompatible job %s: %w", item.id, quarantineErr)
			}
			continue
		}
		m.mu.Lock()
		m.definitions[item.id] = def
		m.mu.Unlock()
		if item.status == StatusRunning {
			if err := m.reconcileRunning(ctx, item.id, def, job); err != nil && !errors.Is(err, errQuarantined) {
				return fmt.Errorf("reconcile job %s: %w", item.id, err)
			}
		}
	}
	return nil
}

func (m *Manager) reconcileRunning(ctx context.Context, jobID string, def Definition, job Job) error {
	running := -1
	for position, step := range job.Steps {
		switch step.Status {
		case StepRunning:
			if running >= 0 {
				if err := m.quarantineJob(ctx, jobID, ErrorIncompatibleState, errors.New("multiple interrupted steps")); err != nil {
					return err
				}
				return errQuarantined
			}
			running = position
		case StepFailed, StepCancelled:
			if err := m.quarantineJob(ctx, jobID, ErrorIncompatibleState, fmt.Errorf("running job contains %s step", step.Status)); err != nil {
				return err
			}
			return errQuarantined
		}
	}
	if running < 0 {
		return m.queueRecoveredJob(ctx, jobID, "", Reconciliation{Outcome: ReconcileRetry})
	}
	step := def.Steps[running]
	if step.Reconcile == nil {
		if err := m.quarantineJob(ctx, jobID, ErrorReconciliationRequired, fmt.Errorf("interrupted step %q requires reconciliation", step.Key)); err != nil {
			return err
		}
		return errQuarantined
	}
	reconciliation, err := step.Reconcile(ctx)
	if err != nil {
		if quarantineErr := m.quarantineJob(ctx, jobID, reconciliationErrorCode(err), err); quarantineErr != nil {
			return quarantineErr
		}
		return errQuarantined
	}
	switch reconciliation.Outcome {
	case ReconcileRetry, ReconcileSucceeded:
		return m.queueRecoveredJob(ctx, jobID, step.Key, reconciliation)
	default:
		if err := m.quarantineJob(ctx, jobID, ErrorReconciliationFailed, errors.New("reconciliation returned an invalid outcome")); err != nil {
			return err
		}
		return errQuarantined
	}
}

func (m *Manager) queueRecoveredJob(ctx context.Context, jobID, stepKey string, reconciliation Reconciliation) error {
	now := time.Now().UTC().Unix()
	var revision int64
	var stepStatus StepStatus
	var output string
	var result json.RawMessage
	if stepKey != "" {
		stepStatus = StepPending
		if reconciliation.Outcome == ReconcileSucceeded {
			stepStatus = StepSucceeded
			result = m.redactor.RedactJSON(reconciliation.Result)
			output = string(result)
		}
	}
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		jobResult, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = NULL, revision = revision + 1
			WHERE id = ? AND status = ?`, StatusQueued, now, jobID, StatusRunning)
		if err != nil {
			return err
		}
		if changed, _ := jobResult.RowsAffected(); changed != 1 {
			var status Status
			if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
				return err
			}
			if status == StatusCancelling || status == StatusCancelled {
				return errJobCancelled
			}
			return fmt.Errorf("job %s recovery state changed to %q", jobID, status)
		}
		if stepKey != "" {
			switch reconciliation.Outcome {
			case ReconcileRetry:
				result, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, result_json = NULL, redacted_output = NULL, error_code = NULL, error = NULL, finished_at = NULL
					WHERE job_id = ? AND step_key = ? AND status = ?`, StepPending, jobID, stepKey, StepRunning)
				if err != nil {
					return err
				}
				if changed, _ := result.RowsAffected(); changed != 1 {
					return errors.New("interrupted step state changed during recovery")
				}
			case ReconcileSucceeded:
				result, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, result_json = ?, redacted_output = ?, error_code = NULL, error = NULL, finished_at = ?
					WHERE job_id = ? AND step_key = ? AND status = ?`, StepSucceeded, []byte(result), output, now, jobID, stepKey, StepRunning)
				if err != nil {
					return err
				}
				if changed, _ := result.RowsAffected(); changed != 1 {
					return errors.New("interrupted step state changed during recovery")
				}
			}
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	}); err != nil {
		if errors.Is(err, errJobCancelled) {
			return m.markCancelled(ctx, jobID)
		}
		return err
	}
	m.broadcast(Event{JobID: jobID, Status: StatusQueued, Revision: revision, StepKey: stepKey, StepStatus: stepStatus, RedactedOutput: output, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) RunNext(ctx context.Context) error {
	id, _, err := m.claimNext(ctx)
	if err != nil {
		return err
	}
	def, err := m.definitionFor(ctx, id)
	if err != nil {
		if quarantineErr := m.quarantineJob(ctx, id, ErrorIncompatibleState, err); quarantineErr != nil {
			return quarantineErr
		}
		return errQuarantined
	}
	job, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := sameSteps(def.Steps, job.Steps); err != nil {
		if quarantineErr := m.quarantineJob(ctx, id, ErrorIncompatibleState, err); quarantineErr != nil {
			return quarantineErr
		}
		return errQuarantined
	}

	for position, step := range def.Steps {
		if job.Steps[position].Status == StepSucceeded {
			continue
		}
		attempt, _, err := m.startStep(ctx, id, step.Key)
		if errors.Is(err, errJobCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		result, runErr := step.Run(ctx)
		if runErr != nil {
			message := m.redactor.Redact(runErr.Error())
			code := failureCode(runErr)
			status, failedAt, revision, persistErr := m.finishStepFailure(ctx, id, step.Key, code, message)
			if persistErr != nil {
				return persistErr
			}
			m.broadcast(Event{JobID: id, Status: status, Revision: revision, StepKey: step.Key, StepStatus: StepFailed, AttemptCount: attempt, ErrorCode: code, Error: message, UpdatedAt: failedAt})
			return fmt.Errorf("%w: %s: %s", ErrStepFailed, step.Key, message)
		}
		redactedResult := m.redactor.redactJSON(result)
		output := string(redactedResult)
		finishedAt, revision, err := m.finishStepSuccess(ctx, id, step.Key, redactedResult, output)
		if err != nil {
			return err
		}
		m.broadcast(Event{JobID: id, Status: StatusRunning, Revision: revision, StepKey: step.Key, StepStatus: StepSucceeded, AttemptCount: attempt, RedactedOutput: output, UpdatedAt: finishedAt})
	}
	status, finishedAt, revision, err := m.finishJobSuccess(ctx, id)
	if err != nil {
		return err
	}
	m.broadcast(Event{JobID: id, Status: status, Revision: revision, UpdatedAt: finishedAt})
	return nil
}

func (m *Manager) Cancel(ctx context.Context, jobID string) error {
	_, err := m.cancel(ctx, jobID, nil)
	return err
}

func (m *Manager) CancelWithAudit(ctx context.Context, jobID string, audit Audit) error {
	_, err := m.cancel(ctx, jobID, &audit)
	return err
}

func (m *Manager) RetryWithAudit(ctx context.Context, jobID string, audit Audit) error {
	if err := validateAudit(audit); err != nil {
		return err
	}
	job, err := m.Get(ctx, jobID)
	if err != nil {
		return err
	}
	if job.Status != StatusFailed || !retryableFailure(job.ErrorCode) {
		return ErrRetryNotAllowed
	}
	def, err := m.Build(job.Kind, job.Input)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRetryNotAllowed, err)
	}
	if err := sameSteps(def.Steps, job.Steps); err != nil {
		return fmt.Errorf("%w: %v", ErrRetryNotAllowed, err)
	}
	now := time.Now().UTC().Unix()
	var revision int64
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = NULL, revision = revision + 1
			WHERE id = ? AND status = ?`, StatusQueued, now, jobID, StatusFailed)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrRetryNotAllowed
		}
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, result_json = NULL, redacted_output = NULL, error_code = NULL, error = NULL, finished_at = NULL
			WHERE job_id = ? AND status = ?`, StepPending, jobID, StepFailed); err != nil {
			return err
		}
		if err := m.insertAuditTx(ctx, tx, jobID, audit, now); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	}); err != nil {
		return err
	}
	m.mu.Lock()
	m.definitions[jobID] = def
	m.mu.Unlock()
	m.broadcast(Event{JobID: jobID, Status: StatusQueued, Revision: revision, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) cancel(ctx context.Context, jobID string, audit *Audit) (bool, error) {
	if audit != nil {
		if err := validateAudit(*audit); err != nil {
			return false, err
		}
	}
	now := time.Now().UTC().Unix()
	var status Status
	var revision int64
	changed := false
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrJobNotFound
			}
			return err
		}
		switch status {
		case StatusQueued:
			status = StatusCancelled
			if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status != ?`, StepCancelled, now, jobID, StepSucceeded); err != nil {
				return err
			}
			changed = true
		case StatusRunning:
			status = StatusCancelling
			changed = true
		case StatusFailed:
			return ErrCancelNotAllowed
		case StatusCancelling, StatusSucceeded, StatusCancelled:
			return nil
		default:
			return fmt.Errorf("unknown job status %q", status)
		}
		finishedAt := any(nil)
		if status == StatusCancelled {
			finishedAt = now
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = coalesce(?, finished_at), revision = revision + 1 WHERE id = ?`, status, now, finishedAt, jobID); err != nil {
			return err
		}
		if audit != nil {
			if err := m.insertAuditTx(ctx, tx, jobID, *audit, now); err != nil {
				return err
			}
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	}); err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	m.broadcast(Event{JobID: jobID, Status: status, Revision: revision, UpdatedAt: time.Unix(now, 0).UTC()})
	return true, nil
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
		if err := tx.QueryRowContext(ctx, `SELECT id, kind, input_json, status, revision, coalesce(error_code, ''), coalesce(error, ''), created_at, updated_at, started_at, finished_at
			FROM jobs WHERE id = ?`, jobID).Scan(&job.ID, &job.Kind, &input, &job.Status, &job.Revision, &job.ErrorCode, &job.Error, &createdAt, &updatedAt, &startedAt, &finishedAt); err != nil {
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
		rows, err := tx.QueryContext(ctx, `SELECT step_key, position, status, attempt_count, result_json, coalesce(redacted_output, ''), coalesce(error_code, ''), coalesce(error, ''), started_at, finished_at
			FROM job_steps WHERE job_id = ? ORDER BY position`, jobID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var step StepState
			var result []byte
			var stepStarted, stepFinished sql.NullInt64
			if err := rows.Scan(&step.Key, &step.Position, &step.Status, &step.AttemptCount, &result, &step.RedactedOutput, &step.ErrorCode, &step.Error, &stepStarted, &stepFinished); err != nil {
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
	event := Event{JobID: job.ID, Status: job.Status, Revision: job.Revision, ErrorCode: job.ErrorCode, Error: job.Error, UpdatedAt: job.UpdatedAt}
	for index := len(job.Steps) - 1; index >= 0; index-- {
		step := job.Steps[index]
		if step.Status != StepPending {
			event.StepKey = step.Key
			event.StepStatus = step.Status
			event.AttemptCount = step.AttemptCount
			event.RedactedOutput = step.RedactedOutput
			if event.Error == "" {
				event.ErrorCode = step.ErrorCode
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

func sameStepLayout(left, right []Step) error {
	if len(left) != len(right) {
		return errors.New("job definition does not match registered step layout")
	}
	for index := range left {
		if left[index].Key != right[index].Key {
			return errors.New("job definition does not match registered step layout")
		}
	}
	return nil
}

func validateAudit(audit Audit) error {
	if audit.AdminID < 1 || audit.Action == "" {
		return errors.New("audit administrator and action are required")
	}
	if len(audit.Detail) == 0 {
		audit.Detail = json.RawMessage(`{}`)
	}
	if !json.Valid(audit.Detail) {
		return errors.New("audit detail must be valid JSON")
	}
	return nil
}

func (m *Manager) insertAuditTx(ctx context.Context, tx *sql.Tx, jobID string, audit Audit, now int64) error {
	detail := audit.Detail
	if len(detail) == 0 {
		detail = json.RawMessage(`{}`)
	}
	detail = m.redactor.RedactJSON(detail)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(admin_id, action, target_kind, target_id, detail_json, created_at)
		VALUES (?, ?, 'job', ?, ?, ?)`, audit.AdminID, audit.Action, jobID, []byte(detail), now); err != nil {
		return fmt.Errorf("insert job audit: %w", err)
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
	var revision int64
	now := time.Now().UTC().Unix()
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT id FROM jobs WHERE status = ? ORDER BY created_at, id LIMIT 1", StatusQueued).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNoQueuedJobs
			}
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, started_at = coalesce(started_at, ?), updated_at = ?, revision = revision + 1 WHERE id = ? AND status = ?`, StatusRunning, now, now, id, StatusQueued)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrNoQueuedJobs
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", id).Scan(&revision)
	})
	updatedAt := time.Unix(now, 0).UTC()
	if err == nil {
		m.broadcast(Event{JobID: id, Status: StatusRunning, Revision: revision, UpdatedAt: updatedAt})
	}
	return id, updatedAt, err
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
	var revision int64
	cancelled := false
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var status Status
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
			return err
		}
		if status == StatusCancelling {
			cancelled = true
			if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status != ?`, StepCancelled, now, jobID, StepSucceeded); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = ?, revision = revision + 1 WHERE id = ?`, StatusCancelled, now, now, jobID); err != nil {
				return err
			}
			return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
		}
		if status != StatusRunning {
			return fmt.Errorf("job %s cannot start a step from %q", jobID, status)
		}
		result, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, attempt_count = attempt_count + 1, error_code = NULL, error = NULL, started_at = ?, finished_at = NULL
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
		if _, err := tx.ExecContext(ctx, "UPDATE jobs SET updated_at = ?, revision = revision + 1 WHERE id = ? AND status = ?", now, jobID, StatusRunning); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	})
	updatedAt := time.Unix(now, 0).UTC()
	if err != nil {
		return 0, updatedAt, err
	}
	if cancelled {
		m.broadcast(Event{JobID: jobID, Status: StatusCancelled, Revision: revision, UpdatedAt: updatedAt})
		return 0, updatedAt, errJobCancelled
	}
	m.broadcast(Event{JobID: jobID, Status: StatusRunning, Revision: revision, StepKey: key, StepStatus: StepRunning, AttemptCount: attempts, UpdatedAt: updatedAt})
	return attempts, updatedAt, nil
}

func (m *Manager) finishStepSuccess(ctx context.Context, jobID, key string, result json.RawMessage, output string) (time.Time, int64, error) {
	now := time.Now().UTC().Unix()
	var revision int64
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, result_json = ?, redacted_output = ?, error_code = NULL, error = NULL, finished_at = ?
			WHERE job_id = ? AND step_key = ? AND status = ?`, StepSucceeded, []byte(result), output, now, jobID, key, StepRunning); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE jobs SET updated_at = ?, revision = revision + 1 WHERE id = ?", now, jobID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	})
	return time.Unix(now, 0).UTC(), revision, err
}

func (m *Manager) finishStepFailure(ctx context.Context, jobID, key string, code ErrorCode, message string) (Status, time.Time, int64, error) {
	now := time.Now().UTC().Unix()
	status := StatusFailed
	var revision int64
	err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var current Status
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&current); err != nil {
			return err
		}
		switch current {
		case StatusRunning:
			status = StatusFailed
		case StatusCancelling:
			status = StatusCancelled
		default:
			return fmt.Errorf("job %s cannot fail a step from %q", jobID, current)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, error_code = ?, error = ?, redacted_output = ?, finished_at = ? WHERE job_id = ? AND step_key = ?`, StepFailed, code, message, message, now, jobID, key); err != nil {
			return err
		}
		if status == StatusCancelled {
			if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status = ?`, StepCancelled, now, jobID, StepPending); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = ?, error = ?, updated_at = ?, finished_at = ?, revision = revision + 1 WHERE id = ?`, status, code, message, now, now, jobID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	})
	return status, time.Unix(now, 0).UTC(), revision, err
}

func (m *Manager) finishJobSuccess(ctx context.Context, jobID string) (Status, time.Time, int64, error) {
	now := time.Now().UTC().Unix()
	status := StatusSucceeded
	var revision int64
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
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = ?, revision = revision + 1 WHERE id = ?`, status, now, now, jobID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	})
	return status, time.Unix(now, 0).UTC(), revision, err
}

func (m *Manager) quarantineJob(ctx context.Context, jobID string, code ErrorCode, cause error) error {
	message := m.redactor.Redact(cause.Error())
	now := time.Now().UTC().Unix()
	var revision int64
	changed := false
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var status Status
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
			return err
		}
		switch status {
		case StatusCancelling, StatusCancelled:
			return errJobCancelled
		case StatusQueued, StatusRunning:
		case StatusFailed, StatusSucceeded:
			return nil
		default:
			return fmt.Errorf("job %s cannot be quarantined from %q", jobID, status)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, error_code = ?, error = ?, redacted_output = ?, finished_at = ?
			WHERE job_id = ? AND status IN (?, ?)`, StepFailed, code, message, message, now, jobID, StepPending, StepRunning); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = ?, error = ?, updated_at = ?, finished_at = ?, revision = revision + 1
			WHERE id = ? AND status IN (?, ?)`, StatusFailed, code, message, now, now, jobID, StatusQueued, StatusRunning)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return errors.New("job quarantine state changed")
		}
		changed = true
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	}); err != nil {
		if errors.Is(err, errJobCancelled) {
			return m.markCancelled(ctx, jobID)
		}
		return err
	}
	if !changed {
		return nil
	}
	m.setWorkerHealth(WorkerHealth{Status: "degraded", ErrorCode: code})
	m.broadcast(Event{JobID: jobID, Status: StatusFailed, Revision: revision, ErrorCode: code, Error: message, UpdatedAt: time.Unix(now, 0).UTC()})
	return nil
}

func (m *Manager) markCancelled(ctx context.Context, jobID string) error {
	now := time.Now().UTC().Unix()
	var revision int64
	changed := false
	if err := m.store.Tx(ctx, func(tx *sql.Tx) error {
		var status Status
		if err := tx.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = ?", jobID).Scan(&status); err != nil {
			return err
		}
		if status != StatusCancelling {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ? WHERE job_id = ? AND status != ?`, StepCancelled, now, jobID, StepSucceeded); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, error_code = NULL, error = NULL, updated_at = ?, finished_at = ?, revision = revision + 1 WHERE id = ? AND status = ?`, StatusCancelled, now, now, jobID, StatusCancelling); err != nil {
			return err
		}
		changed = true
		return tx.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id = ?", jobID).Scan(&revision)
	}); err != nil {
		return err
	}
	if changed {
		m.broadcast(Event{JobID: jobID, Status: StatusCancelled, Revision: revision, UpdatedAt: time.Unix(now, 0).UTC()})
	}
	return nil
}

func failureCode(err error) ErrorCode {
	var agentErr *agentapi.Error
	if errors.As(err, &agentErr) {
		switch agentErr.Code {
		case "invalid_payload":
			return ErrorAgentInvalidPayload
		case "operation_not_allowed":
			return ErrorAgentOperationNotAllowed
		case "internal_error":
			return ErrorAgentInternal
		default:
			return ErrorAgent
		}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return ErrorContextCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorDeadlineExceeded
	default:
		return ErrorInternal
	}
}

func reconciliationErrorCode(_ error) ErrorCode {
	return ErrorReconciliationFailed
}

func retryableFailure(code ErrorCode) bool {
	switch code {
	case ErrorReconciliationRequired, ErrorReconciliationFailed, ErrorIncompatibleState:
		return false
	default:
		return true
	}
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
