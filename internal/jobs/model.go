package jobs

import (
	"context"
	"encoding/json"
	"time"
)

type Status string

const (
	StatusQueued     Status = "queued"
	StatusRunning    Status = "running"
	StatusSucceeded  Status = "succeeded"
	StatusFailed     Status = "failed"
	StatusCancelling Status = "cancelling"
	StatusCancelled  Status = "cancelled"
)

type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepSucceeded StepStatus = "succeeded"
	StepFailed    StepStatus = "failed"
	StepCancelled StepStatus = "cancelled"
)

type ErrorCode string

const (
	ErrorAgentInvalidPayload      ErrorCode = "agent_invalid_payload"
	ErrorAgentOperationNotAllowed ErrorCode = "agent_operation_not_allowed"
	ErrorAgentInternal            ErrorCode = "agent_internal_error"
	ErrorAgent                    ErrorCode = "agent_error"
	ErrorContextCancelled         ErrorCode = "context_cancelled"
	ErrorDeadlineExceeded         ErrorCode = "deadline_exceeded"
	ErrorReconciliationRequired   ErrorCode = "reconciliation_required"
	ErrorReconciliationFailed     ErrorCode = "reconciliation_failed"
	ErrorIncompatibleState        ErrorCode = "incompatible_state"
	ErrorInternal                 ErrorCode = "internal_error"
)

type ReconcileOutcome string

const (
	ReconcileSucceeded ReconcileOutcome = "succeeded"
	ReconcileRetry     ReconcileOutcome = "retry"
)

// Reconciliation records whether an interrupted operation already completed or is safe to retry.
type Reconciliation struct {
	Outcome ReconcileOutcome
	Result  json.RawMessage
}

type Step struct {
	Key       string
	Run       func(context.Context) (json.RawMessage, error)
	Reconcile func(context.Context) (Reconciliation, error)
}

type Definition struct {
	Kind  string
	Input json.RawMessage
	Steps []Step
}

type StepState struct {
	Key            string          `json:"key"`
	Position       int             `json:"position"`
	Status         StepStatus      `json:"status"`
	AttemptCount   int             `json:"attempt_count"`
	Result         json.RawMessage `json:"result,omitempty"`
	RedactedOutput string          `json:"redacted_output,omitempty"`
	ErrorCode      ErrorCode       `json:"error_code,omitempty"`
	Error          string          `json:"error,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
}

type Job struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Input      json.RawMessage `json:"input"`
	Status     Status          `json:"status"`
	Revision   int64           `json:"revision"`
	ErrorCode  ErrorCode       `json:"error_code,omitempty"`
	Error      string          `json:"error,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Steps      []StepState     `json:"steps"`
}

type Event struct {
	JobID          string     `json:"job_id"`
	Status         Status     `json:"status"`
	Revision       int64      `json:"revision"`
	StepKey        string     `json:"step_key,omitempty"`
	StepStatus     StepStatus `json:"step_status,omitempty"`
	AttemptCount   int        `json:"attempt_count,omitempty"`
	RedactedOutput string     `json:"redacted_output,omitempty"`
	ErrorCode      ErrorCode  `json:"error_code,omitempty"`
	Error          string     `json:"error,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type WorkerHealth struct {
	Status    string    `json:"status"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
}

type Audit struct {
	AdminID int64
	Action  string
	Detail  json.RawMessage
}
