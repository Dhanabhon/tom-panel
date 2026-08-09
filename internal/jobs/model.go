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

type Step struct {
	Key string
	Run func(context.Context) (json.RawMessage, error)
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
	Error          string     `json:"error,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Audit struct {
	AdminID int64
	Action  string
	Detail  json.RawMessage
}
