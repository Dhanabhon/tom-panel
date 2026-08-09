package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestRetryStartsAtFirstIncompleteStep(t *testing.T) {
	m, attempts := newTestManager(t, []Step{pass("one"), failOnce("two"), pass("three")})
	id := enqueueAndRun(t, m)
	seedAuditAdmin(t, m.store)
	if err := m.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNext(context.Background()); !errors.Is(err, ErrNoQueuedJobs) {
		t.Fatalf("failed job ran without explicit retry: %v", err)
	}
	if err := m.RetryWithAudit(context.Background(), id, Audit{AdminID: 1, Action: "job.retry.requested", Detail: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAttempts(t, attempts, map[string]int{"one": 1, "two": 2, "three": 1})
	var action string
	if err := m.store.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow("SELECT action FROM audit_events WHERE target_id = ? ORDER BY id DESC LIMIT 1", id).Scan(&action)
	}); err != nil {
		t.Fatal(err)
	}
	if action != "job.retry.requested" {
		t.Fatalf("retry audit action = %q", action)
	}
}

func TestFailedJobRemainsTerminalAcrossRestart(t *testing.T) {
	m, attempts := newTestManager(t, []Step{failOnce("one")})
	id := enqueueAndRun(t, m)
	def, err := m.Build("test", json.RawMessage(`{"value":1}`))
	if err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(m.store)
	if err := restarted.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: def.Steps}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RunNext(context.Background()); !errors.Is(err, ErrNoQueuedJobs) {
		t.Fatalf("restart retried terminal failure: %v", err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusFailed || attempts["one"] != 1 {
		t.Fatalf("job after restart = %#v, attempts = %#v", job, attempts)
	}
}

func TestFailedJobCannotBeCancelled(t *testing.T) {
	m, _ := newTestManager(t, []Step{failOnce("one")})
	id := enqueueAndRun(t, m)
	before, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Cancel(context.Background(), id); !errors.Is(err, ErrCancelNotAllowed) {
		t.Fatalf("cancel failed job error = %v", err)
	}
	after, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != StatusFailed || after.ErrorCode != before.ErrorCode || after.Error != before.Error || after.Revision != before.Revision {
		t.Fatalf("failed job changed on cancel: before=%#v after=%#v", before, after)
	}
}

func TestResumeIncompleteRebuildsFromImmutablePersistedInput(t *testing.T) {
	database := openTestStore(t)
	input := json.RawMessage(`{"message":"persisted"}`)
	first := NewManager(database)
	if err := first.Register("test", func(got json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: got, Steps: []Step{pass("one")}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), Definition{Kind: "test", Input: input, Steps: []Step{pass("one")}})
	if err != nil {
		t.Fatal(err)
	}
	copy(input, json.RawMessage(`{"message":"changed!!"}`))

	var rebuilt string
	restarted := NewManager(database)
	if err := restarted.Register("test", func(got json.RawMessage) (Definition, error) {
		var value struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(got, &value); err != nil {
			return Definition{}, err
		}
		rebuilt = value.Message
		return Definition{Kind: "test", Input: got, Steps: []Step{pass("one")}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rebuilt != "persisted" {
		t.Fatalf("rebuilt input = %q, want persisted", rebuilt)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusSucceeded {
		t.Fatalf("status = %q, want %q", job.Status, StatusSucceeded)
	}
}

func TestCancelWaitsForRunningStepAndSkipsFollowingStep(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	attempts := map[string]int{}
	steps := []Step{
		{Key: "running", Run: func(context.Context) (json.RawMessage, error) {
			mu.Lock()
			attempts["running"]++
			mu.Unlock()
			close(started)
			<-release
			return json.RawMessage(`{"ok":true}`), nil
		}},
		{Key: "skipped", Run: func(context.Context) (json.RawMessage, error) {
			mu.Lock()
			attempts["skipped"]++
			mu.Unlock()
			return json.RawMessage(`{"ok":true}`), nil
		}},
	}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: steps}, nil
	}); err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), Definition{Kind: "test", Input: json.RawMessage(`{}`), Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.RunNext(context.Background()) }()
	<-started
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusCancelling {
		t.Fatalf("status during step = %q, want %q", job.Status, StatusCancelling)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	job, err = m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusCancelled {
		t.Fatalf("final status = %q, want %q", job.Status, StatusCancelled)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts["running"] != 1 || attempts["skipped"] != 0 {
		t.Fatalf("attempts = %#v", attempts)
	}
}

func TestCancelDuringFailingStepFinishesCancelled(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	started := make(chan struct{})
	release := make(chan struct{})
	var skipped atomic.Int32
	steps := []Step{
		{Key: "running", Run: func(context.Context) (json.RawMessage, error) {
			close(started)
			<-release
			return nil, errors.New("operation failed")
		}},
		{Key: "skipped", Run: func(context.Context) (json.RawMessage, error) {
			skipped.Add(1)
			return json.RawMessage(`{}`), nil
		}},
	}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: steps}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.RunNext(context.Background()) }()
	<-started
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrStepFailed) {
		t.Fatalf("run error = %v", err)
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusCancelled || job.Steps[0].Status != StepFailed || job.Steps[1].Status != StepCancelled || skipped.Load() != 0 {
		t.Fatalf("cancelled failing job = %#v, skipped runs = %d", job, skipped.Load())
	}
}

func TestEventsObserveCommittedState(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	id, err := m.Enqueue(context.Background(), Definition{Kind: "test", Input: json.RawMessage(`{"value":1}`), Steps: []Step{pass("one")}})
	if err != nil {
		t.Fatal(err)
	}
	events, unsubscribe := m.Subscribe(id)
	defer unsubscribe()
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	for event := range events {
		job, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job.UpdatedAt.Before(event.UpdatedAt) {
			t.Fatalf("event at %v preceded persisted state at %v", event.UpdatedAt, job.UpdatedAt)
		}
		if event.Status == StatusSucceeded {
			return
		}
	}
}

func TestSubscriberBufferIsBounded(t *testing.T) {
	m := NewManager(openTestStore(t))
	events, unsubscribe := m.Subscribe("job")
	defer unsubscribe()
	if got := cap(events); got != subscriberBuffer {
		t.Fatalf("subscriber buffer = %d, want %d", got, subscriberBuffer)
	}
}

func TestPersistedStepResultIsRedacted(t *testing.T) {
	database := openTestStore(t)
	redactor := NewRedactor("registered-secret")
	m := NewManager(database, redactor)
	step := Step{Key: "emit", Run: func(context.Context) (json.RawMessage, error) {
		return json.RawMessage(`{"token":"credential-value","message":"registered-secret"}`), nil
	}}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), Definition{Kind: "test", Input: json.RawMessage(`{}`), Steps: []Step{step}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	persisted := string(job.Steps[0].Result) + job.Steps[0].RedactedOutput
	for _, secret := range []string{"credential-value", "registered-secret"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("persisted step state contains %q: %q", secret, persisted)
		}
	}
}

func TestStepStartAtomicallyHonorsCancellingParent(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.claimNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.startStep(context.Background(), id, "one"); !errors.Is(err, errJobCancelled) {
		t.Fatalf("start error = %v, want cancellation", err)
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusCancelled || job.Steps[0].AttemptCount != 0 {
		t.Fatalf("job after start gate = %#v", job)
	}
}

func TestEnqueueAndAuditRollbackTogether(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnqueueWithAudit(context.Background(), def, Audit{AdminID: 999, Action: "job.test", Detail: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("enqueue survived audit failure")
	}
	got, err := m.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("jobs after rollback = %#v", got)
	}
}

func TestCancelAndAuditRollbackTogether(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CancelWithAudit(context.Background(), id, Audit{AdminID: 999, Action: "job.cancel", Detail: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("cancel survived audit failure")
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusQueued {
		t.Fatalf("status after rollback = %q", job.Status)
	}
}

func TestEnqueuePersistsNormalizedInputAndRebuildsFromIt(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database, NewRedactor("registered-value"))
	var builds []string
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		builds = append(builds, string(input))
		return Definition{Kind: "test", Input: input, Steps: []Step{pass("one")}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage(`{"access_token":"one","client_secret":"two","authorization":"Basic dGhyZWU=","message":"registered-value"}`)
	def, err := m.Build("test", original)
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"one", "two", "dGhyZWU=", "registered-value"} {
		if strings.Contains(string(job.Input), secret) {
			t.Fatalf("persisted input contains %q: %s", secret, job.Input)
		}
	}
	if got := builds[len(builds)-1]; got != string(job.Input) {
		t.Fatalf("execution rebuilt from %q, persisted %q", got, job.Input)
	}
}

func TestEnqueueRejectsUnregisteredDefinition(t *testing.T) {
	m := NewManager(openTestStore(t))
	_, err := m.Enqueue(context.Background(), Definition{Kind: "missing", Input: json.RawMessage(`{}`), Steps: []Step{pass("one")}})
	if err == nil {
		t.Fatal("unregistered job was accepted")
	}
}

func TestWorkerRunsJobsSeriallyAndStops(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	var active, maximum, completed atomic.Int32
	step := Step{Key: "run", Run: func(context.Context) (json.RawMessage, error) {
		current := active.Add(1)
		for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		completed.Add(1)
		return json.RawMessage(`{}`), nil
	}}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := m.Enqueue(context.Background(), Definition{Kind: "test", Input: json.RawMessage(`{}`), Steps: []Step{step}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		m.Wake()
	}
	deadline := time.After(time.Second)
	for completed.Load() != 4 {
		select {
		case <-deadline:
			t.Fatalf("completed = %d", completed.Load())
		case <-time.After(time.Millisecond):
		}
	}
	m.Stop()
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent jobs = %d", maximum.Load())
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("worker did not restart after stop: %v", err)
	}
	m.Stop()
}

func TestEventsHaveDurableMonotonicRevisions(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	events, unsubscribe := m.Subscribe(id)
	defer unsubscribe()
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var previous int64
	for {
		event := <-events
		if event.Revision <= previous {
			t.Fatalf("revision = %d after %d", event.Revision, previous)
		}
		previous = event.Revision
		if event.Status == StatusSucceeded {
			break
		}
	}
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Revision != previous {
		t.Fatalf("persisted revision = %d, last event = %d", job.Revision, previous)
	}
}

func TestRepeatedCancelDoesNotBroadcastWithoutTransition(t *testing.T) {
	m, _ := newTestManager(t, []Step{pass("one")})
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	events, unsubscribe := m.Subscribe(id)
	defer unsubscribe()
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	<-events
	before, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	after, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision {
		t.Fatalf("revision changed from %d to %d", before.Revision, after.Revision)
	}
	select {
	case event := <-events:
		t.Fatalf("no-op cancel broadcast %#v", event)
	default:
	}
}

func TestMultiwordSecretsStayOutOfPersistenceAndEvents(t *testing.T) {
	database := openTestStore(t)
	seedAuditAdmin(t, database)
	m := NewManager(database)
	success := Step{Key: "emit", Run: func(context.Context) (json.RawMessage, error) {
		return json.RawMessage(`{"message":"token=alpha beta gamma\nordinary result"}`), nil
	}}
	failure := Step{Key: "fail", Run: func(context.Context) (json.RawMessage, error) {
		return nil, errors.New("client_secret=delta epsilon zeta\nordinary failure")
	}}
	for kind, step := range map[string]Step{"success": success, "failure": failure} {
		step := step
		if err := m.Register(kind, func(input json.RawMessage) (Definition, error) {
			return Definition{Kind: kind, Input: input, Steps: []Step{step}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	input := json.RawMessage(`{"message":"password=correct horse battery staple\nordinary input"}`)
	def, err := m.Build("success", input)
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.EnqueueWithAudit(context.Background(), def, Audit{AdminID: 1, Action: "job.success", Detail: input})
	if err != nil {
		t.Fatal(err)
	}
	events, unsubscribe := m.Subscribe(id)
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var eventText strings.Builder
	for {
		event := <-events
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		eventText.Write(encoded)
		if event.Status == StatusSucceeded {
			break
		}
	}
	unsubscribe()
	job, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var auditDetail string
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow("SELECT detail_json FROM audit_events WHERE target_id = ?", id).Scan(&auditDetail)
	}); err != nil {
		t.Fatal(err)
	}
	exposed := string(job.Input) + string(job.Steps[0].Result) + job.Steps[0].RedactedOutput + eventText.String() + auditDetail
	for _, secret := range []string{"horse battery staple", "beta gamma"} {
		if strings.Contains(exposed, secret) {
			t.Fatalf("success state leaked %q: %s", secret, exposed)
		}
	}
	for _, ordinary := range []string{"ordinary input", "ordinary result"} {
		if !strings.Contains(exposed, ordinary) {
			t.Fatalf("success state lost %q: %s", ordinary, exposed)
		}
	}
	if !strings.Contains(job.Steps[0].RedactedOutput, "ordinary result") {
		t.Fatalf("redacted output lost ordinary text: %q", job.Steps[0].RedactedOutput)
	}

	failureDef, err := m.Build("failure", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	failureID, err := m.Enqueue(context.Background(), failureDef)
	if err != nil {
		t.Fatal(err)
	}
	failureEvents, stopFailureEvents := m.Subscribe(failureID)
	defer stopFailureEvents()
	if err := m.RunNext(context.Background()); !errors.Is(err, ErrStepFailed) {
		t.Fatalf("failure run error = %v", err)
	}
	failureJob, err := m.Get(context.Background(), failureID)
	if err != nil {
		t.Fatal(err)
	}
	failureSnapshot, err := m.SnapshotEvent(context.Background(), failureID)
	if err != nil {
		t.Fatal(err)
	}
	failureText := failureJob.Error + failureJob.Steps[0].Error + failureJob.Steps[0].RedactedOutput + failureSnapshot.Error
	for len(failureEvents) > 0 {
		event := <-failureEvents
		failureText += event.Error
	}
	if strings.Contains(failureText, "epsilon zeta") || !strings.Contains(failureText, "ordinary failure") {
		t.Fatalf("failure exposure was not safely redacted: %q", failureText)
	}
}

func TestLargeIntegerSurvivesPersistenceAndRestartRebuild(t *testing.T) {
	database := openTestStore(t)
	input := json.RawMessage(`{"sequence":900719925474099312345678901234567890,"message":"ordinary"}`)
	first := NewManager(database)
	if err := first.Register("test", func(got json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: got, Steps: []Step{pass("one")}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := first.Build("test", input)
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}

	var rebuilt json.RawMessage
	restarted := NewManager(database)
	if err := restarted.Register("test", func(got json.RawMessage) (Definition, error) {
		rebuilt = append(rebuilt[:0], got...)
		return Definition{Kind: "test", Input: got, Steps: []Step{pass("one")}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	const number = "900719925474099312345678901234567890"
	if !strings.Contains(string(job.Input), number) || !strings.Contains(string(rebuilt), number) {
		t.Fatalf("large integer changed: persisted=%s rebuilt=%s", job.Input, rebuilt)
	}
}

func TestCrashInterruptedStepRequiresReconciliation(t *testing.T) {
	database := openTestStore(t)
	step := pass("one")
	first := NewManager(database)
	if err := first.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := first.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.claimNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.startStep(context.Background(), id, "one"); err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(database)
	if err := restarted.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusFailed || job.ErrorCode != ErrorReconciliationRequired || job.Steps[0].ErrorCode != ErrorReconciliationRequired {
		t.Fatalf("ambiguous job was not quarantined: %#v", job)
	}
	if err := restarted.RunNext(context.Background()); !errors.Is(err, ErrNoQueuedJobs) {
		t.Fatalf("ambiguous step was retried: %v", err)
	}
}

func TestCrashInterruptedStepReconcilesBeforeSafeRetry(t *testing.T) {
	database := openTestStore(t)
	var reconciled, ran atomic.Int32
	step := Step{
		Key: "one",
		Run: func(context.Context) (json.RawMessage, error) {
			ran.Add(1)
			return json.RawMessage(`{"ok":true}`), nil
		},
		Reconcile: func(context.Context) (Reconciliation, error) {
			reconciled.Add(1)
			return Reconciliation{Outcome: ReconcileRetry}, nil
		},
	}
	first := NewManager(database)
	if err := first.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := first.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.claimNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.startStep(context.Background(), id, "one"); err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(database)
	if err := restarted.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Load() != 1 || ran.Load() != 1 || job.Status != StatusSucceeded {
		t.Fatalf("reconciled=%d ran=%d job=%#v", reconciled.Load(), ran.Load(), job)
	}
}

func TestReconciliationFailureCannotBeExplicitlyRetried(t *testing.T) {
	database := openTestStore(t)
	seedAuditAdmin(t, database)
	step := Step{
		Key: "one",
		Run: pass("one").Run,
		Reconcile: func(context.Context) (Reconciliation, error) {
			return Reconciliation{}, &agentapi.Error{Code: "operation_not_allowed", Message: "state check unavailable"}
		},
	}
	first := NewManager(database)
	if err := first.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := first.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.claimNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.startStep(context.Background(), id, "one"); err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(database)
	if err := restarted.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.ErrorCode != ErrorReconciliationFailed || job.Steps[0].ErrorCode != ErrorReconciliationFailed {
		t.Fatalf("reconciliation codes = (%q, %q)", job.ErrorCode, job.Steps[0].ErrorCode)
	}
	if err := restarted.RetryWithAudit(context.Background(), id, Audit{AdminID: 1, Action: "job.retry.requested", Detail: json.RawMessage(`{}`)}); !errors.Is(err, ErrRetryNotAllowed) {
		t.Fatalf("unsafe retry error = %v", err)
	}
}

func TestCancelWinsWhileReconciliationIsBlocked(t *testing.T) {
	database := openTestStore(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	step := Step{
		Key: "one",
		Run: pass("one").Run,
		Reconcile: func(context.Context) (Reconciliation, error) {
			close(entered)
			<-release
			return Reconciliation{}, errors.New("state check failed")
		},
	}
	first := NewManager(database)
	if err := first.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := first.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.claimNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.startStep(context.Background(), id, "one"); err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(database)
	if err := restarted.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- restarted.ResumeIncomplete(context.Background()) }()
	<-entered
	if err := restarted.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	job, err := restarted.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusCancelled || job.ErrorCode != "" || job.Steps[0].Status != StepCancelled {
		t.Fatalf("reconciliation overwrote cancellation: %#v", job)
	}
}

func TestWorkerContainsIncompatibleJobAndContinues(t *testing.T) {
	database := openTestStore(t)
	seed := NewManager(database)
	for _, kind := range []string{"bad", "good"} {
		kind := kind
		if err := seed.Register(kind, func(input json.RawMessage) (Definition, error) {
			return Definition{Kind: kind, Input: input, Steps: []Step{pass("one")}}, nil
		}); err != nil {
			t.Fatal(err)
		}
		def, err := seed.Build(kind, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := seed.Enqueue(context.Background(), def); err != nil {
			t.Fatal(err)
		}
	}

	var goodRuns atomic.Int32
	restarted := NewManager(database)
	if err := restarted.Register("bad", func(json.RawMessage) (Definition, error) {
		return Definition{}, errors.New("definition changed")
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Register("good", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "good", Input: input, Steps: []Step{{Key: "one", Run: func(context.Context) (json.RawMessage, error) {
			goodRuns.Add(1)
			return json.RawMessage(`{}`), nil
		}}}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	var bad Job
	deadline := time.Now().Add(2 * time.Second)
	for {
		persisted, err := restarted.List(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range persisted {
			if job.Kind == "bad" {
				bad = job
			}
		}
		if goodRuns.Load() == 1 && bad.Status == StatusFailed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not contain both jobs: good=%d bad=%#v health=%#v", goodRuns.Load(), bad, restarted.WorkerHealth())
		}
		time.Sleep(time.Millisecond)
	}
	if bad.Status != StatusFailed || bad.ErrorCode != ErrorIncompatibleState || len(bad.Steps) != 1 || bad.Steps[0].ErrorCode != ErrorIncompatibleState {
		t.Fatalf("incompatible job was not quarantined: %#v", bad)
	}
}

func TestWorkerRetriesInfrastructureFailureWithoutExternalWake(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	var runs atomic.Int32
	step := Step{Key: "one", Run: func(context.Context) (json.RawMessage, error) {
		runs.Add(1)
		return json.RawMessage(`{}`), nil
	}}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Enqueue(context.Background(), def); err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER fail_claim BEFORE UPDATE OF status ON jobs WHEN NEW.status = 'running' BEGIN SELECT RAISE(FAIL, 'temporary failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.After(2 * time.Second)
	for m.WorkerHealth().Status != "degraded" {
		select {
		case <-deadline:
			t.Fatalf("worker did not report failure: %#v", m.WorkerHealth())
		case <-time.After(time.Millisecond):
		}
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DROP TRIGGER fail_claim`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(2 * time.Second)
	for runs.Load() != 1 || m.WorkerHealth().Status != "ok" {
		select {
		case <-deadline:
			t.Fatalf("worker did not recover: runs=%d health=%#v", runs.Load(), m.WorkerHealth())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestWorkerClearsTransientHealthAfterNoWorkRecovery(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	step := pass("one")
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER fail_claim_for_health BEFORE UPDATE OF status ON jobs WHEN NEW.status = 'running' BEGIN SELECT RAISE(FAIL, 'temporary failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for m.WorkerHealth().ErrorCode != ErrorInternal {
		if time.Now().After(deadline) {
			t.Fatalf("worker did not degrade: %#v", m.WorkerHealth())
		}
		time.Sleep(time.Millisecond)
	}
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DROP TRIGGER fail_claim_for_health`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for m.WorkerHealth().Status != "ok" {
		if time.Now().After(deadline) {
			t.Fatalf("worker health stayed degraded after idle recovery: %#v", m.WorkerHealth())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerRetriesRecoveryAfterClaimWithoutExternalWake(t *testing.T) {
	database := openTestStore(t)
	m := NewManager(database)
	var runs, reconciliations atomic.Int32
	secondRecovery := make(chan struct{})
	releaseRecovery := make(chan struct{})
	step := Step{
		Key: "one",
		Run: func(context.Context) (json.RawMessage, error) {
			runs.Add(1)
			return json.RawMessage(`{"ok":true}`), nil
		},
		Reconcile: func(context.Context) (Reconciliation, error) {
			if reconciliations.Add(1) == 2 {
				close(secondRecovery)
				<-releaseRecovery
			}
			return Reconciliation{Outcome: ReconcileRetry}, nil
		},
	}
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := m.Build("test", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER fail_step_progress BEFORE UPDATE OF status ON job_steps WHEN NEW.status IN ('succeeded', 'pending') BEGIN SELECT RAISE(FAIL, 'temporary failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	defer func() {
		select {
		case <-releaseRecovery:
		default:
			close(releaseRecovery)
		}
	}()
	select {
	case <-secondRecovery:
	case <-time.After(2 * time.Second):
		t.Fatalf("worker did not retry failed recovery: runs=%d reconciliations=%d health=%#v", runs.Load(), reconciliations.Load(), m.WorkerHealth())
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`DROP TRIGGER fail_step_progress`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	close(releaseRecovery)
	deadline := time.Now().Add(2 * time.Second)
	for {
		job, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == StatusSucceeded && runs.Load() == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker stranded claimed job: job=%#v runs=%d reconciliations=%d health=%#v", job, runs.Load(), reconciliations.Load(), m.WorkerHealth())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFailureCodesPersistAndReachSnapshots(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code ErrorCode
	}{
		{name: "typed agent", err: &agentapi.Error{Code: "operation_not_allowed", Message: "denied"}, code: ErrorAgentOperationNotAllowed},
		{name: "cancelled", err: context.Canceled, code: ErrorContextCancelled},
		{name: "deadline", err: context.DeadlineExceeded, code: ErrorDeadlineExceeded},
		{name: "internal", err: errors.New("unexpected"), code: ErrorInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := openTestStore(t)
			m := NewManager(database)
			step := Step{Key: "fail", Run: func(context.Context) (json.RawMessage, error) { return nil, test.err }}
			if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
				return Definition{Kind: "test", Input: input, Steps: []Step{step}}, nil
			}); err != nil {
				t.Fatal(err)
			}
			def, err := m.Build("test", json.RawMessage(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			id, err := m.Enqueue(context.Background(), def)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.RunNext(context.Background()); !errors.Is(err, ErrStepFailed) {
				t.Fatalf("run error = %v", err)
			}
			job, err := m.Get(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := m.SnapshotEvent(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if job.ErrorCode != test.code || job.Steps[0].ErrorCode != test.code || snapshot.ErrorCode != test.code {
				t.Fatalf("codes job=%q step=%q snapshot=%q, want %q", job.ErrorCode, job.Steps[0].ErrorCode, snapshot.ErrorCode, test.code)
			}
		})
	}
}

func newTestManager(t *testing.T, steps []Step) (*Manager, map[string]int) {
	t.Helper()
	database := openTestStore(t)
	attempts := map[string]int{}
	wrapped := make([]Step, 0, len(steps))
	for _, step := range steps {
		step := step
		wrapped = append(wrapped, Step{Key: step.Key, Run: func(ctx context.Context) (json.RawMessage, error) {
			attempts[step.Key]++
			return step.Run(ctx)
		}})
	}
	m := NewManager(database)
	if err := m.Register("test", func(input json.RawMessage) (Definition, error) {
		return Definition{Kind: "test", Input: input, Steps: wrapped}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return m, attempts
}

func enqueueAndRun(t *testing.T, m *Manager) string {
	t.Helper()
	def, err := m.Build("test", json.RawMessage(`{"value":1}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Enqueue(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RunNext(context.Background()); !errors.Is(err, ErrStepFailed) {
		t.Fatalf("first run error = %v, want step failure", err)
	}
	return id
}

func retryAndRun(t *testing.T, m *Manager, _ string) {
	t.Helper()
	if err := m.ResumeIncomplete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func assertAttempts(t *testing.T, got, want map[string]int) {
	t.Helper()
	for key, count := range want {
		if got[key] != count {
			t.Fatalf("attempts[%q] = %d, want %d (all: %#v)", key, got[key], count, got)
		}
	}
}

func pass(key string) Step {
	return Step{Key: key, Run: func(context.Context) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	}}
}

func failOnce(key string) Step {
	failed := false
	return Step{Key: key, Run: func(context.Context) (json.RawMessage, error) {
		if !failed {
			failed = true
			return nil, errors.New("temporary secret=password")
		}
		return json.RawMessage(`{"ok":true}`), nil
	}}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func seedAuditAdmin(t *testing.T, database *store.Store) {
	t.Helper()
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO admins(id, username, password_hash, created_at, updated_at) VALUES (1, 'admin', X'00', 1, 1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
