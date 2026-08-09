package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestRetryStartsAtFirstIncompleteStep(t *testing.T) {
	m, attempts := newTestManager(t, []Step{pass("one"), failOnce("two"), pass("three")})
	id := enqueueAndRun(t, m)
	retryAndRun(t, m, id)
	assertAttempts(t, attempts, map[string]int{"one": 1, "two": 2, "three": 1})
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
