package sites

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
)

type provisionAgent struct {
	mu       sync.Mutex
	calls    map[string]int
	failOnce string
}

func (a *provisionAgent) call(_ context.Context, operation string, input, output any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls[operation]++
	if operation == a.failOnce && a.calls[operation] == 1 {
		return errors.New("injected agent failure")
	}
	if output != nil {
		payload, _ := json.Marshal(struct{}{})
		_ = json.Unmarshal(payload, output)
	}
	return nil
}

func (a *provisionAgent) count(operation string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[operation]
}

func TestProvisionRetryDoesNotDuplicateLinuxUser(t *testing.T) {
	repository := openTestRepository(t)
	site, err := repository.Create(context.Background(), CreateInput{
		Kind: KindStatic, PrimaryDomain: "retry.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent := &provisionAgent{calls: make(map[string]int), failOnce: "nginx.validate_activate"}
	provisioner := NewProvisioner(repository, nil, nil, func(site Site) ([]byte, error) {
		return []byte("# Managed by TomPanel: " + site.ID + "\nserver {}\n"), nil
	})
	provisioner.agentCall = agent.call
	manager := jobs.NewManager(repository.store)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	definition, err := provisioner.BuildProvisionJob(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); !errors.Is(err, jobs.ErrStepFailed) {
		t.Fatalf("first run error = %v, want step failure", err)
	}
	if got := agent.count("site.ensure_identity"); got != 1 {
		t.Fatalf("identity calls after failure = %d, want 1", got)
	}
	insertProvisionTestAdmin(t, repository)
	if err := manager.RetryWithAudit(context.Background(), jobID, jobs.Audit{
		AdminID: 1, Action: "job.retry.requested", Detail: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := agent.count("site.ensure_identity"); got != 1 {
		t.Fatalf("identity calls after retry = %d, want 1", got)
	}
	got, err := repository.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive {
		t.Fatalf("state after retry = %q, want %q", got.State, StateActive)
	}
}

func TestDisableKeepsManagedResources(t *testing.T) {
	repository := openTestRepository(t)
	site, err := repository.Create(context.Background(), CreateInput{
		Kind: KindStatic, PrimaryDomain: "keep.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetState(context.Background(), site.ID, StateActive); err != nil {
		t.Fatal(err)
	}
	agent := &provisionAgent{calls: make(map[string]int)}
	provisioner := NewProvisioner(repository, nil, nil, nil)
	provisioner.agentCall = agent.call
	manager := jobs.NewManager(repository.store)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	definition, err := provisioner.BuildSetEnabledJob(site.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Enqueue(context.Background(), definition); err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := repository.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateDisabled {
		t.Fatalf("state = %q, want %q", got.State, StateDisabled)
	}
	var domains int
	if err := repository.store.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow("SELECT count(*) FROM domains WHERE site_id = ?", site.ID).Scan(&domains)
	}); err != nil {
		t.Fatal(err)
	}
	if domains != 2 || agent.count("nginx.disable") != 1 {
		t.Fatalf("domains=%d nginx.disable calls=%d", domains, agent.count("nginx.disable"))
	}
}

func TestReEnableRunsHealthCheck(t *testing.T) {
	repository := openTestRepository(t)
	site, err := repository.Create(context.Background(), CreateInput{
		Kind: KindStatic, PrimaryDomain: "enable.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetState(context.Background(), site.ID, StateDisabled); err != nil {
		t.Fatal(err)
	}
	agent := &provisionAgent{calls: make(map[string]int)}
	provisioner := NewProvisioner(repository, nil, nil, func(site Site) ([]byte, error) {
		return []byte("# Managed by TomPanel: " + site.ID + "\nserver {}\n"), nil
	})
	provisioner.agentCall = agent.call
	manager := jobs.NewManager(repository.store)
	if err := provisioner.Register(manager); err != nil {
		t.Fatal(err)
	}
	definition, err := provisioner.BuildSetEnabledJob(site.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Enqueue(context.Background(), definition); err != nil {
		t.Fatal(err)
	}
	if err := manager.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := agent.count("nginx.validate_activate"); got != 1 {
		t.Fatalf("nginx activation calls = %d, want 1", got)
	}
	got, err := repository.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive {
		t.Fatalf("state = %q, want %q", got.State, StateActive)
	}
}

func insertProvisionTestAdmin(t *testing.T, repository *Repository) {
	t.Helper()
	if err := repository.store.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO admins(id, username, password_hash, created_at, updated_at)
			VALUES (1, 'admin', X'01', 1, 1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
