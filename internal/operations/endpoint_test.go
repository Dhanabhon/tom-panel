package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func endpointStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "state.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, php_version, created_at, updated_at)
			VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'php', 'active', 'app.example.test', 443, 0, '8.3', 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO domains(id, site_id, hostname, port, kind, created_at, updated_at)
			VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'app.example.test', 443, 'primary', 0, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestCloudflareProxyRejectsUnsupportedPort(t *testing.T) {
	err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: 9443, CloudflareProxy: true}, nil)
	if !errors.Is(err, ErrCloudflarePort) {
		t.Fatalf("got %v, want ErrCloudflarePort", err)
	}
	for _, port := range []uint16{443, 8443} {
		if err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: port, CloudflareProxy: true, AcmeEmail: "tom@example.com"}, nil); err != nil {
			t.Fatalf("supported port %d rejected: %v", port, err)
		}
	}
}

func TestEndpointRejectsSiteHostname(t *testing.T) {
	database := endpointStore(t)
	reserved, err := ReservedHostnames(context.Background(), database)
	if err != nil || len(reserved) != 1 {
		t.Fatalf("reserved hostnames: %v %v", reserved, err)
	}
	err = ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "APP.example.test", Port: 443}, reserved)
	if !errors.Is(err, ErrEndpointHostname) {
		t.Fatalf("got %v, want ErrEndpointHostname", err)
	}
	if err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: 443, AcmeEmail: "tom@example.com"}, reserved); err != nil {
		t.Fatalf("safe hostname rejected: %v", err)
	}
	if err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: 443}, reserved); !errors.Is(err, ErrEndpointInvalid) {
		t.Fatalf("missing acme email accepted: %v", err)
	}
}

func TestEndpointValidationRules(t *testing.T) {
	if err := ValidateEndpoint(EndpointConfig{Mode: "tunnel"}, nil); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: 80}, nil); err == nil {
		t.Fatal("plain HTTP port accepted")
	}
	if err := ValidateEndpoint(EndpointConfig{Mode: "loopback", Hostname: "x"}, nil); err == nil {
		t.Fatal("loopback with hostname accepted")
	}
}

type endpointAgent struct {
	activations []EndpointConfig
	fail        bool
}

func (e *endpointAgent) call(_ context.Context, operation string, input, _ any) error {
	if operation != "endpoint.activate" || e.fail {
		return errors.New("endpoint agent refused")
	}
	encoded, _ := json.Marshal(input)
	var parsed struct {
		Config EndpointConfig `json:"config"`
	}
	_ = json.Unmarshal(encoded, &parsed)
	e.activations = append(e.activations, parsed.Config)
	return nil
}

func TestEndpointChangeKeepsOldRouteUntilHealthy(t *testing.T) {
	database := endpointStore(t)
	agent := &endpointAgent{}
	changer := NewEndpointChanger(database, agent.call)
	changer.SetCertificateIssuer(func(context.Context, EndpointConfig) error { return nil })
	changer.health = func(context.Context, string, uint16) error { return nil }
	manager := jobs.NewManager(database)
	if err := changer.Register(manager); err != nil {
		t.Fatal(err)
	}
	definition, err := changer.BuildEndpointChangeJob(context.Background(), EndpointConfig{
		Mode: "public", Hostname: "panel.example.com", Port: 443, AcmeEmail: "tom@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	runEndpointJob(t, manager, jobID)
	if len(agent.activations) != 1 || agent.activations[0].Hostname != "panel.example.com" {
		t.Fatalf("activations: %+v", agent.activations)
	}
	current, err := changer.Current(context.Background())
	if err != nil || current.Hostname != "panel.example.com" {
		t.Fatalf("endpoint not committed: %+v %v", current, err)
	}
}

func TestHealthFailureTriggersRollback(t *testing.T) {
	database := endpointStore(t)
	agent := &endpointAgent{}
	changer := NewEndpointChanger(database, agent.call)
	changer.SetCertificateIssuer(func(context.Context, EndpointConfig) error { return nil })
	changer.health = func(context.Context, string, uint16) error { return errors.New("unreachable") }
	definition, err := changer.BuildEndpointChangeJob(context.Background(), EndpointConfig{
		Mode: "public", Hostname: "panel.example.com", Port: 443, AcmeEmail: "tom@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := jobs.NewManager(database)
	if err := changer.Register(manager); err != nil {
		t.Fatal(err)
	}
	jobID, err := manager.Enqueue(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	runEndpointJob(t, manager, jobID, true)
	current, err := changer.Current(context.Background())
	if err != nil || current.Mode != "loopback" {
		t.Fatalf("failed change altered the endpoint: %+v %v", current, err)
	}
}

func runEndpointJob(t *testing.T, manager *jobs.Manager, jobID string, expectFailure ...bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, err := manager.Get(context.Background(), jobID)
		if err != nil {
			t.Fatal(err)
		}
		if len(expectFailure) > 0 && job.Status == jobs.StatusFailed {
			return
		}
		if job.Status == jobs.StatusSucceeded {
			if len(expectFailure) > 0 {
				t.Fatal("endpoint job unexpectedly succeeded")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("endpoint job did not finish")
}
