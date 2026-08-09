package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestConcurrentStartupAllowsOneDaemonPerStateDirectory(t *testing.T) {
	cfg := config.Config{Listen: "127.0.0.1:0", StateDir: t.TempDir()}
	type result struct {
		startup *daemonStartup
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			startup, err := acquireDaemonStartup(cfg)
			results <- result{startup: startup, err: err}
		}()
	}
	close(start)

	var winner *daemonStartup
	for range 2 {
		candidate := <-results
		if candidate.err == nil {
			if winner != nil {
				t.Fatal("both daemons acquired the same state directory")
			}
			winner = candidate.startup
			continue
		}
		if !errors.Is(candidate.err, errDaemonAlreadyRunning) {
			t.Fatalf("losing daemon got %v", candidate.err)
		}
	}
	if winner == nil {
		t.Fatal("neither daemon acquired the state directory")
	}
	t.Cleanup(winner.Close)
}

func TestOccupiedListenerFailsBeforeJobReconstruction(t *testing.T) {
	dir, database := daemonStateWithCancellingJob(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	cfg := config.Config{Listen: occupied.Addr().String(), StateDir: dir, AgentSocket: filepath.Join(dir, "agent.sock")}

	if err := run(cfg); err == nil {
		t.Fatal("daemon started with an occupied listener")
	}
	if status := persistedJobStatus(t, database); status != "cancelling" {
		t.Fatalf("job status = %q, want cancelling", status)
	}
}

func TestLockedStateFailsBeforeJobReconstructionOnAnotherPort(t *testing.T) {
	dir, database := daemonStateWithCancellingJob(t)
	owner, err := acquireDaemonStartup(config.Config{Listen: "127.0.0.1:0", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)

	err = run(config.Config{Listen: "127.0.0.1:0", StateDir: dir, AgentSocket: filepath.Join(dir, "agent.sock")})
	if !errors.Is(err, errDaemonAlreadyRunning) {
		t.Fatalf("second daemon error = %v, want %v", err, errDaemonAlreadyRunning)
	}
	if status := persistedJobStatus(t, database); status != "cancelling" {
		t.Fatalf("job status = %q, want cancelling", status)
	}
}

func daemonStateWithCancellingJob(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO jobs(id, kind, input_json, status, created_at, updated_at)
			VALUES ('startup-order-job', 'demo', '{"message":"safe"}', 'cancelling', 1, 1)`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO job_steps(job_id, step_key, position, status)
			VALUES ('startup-order-job', 'inspect-agent', 0, 'pending')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return dir, database
}

func persistedJobStatus(t *testing.T, database *store.Store) string {
	t.Helper()
	var status string
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow("SELECT status FROM jobs WHERE id = 'startup-order-job'").Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	return status
}
