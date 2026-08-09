package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoveStaleSocketRefusesLiveListener(t *testing.T) {
	path := testSocketPath(t)
	listener := listenUnix(t, path)
	t.Cleanup(func() { listener.Close() })

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("live socket was unlinked")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("live socket path was removed: %v", err)
	}
}

func TestRemoveStaleSocketCleansClosedListener(t *testing.T) {
	path := testSocketPath(t)
	listener := listenUnix(t, path)
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	if err := removeStaleSocket(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket remains: %v", err)
	}
}

func TestRemoveStaleSocketPreservesSocketWhenLivenessIsUnknown(t *testing.T) {
	path := testSocketPath(t)
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("socket with unknown liveness was unlinked")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("socket with unknown liveness was removed: %v", err)
	}
}

func TestRemoveOwnedSocketRemovesOnlyMatchingInode(t *testing.T) {
	t.Run("owned socket", func(t *testing.T) {
		path := testSocketPath(t)
		listener := listenUnix(t, path)
		listener.SetUnlinkOnClose(false)
		owned, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}

		if err := removeOwnedSocket(path, owned); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned socket remains: %v", err)
		}
	})

	t.Run("replacement socket", func(t *testing.T) {
		path := testSocketPath(t)
		original := listenUnix(t, path)
		original.SetUnlinkOnClose(false)
		t.Cleanup(func() { original.Close() })
		owned, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}

		replacement := listenUnix(t, path)
		t.Cleanup(func() { replacement.Close() })
		if err := removeOwnedSocket(path, owned); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("replacement socket was removed: %v", err)
		}
	})
}

func TestConcurrentStartKeepsWinnerSocketReachable(t *testing.T) {
	path := testSocketPath(t)
	stale := listenUnix(t, path)
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(filepath.Dir(path), "agent.lock")

	type result struct {
		listener *net.UnixListener
		lock     *os.File
		owned    os.FileInfo
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			listener, lock, owned, err := listenAgentSocket(path, lockPath)
			results <- result{listener: listener, lock: lock, owned: owned, err: err}
		}()
	}
	close(start)

	first, second := <-results, <-results
	var winner result
	for _, candidate := range []result{first, second} {
		if candidate.err == nil {
			if winner.listener != nil {
				t.Fatal("both starters acquired the agent socket")
			}
			winner = candidate
			continue
		}
		if !errors.Is(candidate.err, errAgentAlreadyRunning) {
			t.Fatalf("losing starter got %v", candidate.err)
		}
	}
	if winner.listener == nil {
		t.Fatal("neither starter acquired the agent socket")
	}
	t.Cleanup(func() {
		_ = removeOwnedSocket(path, winner.owned)
		_ = winner.listener.Close()
		_ = winner.lock.Close()
	})

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("winner socket is unreachable: %v", err)
	}
	_ = conn.Close()
}

func listenUnix(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "tp-main-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return filepath.Join(directory, "agent.sock")
}
