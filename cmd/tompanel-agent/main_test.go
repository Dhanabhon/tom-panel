package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
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
