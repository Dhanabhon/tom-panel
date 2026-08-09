package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
)

func TestRejectsUnexpectedPeerUID(t *testing.T) {
	srv, _ := newTestServer(t, PeerCredentials{UID: 1002}, 1001)
	err := srv.ServeOne(context.Background())
	if !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsWrongProtocolVersion(t *testing.T) {
	srv, client := newTestServer(t, PeerCredentials{UID: 1001}, 1001)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeOne(context.Background()) }()

	request := agentapi.Request{Version: agentapi.ProtocolVersion + 1, ID: "req-version", Operation: "job.demo", Payload: []byte(`{}`)}
	if err := agentapi.WriteFrame(context.Background(), client, request); err != nil {
		t.Fatal(err)
	}
	var response agentapi.Response
	if err := agentapi.ReadFrame(context.Background(), client, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "unsupported_version" {
		t.Fatalf("got %#v", response.Error)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
}

func TestRejectsMalformedJSON(t *testing.T) {
	srv, client := newTestServer(t, PeerCredentials{UID: 1001}, 1001)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeOne(context.Background()) }()

	malformed := []byte(`{"version":1`)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(malformed)))
	if _, err := client.Write(append(header[:], malformed...)); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; !errors.Is(err, agentapi.ErrMalformedFrame) {
		t.Fatalf("got %v", err)
	}
}

func TestAllowsDemoOperation(t *testing.T) {
	response := callTestServer(t, agentapi.Request{
		Version:   agentapi.ProtocolVersion,
		ID:        "req-demo",
		Operation: "job.demo",
		Payload:   []byte(`{"message":"hello"}`),
	})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if got := string(response.Result); got != `{"message":"hello"}` {
		t.Fatalf("got %s", got)
	}
}

func TestAllowsSystemInspectOperation(t *testing.T) {
	response := callTestServer(t, agentapi.Request{
		Version:   agentapi.ProtocolVersion,
		ID:        "req-inspect",
		Operation: "system.inspect",
		Payload:   []byte(`{}`),
	})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if got := string(response.Result); got != `{"status":"ok"}` {
		t.Fatalf("got %s", got)
	}
}

func TestRejectsInvalidDemoPayload(t *testing.T) {
	response := callTestServer(t, agentapi.Request{
		Version:   agentapi.ProtocolVersion,
		ID:        "req-invalid-demo",
		Operation: "job.demo",
		Payload:   []byte(`[]`),
	})
	if response.Error == nil || response.Error.Code != "invalid_payload" {
		t.Fatalf("got %#v", response.Error)
	}
}

func TestRejectsOperationOutsideClosedSet(t *testing.T) {
	response := callTestServer(t, agentapi.Request{
		Version:   agentapi.ProtocolVersion,
		ID:        "req-shell",
		Operation: "shell.exec",
		Payload:   []byte(`{"command":"rm -rf /"}`),
	})
	if response.Error == nil || response.Error.Code != "operation_not_allowed" {
		t.Fatalf("got %#v", response.Error)
	}
}

func TestServeOneHonorsContextDeadline(t *testing.T) {
	srv, _ := newTestServer(t, PeerCredentials{UID: 1001}, 1001)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := srv.ServeOne(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestNewServerBoundsIdlePeer(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() })
	t.Cleanup(func() { client.Close() })
	srv := NewServer(server, 1001)
	srv.peerCredentials = func(net.Conn) (PeerCredentials, error) {
		return PeerCredentials{UID: 1001}, nil
	}
	go func() {
		time.Sleep(3 * time.Second)
		_ = client.Close()
	}()

	started := time.Now()
	err := srv.ServeOne(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("idle peer held the server for %v", elapsed)
	}
}

func TestReadsLinuxPeerCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only")
	}

	path := t.TempDir() + "/agent.sock"
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server := <-accepted
	t.Cleanup(func() { server.Close() })

	credentials, err := defaultPeerCredentials(server)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.UID != uint32(os.Getuid()) {
		t.Fatalf("got UID %d", credentials.UID)
	}
}

func newTestServer(t *testing.T, credentials PeerCredentials, expectedUID uint32) (*Server, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() })
	t.Cleanup(func() { client.Close() })
	return &Server{
		conn:        server,
		expectedUID: expectedUID,
		peerCredentials: func(net.Conn) (PeerCredentials, error) {
			return credentials, nil
		},
	}, client
}

func callTestServer(t *testing.T, request agentapi.Request) agentapi.Response {
	t.Helper()
	srv, client := newTestServer(t, PeerCredentials{UID: 1001}, 1001)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeOne(context.Background()) }()
	if err := agentapi.WriteFrame(context.Background(), client, request); err != nil {
		t.Fatal(err)
	}
	var response agentapi.Response
	if err := agentapi.ReadFrame(context.Background(), client, &response); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	return response
}
