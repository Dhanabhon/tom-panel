package agentapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type readyConn struct {
	bytes.Buffer
}

func (*readyConn) Close() error                     { return nil }
func (*readyConn) LocalAddr() net.Addr              { return nil }
func (*readyConn) RemoteAddr() net.Addr             { return nil }
func (*readyConn) SetDeadline(time.Time) error      { return nil }
func (*readyConn) SetReadDeadline(time.Time) error  { return nil }
func (*readyConn) SetWriteDeadline(time.Time) error { return nil }

func TestReadFrameRejectsAlreadyCancelledContext(t *testing.T) {
	conn := &readyConn{}
	if err := WriteFrame(context.Background(), conn, Response{Version: ProtocolVersion, ID: "ready"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var response Response
	if err := ReadFrame(ctx, conn, &response); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFrameRejectsAlreadyCancelledContext(t *testing.T) {
	conn := &readyConn{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WriteFrame(ctx, conn, Request{Version: ProtocolVersion, ID: "ready"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if conn.Len() != 0 {
		t.Fatal("cancelled write reached the connection")
	}
}

func TestRejectsOversizedFrame(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() })
	t.Cleanup(func() { client.Close() })

	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
		_, _ = client.Write(header[:])
	}()

	var response Response
	err := ReadFrame(context.Background(), server, &response)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFrameHonorsContextDeadline(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() })
	t.Cleanup(func() { client.Close() })
	go func() {
		time.Sleep(time.Second)
		_ = server.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := WriteFrame(ctx, client, Request{Version: ProtocolVersion, ID: "blocked-write"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("write returned after %v", elapsed)
	}
}

func TestClientCallReturnsTypedResult(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		var request Request
		if err := ReadFrame(context.Background(), conn, &request); err != nil {
			serverErr <- err
			return
		}
		serverErr <- WriteFrame(context.Background(), conn, Response{
			Version: ProtocolVersion,
			ID:      request.ID,
			Result:  []byte(`{"accepted":true}`),
		})
	}()

	var output struct {
		Accepted bool `json:"accepted"`
	}
	if err := NewClient(path).Call(context.Background(), "job.demo", struct{}{}, &output); err != nil {
		t.Fatal(err)
	}
	if !output.Accepted {
		t.Fatal("demo result was not decoded")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestClientCallReturnsAgentError(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request Request
		if ReadFrame(context.Background(), conn, &request) != nil {
			return
		}
		_ = WriteFrame(context.Background(), conn, Response{
			Version: ProtocolVersion,
			ID:      request.ID,
			Error:   &Error{Code: "operation_not_allowed", Message: "operation is not allowed"},
		})
	}()

	err = NewClient(path).Call(context.Background(), "shell.exec", struct{}{}, nil)
	var agentErr *Error
	if !errors.As(err, &agentErr) || agentErr.Code != "operation_not_allowed" {
		t.Fatalf("got %v", err)
	}
}

func TestClientCallHonorsContextDeadline(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	accepted := make(chan struct{})
	release := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		<-release
	}()
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = NewClient(path).Call(ctx, "job.demo", struct{}{}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	<-accepted
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "tp-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return filepath.Join(directory, "agent.sock")
}
