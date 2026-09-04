package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
)

const frameIdleTimeout = 2 * time.Second

var (
	ErrUnauthorizedPeer           = errors.New("unauthorized agent peer")
	ErrPeerCredentialsUnsupported = errors.New("peer credentials are unsupported on this platform")
)

type PeerCredentials struct {
	PID int32
	UID uint32
	GID uint32
}

type peerCredentialsFunc func(net.Conn) (PeerCredentials, error)

type idleConn struct {
	net.Conn
	ctx     context.Context
	timeout time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.setReadDeadline(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	return n, c.ioError(err)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.setWriteDeadline(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	return n, c.ioError(err)
}

func (c *idleConn) setReadDeadline() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := c.Conn.SetReadDeadline(c.deadline()); err != nil {
		return err
	}
	return c.ctx.Err()
}

func (c *idleConn) setWriteDeadline() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := c.Conn.SetWriteDeadline(c.deadline()); err != nil {
		return err
	}
	return c.ctx.Err()
}

func (c *idleConn) deadline() time.Time {
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := c.ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func (c *idleConn) ioError(err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := c.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

var defaultPeerCredentials peerCredentialsFunc = func(net.Conn) (PeerCredentials, error) {
	return PeerCredentials{}, ErrPeerCredentialsUnsupported
}

type Server struct {
	conn            net.Conn
	expectedUID     uint32
	peerCredentials peerCredentialsFunc
	dispatchRequest func(context.Context, agentapi.Request) (json.RawMessage, *agentapi.Error)
}

func NewServer(conn net.Conn, expectedUID uint32) *Server {
	return &Server{
		conn:            conn,
		expectedUID:     expectedUID,
		peerCredentials: defaultPeerCredentials,
		dispatchRequest: dispatch,
	}
}

func (s *Server) ServeOne(ctx context.Context) error {
	credentials, err := s.peerCredentials(s.conn)
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if credentials.UID != s.expectedUID {
		return fmt.Errorf("%w: got UID %d", ErrUnauthorizedPeer, credentials.UID)
	}

	var request agentapi.Request
	framedConn := &idleConn{Conn: s.conn, ctx: ctx, timeout: frameIdleTimeout}
	if err := agentapi.ReadFrame(ctx, framedConn, &request); err != nil {
		return err
	}
	response := agentapi.Response{Version: agentapi.ProtocolVersion, ID: request.ID}
	if request.Version != agentapi.ProtocolVersion {
		response.Error = &agentapi.Error{Code: "unsupported_version", Message: "agent protocol version is unsupported"}
	} else {
		response.Result, response.Error = s.dispatchRequest(ctx, request)
	}
	return agentapi.WriteFrame(ctx, framedConn, response)
}
