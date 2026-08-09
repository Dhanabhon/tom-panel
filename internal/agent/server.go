package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
)

// ponytail: current operations are local-only; split framing and operation budgets when long-running operations land.
const requestTimeout = 2 * time.Second

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

var defaultPeerCredentials peerCredentialsFunc = func(net.Conn) (PeerCredentials, error) {
	return PeerCredentials{}, ErrPeerCredentialsUnsupported
}

type Server struct {
	conn            net.Conn
	expectedUID     uint32
	peerCredentials peerCredentialsFunc
}

func NewServer(conn net.Conn, expectedUID uint32) *Server {
	return &Server{conn: conn, expectedUID: expectedUID, peerCredentials: defaultPeerCredentials}
}

func (s *Server) ServeOne(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	credentials, err := s.peerCredentials(s.conn)
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if credentials.UID != s.expectedUID {
		return fmt.Errorf("%w: got UID %d", ErrUnauthorizedPeer, credentials.UID)
	}

	var request agentapi.Request
	if err := agentapi.ReadFrame(ctx, s.conn, &request); err != nil {
		return err
	}
	response := agentapi.Response{Version: agentapi.ProtocolVersion, ID: request.ID}
	if request.Version != agentapi.ProtocolVersion {
		response.Error = &agentapi.Error{Code: "unsupported_version", Message: "agent protocol version is unsupported"}
	} else {
		response.Result, response.Error = dispatch(request)
	}
	return agentapi.WriteFrame(ctx, s.conn, response)
}
