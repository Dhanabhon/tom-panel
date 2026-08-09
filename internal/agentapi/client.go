package agentapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

type Client struct {
	socketPath string
}

func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

func (c *Client) Call(ctx context.Context, operation string, input, output any) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	id, err := requestID()
	if err != nil {
		return err
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	request := Request{Version: ProtocolVersion, ID: id, Operation: operation, Payload: payload}
	if err := WriteFrame(ctx, conn, request); err != nil {
		return err
	}
	var response Response
	if err := ReadFrame(ctx, conn, &response); err != nil {
		return err
	}
	if response.Version != ProtocolVersion {
		return fmt.Errorf("unexpected agent protocol version %d", response.Version)
	}
	if response.ID != id {
		return errors.New("agent response ID does not match request")
	}
	if response.Error != nil {
		return response.Error
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, output); err != nil {
		return fmt.Errorf("decode agent response: %w", err)
	}
	return nil
}

func requestID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate agent request ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}
