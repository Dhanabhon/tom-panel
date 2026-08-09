package agentapi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ProtocolVersion uint16 = 1
	MaxFrameSize           = 1 << 20
)

var (
	ErrFrameTooLarge  = errors.New("agent frame exceeds 1 MiB")
	ErrMalformedFrame = errors.New("malformed agent frame")
)

type Request struct {
	Version   uint16          `json:"version"`
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type Response struct {
	Version uint16          `json:"version"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

func ReadFrame(ctx context.Context, conn net.Conn, output any) error {
	stop, err := setReadDeadline(ctx, conn)
	if err != nil {
		return err
	}
	defer stop()

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return contextError(ctx, err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrameSize {
		return ErrFrameTooLarge
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return contextError(ctx, err)
	}
	if err := json.Unmarshal(payload, output); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedFrame, err)
	}
	return nil
}

func WriteFrame(ctx context.Context, conn net.Conn, input any) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	stop, err := setWriteDeadline(ctx, conn)
	if err != nil {
		return err
	}
	defer stop()

	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return contextError(ctx, err)
		}
		frame = frame[n:]
	}
	return nil
}

func setReadDeadline(ctx context.Context, conn net.Conn) (func(), error) {
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	return func() { stop() }, nil
}

func setWriteDeadline(ctx context.Context, conn net.Conn) (func(), error) {
	deadline, _ := ctx.Deadline()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) })
	return func() { stop() }, nil
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}
