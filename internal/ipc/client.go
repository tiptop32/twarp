package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

const maxResponseSize = 1 << 20

// SocketPath returns TWARP_SOCKET or DefaultSocket.
func SocketPath(getenv func(string) string) string {
	if path := getenv("TWARP_SOCKET"); path != "" {
		return path
	}
	return DefaultSocket
}

// Call sends one request and returns the daemon's response. A missing socket
// or a refused connection is ErrDaemonUnavailable; a refused peer is
// ErrForbidden; any other failed operation returns the response with its
// Error as the error.
func Call(ctx context.Context, path string, request Request) (Response, error) {
	request.V = Version
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return Response{}, fmt.Errorf("%w (%s)", ErrDaemonUnavailable, path)
		}
		return Response{}, fmt.Errorf("connect to twarpd: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	data, err := json.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return Response{}, fmt.Errorf("send request: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxResponseSize)).ReadBytes('\n')
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		if ctx.Err() != nil {
			return Response{}, fmt.Errorf("twarpd: %w", ctx.Err())
		}
		return Response{}, fmt.Errorf("read response: %w", err)
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	switch {
	case response.OK:
		return response, nil
	case response.Error == ErrorForbidden:
		return response, ErrForbidden
	default:
		return response, errors.New(response.Error)
	}
}
