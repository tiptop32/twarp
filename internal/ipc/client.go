package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"syscall"
	"time"
)

// ErrDaemonUnavailable reports that no daemon listens on the socket.
var ErrDaemonUnavailable = errors.New("twarpd is not running")

// Call sends one request and returns the daemon's response. The deadline of
// ctx bounds the whole exchange. A missing socket or a refused connection is
// ErrDaemonUnavailable.
func Call(ctx context.Context, path string, request Request) (Response, error) {
	if request.V == 0 {
		request.V = Version
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return Response{}, fmt.Errorf("%w: %w", ErrDaemonUnavailable, err)
		}
		return Response{}, fmt.Errorf("connect to twarpd: %w", err)
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()

	data, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}
	// A refused or busy caller gets its answer before the server reads the
	// request, and the server may close first: a failed write still has a
	// response to read.
	_, writeErr := connection.Write(append(data, '\n'))
	line, err := bufio.NewReaderSize(io.LimitReader(connection, maxResponseBytes), maxResponseBytes).ReadSlice('\n')
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		if ctx.Err() != nil {
			return Response{}, fmt.Errorf("twarpd did not answer %s in time: %w", request.Op, ctx.Err())
		}
		if writeErr != nil {
			return Response{}, fmt.Errorf("send to twarpd: %w", writeErr)
		}
		return Response{}, fmt.Errorf("read twarpd response: %w", err)
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		return Response{}, fmt.Errorf("decode twarpd response: %w", err)
	}
	return response, nil
}
