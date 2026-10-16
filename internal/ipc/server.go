package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const responseWriteTimeout = 10 * time.Second

// Handler serves one validated request from an allowed peer.
type Handler func(ctx context.Context, request Request) Response

// Server accepts requests on a unix socket.
type Server struct {
	listener net.Listener
	allowed  map[int]bool
	handler  Handler
	// OnForbidden, when set, is called for every refused peer (for the
	// root audit log).
	OnForbidden func(uid int)
	wg          sync.WaitGroup
}

// Listen creates the socket directory (0755), replaces a stale socket file,
// listens on path and opens the socket to everyone (0666): authorization is
// the kernel-reported peer uid, which must be in allowedUIDs.
func Listen(path string, allowedUIDs []int, handler Handler) (*Server, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create socket directory %q: %w", directory, err)
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("open socket %q: %w", path, err)
	}
	allowed := make(map[int]bool, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		allowed[uid] = true
	}
	return &Server{listener: listener, allowed: allowed, handler: handler}, nil
}

// removeStaleSocket deletes a socket left by a previous daemon. Anything
// else at the path is left alone: it is not ours to delete.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket %q: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%q exists and is not a socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %q: %w", path, err)
	}
	return nil
}

// Addr is the socket path.
func (server *Server) Addr() string { return server.listener.Addr().String() }

// Serve accepts connections until ctx is cancelled, then waits for the
// requests in flight.
func (server *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = server.listener.Close() })
	defer stop()
	defer server.wg.Wait()
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			defer func() { _ = conn.Close() }()
			server.serveConn(ctx, conn)
		}()
	}
}

// Close stops accepting connections.
func (server *Server) Close() error { return server.listener.Close() }

func (server *Server) serveConn(ctx context.Context, conn net.Conn) {
	uid, err := peerUID(conn)
	if err != nil {
		writeResponse(conn, Response{Error: "read peer credentials: " + err.Error()})
		return
	}
	if !server.allowed[uid] {
		if server.OnForbidden != nil {
			server.OnForbidden(uid)
		}
		writeResponse(conn, Response{Error: ErrorForbidden})
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(responseWriteTimeout))
	request, err := readRequest(conn)
	if err != nil {
		writeResponse(conn, Response{Error: err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	writeResponse(conn, server.handler(ctx, request))
}

func readRequest(reader io.Reader) (Request, error) {
	line, err := bufio.NewReaderSize(io.LimitReader(reader, MaxRequestSize+1), MaxRequestSize+1).ReadBytes('\n')
	if len(line) > MaxRequestSize {
		return Request{}, fmt.Errorf("request exceeds %d bytes", MaxRequestSize)
	}
	if err != nil {
		return Request{}, fmt.Errorf("read request: %w", err)
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

func writeResponse(conn net.Conn, response Response) {
	data, err := json.Marshal(response)
	if err != nil {
		data = []byte(`{"ok":false,"error":"encode response"}`)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
	_, _ = conn.Write(append(data, '\n'))
}

func peerUID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		uid    int
		uidErr error
	)
	if err := raw.Control(func(fd uintptr) { uid, uidErr = peerUIDFromFD(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, uidErr
}
