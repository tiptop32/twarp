package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// readTimeout bounds how long a client may take to send its request.
	readTimeout = 5 * time.Second
	// writeTimeout bounds how long a client may take to read the answer.
	writeTimeout = 10 * time.Second
	// maxConnections caps concurrent clients; more get CodeBusy.
	maxConnections = 8
)

// Peer identifies the process on the other end of a connection.
type Peer struct {
	UID int
}

// Handler runs one validated request from an authorized peer.
type Handler func(ctx context.Context, peer Peer, request Request) Response

// Server answers one request per connection on a unix socket.
type Server struct {
	listener net.Listener
	allowed  map[int]bool
	handler  Handler
	slots    chan struct{}
	// OnForbidden is called for every rejected peer, for the audit log. Set it
	// before Serve.
	OnForbidden func(peer Peer)
	wg          sync.WaitGroup
}

// Listen creates the socket at path. Its directory is made 0755 and the
// socket 0666: anyone may connect, and every connection is authorized by the
// peer uid the kernel reports, which must be in allowedUIDs. A stale socket
// is replaced; any other file at path is an error, never deleted.
func Listen(path string, allowedUIDs []int, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("ipc: handler is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		return nil, fmt.Errorf("set socket directory mode: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set socket mode: %w", err)
	}
	allowed := make(map[int]bool, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		allowed[uid] = true
	}
	return &Server{listener: listener, allowed: allowed, handler: handler, slots: make(chan struct{}, maxConnections)}, nil
}

// Serve accepts connections until ctx is done, then waits for running
// requests and closes the listener.
func (server *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = server.listener.Close() })
	defer stop()
	defer server.wg.Wait()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case server.slots <- struct{}{}:
		default:
			writeResponse(connection, Response{Code: CodeBusy, Error: "twarpd is busy, try again"})
			_ = connection.Close()
			continue
		}
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			defer func() { <-server.slots }()
			server.handle(ctx, connection)
		}()
	}
}

// Close stops accepting connections.
func (server *Server) Close() error {
	return server.listener.Close()
}

func (server *Server) handle(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()
	uid, err := peerUID(connection)
	if err != nil {
		writeResponse(connection, Response{Code: CodeForbidden, Error: "cannot identify the caller: " + err.Error()})
		return
	}
	peer := Peer{UID: uid}
	if !server.allowed[uid] {
		if server.OnForbidden != nil {
			server.OnForbidden(peer)
		}
		writeResponse(connection, Response{Code: CodeForbidden, Error: fmt.Sprintf("uid %d may not control this twarp", uid)})
		return
	}
	_ = connection.SetReadDeadline(time.Now().Add(readTimeout))
	request, err := readRequest(connection)
	if err != nil {
		writeResponse(connection, Response{Code: CodeBadRequest, Error: err.Error()})
		return
	}
	writeResponse(connection, server.handler(ctx, peer, request))
}

func readRequest(reader io.Reader) (Request, error) {
	line, err := bufio.NewReaderSize(io.LimitReader(reader, MaxRequestBytes+1), MaxRequestBytes+1).ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > MaxRequestBytes {
		return Request{}, fmt.Errorf("request is larger than %d bytes", MaxRequestBytes)
	}
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
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

func writeResponse(connection net.Conn, response Response) {
	_ = connection.SetWriteDeadline(time.Now().Add(writeTimeout))
	data, err := json.Marshal(response)
	if err != nil {
		data = []byte(`{"ok":false,"code":"failed","error":"encode response"}`)
	}
	_, _ = connection.Write(append(data, '\n'))
}
