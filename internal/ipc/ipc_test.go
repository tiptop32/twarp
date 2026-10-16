package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// socketPath is short: unix socket paths are limited to about 104 bytes.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "twarp-ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "run", "twarpd.sock")
}

func startServer(t *testing.T, path string, allowed []int, handler Handler, configure ...func(*Server)) *Server {
	t.Helper()
	server, err := Listen(path, allowed, handler)
	if err != nil {
		t.Fatal(err)
	}
	for _, apply := range configure {
		apply(server)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() = %v", err)
		}
	})
	return server
}

func callContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCallRoundTrip(t *testing.T) {
	path := socketPath(t)
	var got Request
	startServer(t, path, []int{os.Getuid()}, func(_ context.Context, request Request) Response {
		got = request
		return Response{OK: true, Summary: "tunnel on", Live: &LiveStatus{GatewayLive: "192.0.2.10:8080"}}
	})

	response, err := Call(callContext(t), path, Request{Op: OpUp, Actor: ActorCLI})
	if err != nil || response.Summary != "tunnel on" || response.Live == nil || response.Live.GatewayLive != "192.0.2.10:8080" {
		t.Fatalf("Call() = (%+v, %v), want the handler response", response, err)
	}
	if got != (Request{V: Version, Op: OpUp, Actor: ActorCLI}) {
		t.Fatalf("handler got %+v", got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o666 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, %v; want a 0666 socket", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("socket directory mode = %v, %v; want 0755", info.Mode(), err)
	}
}

func TestCallHandlerError(t *testing.T) {
	path := socketPath(t)
	startServer(t, path, []int{os.Getuid()}, func(context.Context, Request) Response {
		return Response{Error: "sing-box check failed"}
	})
	if _, err := Call(callContext(t), path, Request{Op: OpApply}); err == nil || err.Error() != "sing-box check failed" {
		t.Fatalf("Call() error = %v, want the handler error", err)
	}
}

func TestServerRejectsForeignUID(t *testing.T) {
	path := socketPath(t)
	var called, forbidden atomic.Int32
	startServer(t, path, []int{os.Getuid() + 1000}, func(context.Context, Request) Response {
		called.Add(1)
		return Response{OK: true}
	}, func(server *Server) {
		server.OnForbidden = func(uid int) {
			if uid == os.Getuid() {
				forbidden.Add(1)
			}
		}
	})
	if _, err := Call(callContext(t), path, Request{Op: OpDown}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Call() error = %v, want ErrForbidden", err)
	}
	if called.Load() != 0 || forbidden.Load() != 1 {
		t.Fatalf("handler calls = %d, forbidden callbacks = %d; want 0 and 1", called.Load(), forbidden.Load())
	}
}

func TestServerRejectsBadRequests(t *testing.T) {
	path := socketPath(t)
	startServer(t, path, []int{os.Getuid()}, func(context.Context, Request) Response {
		return Response{OK: true}
	})
	tests := []struct {
		name string
		line string
		want string
	}{
		{"unknown operation", `{"v":1,"op":"rm -rf"}`, "unknown operation"},
		{"unknown version", `{"v":2,"op":"up"}`, "unsupported protocol version"},
		{"unknown actor", `{"v":1,"op":"up","actor":"mcp"}`, "unknown actor"},
		{"extra field", `{"v":1,"op":"up","path":"/etc"}`, "unknown field"},
		{"too long", `{"v":1,"op":"up","actor":"` + strings.Repeat("a", MaxRequestSize) + `"}`, "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(tt.line + "\n")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 512)
			n, _ := conn.Read(reply)
			if got := string(reply[:n]); !strings.Contains(got, tt.want) || strings.Contains(got, `"ok":true`) {
				t.Fatalf("reply = %q, want an error containing %q", got, tt.want)
			}
		})
	}
}

func TestListenReplacesStaleSocketOnly(t *testing.T) {
	path := socketPath(t)
	stale, err := Listen(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// a crashed daemon leaves the file behind
	if unixListener, ok := stale.listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	_ = stale.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket must remain for the test: %v", err)
	}
	server, err := Listen(path, nil, nil)
	if err != nil {
		t.Fatalf("Listen() over a stale socket = %v", err)
	}
	_ = server.Close()

	regular := filepath.Join(filepath.Dir(path), "not-a-socket")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(regular, nil, nil); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Listen() over a regular file = %v, want refusal", err)
	}
	if data, err := os.ReadFile(regular); err != nil || string(data) != "keep" {
		t.Fatal("a regular file at the socket path must be left alone")
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	path := socketPath(t)
	if _, err := Call(callContext(t), path, Request{Op: OpStatus}); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Call(no socket) = %v, want ErrDaemonUnavailable", err)
	}
	stale, err := Listen(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unixListener, ok := stale.listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	_ = stale.Close()
	if _, err := Call(callContext(t), path, Request{Op: OpStatus}); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Call(stale socket) = %v, want ErrDaemonUnavailable", err)
	}
}

func TestSocketPath(t *testing.T) {
	if got := SocketPath(func(string) string { return "" }); got != DefaultSocket {
		t.Fatalf("SocketPath() = %q, want default", got)
	}
	if got := SocketPath(func(string) string { return "/tmp/x.sock" }); got != "/tmp/x.sock" {
		t.Fatalf("SocketPath(override) = %q", got)
	}
}
