package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// socketPath stays short: unix socket paths are limited to about 104 bytes.
func socketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "run", "twarpd.sock")
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	})
	return server
}

func echoHandler(_ context.Context, _ Peer, request Request) Response {
	return Response{OK: true, Summary: request.Op + " by " + request.Actor}
}

func call(t *testing.T, path string, request Request) (Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Call(ctx, path, request)
}

func TestCallRunsHandlerForAllowedPeer(t *testing.T) {
	path := socketPath(t)
	var gotPeer Peer
	startServer(t, path, []int{os.Getuid()}, func(ctx context.Context, peer Peer, request Request) Response {
		gotPeer = peer
		return echoHandler(ctx, peer, request)
	})
	response, err := call(t, path, Request{Op: OpUp, Actor: ActorCLI})
	if err != nil || !response.OK || response.Summary != "up by cli" {
		t.Fatalf("Call() = (%+v, %v)", response, err)
	}
	if gotPeer.UID != os.Getuid() {
		t.Fatalf("peer uid = %d, want %d", gotPeer.UID, os.Getuid())
	}
	for path, want := range map[string]os.FileMode{path: 0o666, filepath.Dir(path): 0o755} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
		}
	}
}

func TestServerRejectsPeerOutsideAllowedUIDs(t *testing.T) {
	path := socketPath(t)
	var mu sync.Mutex
	var forbidden []Peer
	handled := false
	startServer(t, path, []int{os.Getuid() + 12345}, func(context.Context, Peer, Request) Response {
		mu.Lock()
		defer mu.Unlock()
		handled = true
		return Response{OK: true}
	}, func(server *Server) {
		server.OnForbidden = func(peer Peer) {
			mu.Lock()
			defer mu.Unlock()
			forbidden = append(forbidden, peer)
		}
	})
	response, err := call(t, path, Request{Op: OpDown, Actor: ActorCLI})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Code != CodeForbidden || !errors.Is(response.Err(), ErrForbidden) {
		t.Fatalf("response = %+v, want forbidden", response)
	}
	mu.Lock()
	defer mu.Unlock()
	if handled || len(forbidden) != 1 || forbidden[0].UID != os.Getuid() {
		t.Fatalf("handled = %t, forbidden = %v", handled, forbidden)
	}
}

func TestServerRejectsBadRequests(t *testing.T) {
	path := socketPath(t)
	startServer(t, path, []int{os.Getuid()}, echoHandler)
	for name, request := range map[string]Request{
		"version":   {V: 2, Op: OpUp, Actor: ActorCLI},
		"operation": {Op: "install", Actor: ActorCLI},
		"actor":     {Op: OpUp, Actor: "mcp"},
	} {
		response, err := call(t, path, request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if response.OK || response.Code != CodeBadRequest {
			t.Fatalf("%s: response = %+v, want bad request", name, response)
		}
	}

	for name, line := range map[string]string{
		"too long":      `{"v":1,"op":"up","actor":"cli","pad":"` + strings.Repeat("x", MaxRequestBytes) + "\"}\n",
		"unknown field": `{"v":1,"op":"up","actor":"cli","path":"/etc"}` + "\n",
		"not json":      "up\n",
	} {
		connection, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1024)
		n, _ := connection.Read(buffer)
		_ = connection.Close()
		if !strings.Contains(string(buffer[:n]), `"code":"bad_request"`) {
			t.Fatalf("%s: response = %q, want bad request", name, buffer[:n])
		}
	}
}

func TestListenReplacesStaleSocketOnly(t *testing.T) {
	path := socketPath(t)
	first, err := Listen(path, []int{os.Getuid()}, echoHandler)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the socket file behind, as a crashed daemon would.
	if listener, ok := first.listener.(*net.UnixListener); ok {
		listener.SetUnlinkOnClose(false)
	}
	_ = first.Close()
	startServer(t, path, []int{os.Getuid()}, echoHandler)
	if response, err := call(t, path, Request{Op: OpStatus, Actor: ActorTUI}); err != nil || !response.OK {
		t.Fatalf("Call() after stale socket = (%+v, %v)", response, err)
	}

	regular := filepath.Join(filepath.Dir(path), "file")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(regular, nil, echoHandler); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Listen() over a regular file error = %v", err)
	}
	if data, _ := os.ReadFile(regular); string(data) != "keep" {
		t.Fatal("Listen() replaced a regular file")
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	path := socketPath(t)
	if _, err := call(t, path, Request{Op: OpStatus, Actor: ActorCLI}); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Call() without socket error = %v, want ErrDaemonUnavailable", err)
	}
	server, err := Listen(path, []int{os.Getuid()}, echoHandler)
	if err != nil {
		t.Fatal(err)
	}
	if listener, ok := server.listener.(*net.UnixListener); ok {
		listener.SetUnlinkOnClose(false)
	}
	_ = server.Close()
	if _, err := call(t, path, Request{Op: OpStatus, Actor: ActorCLI}); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Call() to a dead socket error = %v, want ErrDaemonUnavailable", err)
	}
}

func TestServerCapsConnectionsAndTimesOutSilentClients(t *testing.T) {
	path := socketPath(t)
	release := make(chan struct{})
	startServer(t, path, []int{os.Getuid()}, func(context.Context, Peer, Request) Response {
		<-release
		return Response{OK: true}
	})
	defer close(release)
	var connections []net.Conn
	for range maxConnections {
		connection, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		if _, err := connection.Write([]byte(`{"v":1,"op":"up","actor":"cli"}` + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, err := call(t, path, Request{Op: OpStatus, Actor: ActorCLI})
		if err == nil && response.Code == CodeBusy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("extra connection = (%+v, %v), want busy", response, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTimeouts(t *testing.T) {
	if Timeout(OpStatus) != 5*time.Second || Timeout(OpUp) != time.Minute || Timeout(OpGeoUpdate) <= Timeout(OpApply) {
		t.Fatal("unexpected client timeouts")
	}
}
