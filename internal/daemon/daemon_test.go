package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/ipc"
)

type testSys struct{ env map[string]string }

func (testSys) Geteuid() int                          { return 501 }
func (system testSys) Getenv(name string) string      { return system.env[name] }
func (testSys) LookupUser(string) (*user.User, error) { return nil, errors.New("no users") }
func (testSys) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

// fakeService records calls. Apply rewrites config.json with the address the
// daemon's resolver returns, like the real render would.
type fakeService struct {
	fixture *fixture
	actor   string
	resolve ResolveFunc
}

func (service fakeService) Apply(ctx context.Context) (string, error) {
	service.fixture.enter(service.actor + ":apply")
	defer service.fixture.leave()
	if service.fixture.applyErr != nil {
		return "", service.fixture.applyErr
	}
	addr, err := service.resolve(ctx, service.fixture.socks)
	if err != nil {
		return "", err
	}
	service.fixture.writeLive(addr.String())
	return "applied and reloaded sing-box", nil
}

func (service fakeService) Start(context.Context) (string, error) {
	service.fixture.enter(service.actor + ":start")
	defer service.fixture.leave()
	return "started", nil
}

func (service fakeService) Stop(context.Context) (string, error) {
	service.fixture.enter(service.actor + ":stop")
	defer service.fixture.leave()
	return "stopped", nil
}

func (service fakeService) GeoUpdate(context.Context) (geo.Report, error) {
	service.fixture.enter(service.actor + ":geo")
	defer service.fixture.leave()
	return geo.Report{Files: []geo.FileReport{{Name: "geoip-ru.srs", Size: 10}}}, nil
}

func (service fakeService) Audit(operation, result string) error {
	service.fixture.mu.Lock()
	defer service.fixture.mu.Unlock()
	service.fixture.audits = append(service.fixture.audits, service.actor+":"+operation+":"+result)
	return nil
}

type fixture struct {
	t     *testing.T
	home  string
	out   string
	socks string

	mu        sync.Mutex
	calls     []string
	audits    []string
	lookups   int
	answer    []string
	lookupErr error
	applyErr  error
	active    int
	maxActive int
	hold      chan struct{}
}

func newFixture(t *testing.T, socks, live string) (*fixture, *Daemon) {
	t.Helper()
	base, err := os.MkdirTemp("", "twarpd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	f := &fixture{t: t, home: filepath.Join(base, "home"), out: filepath.Join(base, "out"), socks: socks, answer: []string{"192.0.2.10"}}
	for _, directory := range []string{f.home, f.out} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	configText := fmt.Sprintf("gateway:\n  socks: %s\n  domains: [intra.example]\n  dns: 100.64.0.53\n", socks)
	if err := os.WriteFile(filepath.Join(f.home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	if live != "" {
		f.writeLive(live)
	}
	daemon := New(Deps{
		Sys:        testSys{env: map[string]string{"TWARP_HOME": f.home, "TWARP_OUT": f.out, "TWARP_SINGBOX": "/bin/true"}},
		SocketPath: filepath.Join(base, "run", "twarpd.sock"),
		OwnerUID:   os.Getuid(),
		NewService: func(actor string, resolve ResolveFunc) Service {
			return fakeService{fixture: f, actor: actor, resolve: resolve}
		},
		Lookup: f.lookup,
	})
	return f, daemon
}

func (f *fixture) lookup(context.Context, string, string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	ips := make([]net.IP, len(f.answer))
	for index, answer := range f.answer {
		ips[index] = net.ParseIP(answer)
	}
	return ips, nil
}

// writeLive writes a running config.json whose gateway outbound dials live
// and dates it in the past, so twarp.yaml written later counts as newer only
// when a test touches it.
func (f *fixture) writeLive(live string) {
	f.t.Helper()
	addr := netip.MustParseAddrPort(live)
	data := fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"gateway","server":%q,"server_port":%d}]}`, addr.Addr(), addr.Port())
	path := filepath.Join(f.out, "config.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) enter(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.active++
	f.maxActive = max(f.maxActive, f.active)
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
}

func (f *fixture) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active--
}

func (f *fixture) snapshot() (calls []string, lookups int, audits []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), f.lookups, append([]string(nil), f.audits...)
}

func TestCheckNetworkAppliesOnlyWhenAddressChanges(t *testing.T) {
	f, daemon := newFixture(t, "proxy.local:1080", "192.0.2.10:1080")
	daemon.CheckNetwork(context.Background())
	if calls, _, _ := f.snapshot(); len(calls) != 0 {
		t.Fatalf("calls with the same address = %v, want none", calls)
	}

	f.mu.Lock()
	f.answer = []string{"fe80::1", "192.0.2.20"}
	f.mu.Unlock()
	daemon.CheckNetwork(context.Background())
	calls, lookups, audits := f.snapshot()
	if strings.Join(calls, ",") != ActorNet+":apply" {
		t.Fatalf("calls after the address changed = %v, want one network apply", calls)
	}
	if lookups != 2 {
		t.Fatalf("lookups = %d, want 2: the apply reuses the address just resolved", lookups)
	}
	if len(audits) != 1 || !strings.Contains(audits[0], "gateway_change:192.0.2.10:1080 -> 192.0.2.20:1080") {
		t.Fatalf("audits = %v", audits)
	}
	live, err := daemon.LiveStatus()
	if err != nil || live.GatewayLive != "192.0.2.20:1080" || live.GatewayConfigured != "proxy.local:1080" {
		t.Fatalf("LiveStatus() = (%+v, %v)", live, err)
	}

	daemon.CheckNetwork(context.Background())
	if calls, _, _ := f.snapshot(); len(calls) != 1 {
		t.Fatalf("calls after a second check = %v, want still one", calls)
	}
}

func TestCheckNetworkKeepsConfigWhenNameDoesNotResolve(t *testing.T) {
	f, daemon := newFixture(t, "proxy.local:1080", "192.0.2.10:1080")
	f.lookupErr = context.DeadlineExceeded
	daemon.CheckNetwork(context.Background())
	if calls, _, _ := f.snapshot(); len(calls) != 0 {
		t.Fatalf("calls = %v, want none", calls)
	}
	live, err := daemon.LiveStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.LastResolveError, "proxy.local does not resolve") || !strings.Contains(live.LastResolveError, "running on 192.0.2.10:1080") {
		t.Fatalf("LastResolveError = %q", live.LastResolveError)
	}

	f.mu.Lock()
	f.lookupErr = nil
	f.mu.Unlock()
	daemon.CheckNetwork(context.Background())
	if live, _ := daemon.LiveStatus(); live.LastResolveError != "" {
		t.Fatalf("LastResolveError after recovery = %q", live.LastResolveError)
	}
}

func TestCheckNetworkSkipsLiteralAndUninstalled(t *testing.T) {
	f, daemon := newFixture(t, "192.0.2.10:1080", "192.0.2.10:1080")
	daemon.CheckNetwork(context.Background())
	if calls, lookups, _ := f.snapshot(); len(calls) != 0 || lookups != 0 {
		t.Fatalf("IP literal: calls = %v, lookups = %d, want none", calls, lookups)
	}

	f, daemon = newFixture(t, "proxy.local:1080", "")
	daemon.CheckNetwork(context.Background())
	if calls, lookups, _ := f.snapshot(); len(calls) != 0 || lookups != 0 {
		t.Fatalf("not installed: calls = %v, lookups = %d, want none", calls, lookups)
	}
}

func TestLiveStatusReportsStaleConfig(t *testing.T) {
	f, daemon := newFixture(t, "192.0.2.10:1080", "192.0.2.10:1080")
	live, err := daemon.LiveStatus()
	if err != nil || live.Stale || live.ConfigAppliedAt.IsZero() {
		t.Fatalf("fresh LiveStatus() = (%+v, %v)", live, err)
	}
	later := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(f.home, "twarp.yaml"), later, later); err != nil {
		t.Fatal(err)
	}
	if live, err := daemon.LiveStatus(); err != nil || !live.Stale {
		t.Fatalf("LiveStatus() after editing twarp.yaml = (%+v, %v), want stale", live, err)
	}
}

func startDaemon(t *testing.T, daemon *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run() error = %v", err)
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(daemon.deps.SocketPath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func request(t *testing.T, daemon *Daemon, op string) ipc.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := ipc.Call(ctx, daemon.deps.SocketPath, ipc.Request{Op: op, Actor: ipc.ActorCLI})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRunServesOperationsOverSocket(t *testing.T) {
	f, daemon := newFixture(t, "192.0.2.10:1080", "192.0.2.10:1080")
	startDaemon(t, daemon)

	// The config is fresh, so up starts without reloading sing-box.
	if response := request(t, daemon, ipc.OpUp); !response.OK || response.Summary != "started" {
		t.Fatalf("up = %+v", response)
	}
	later := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(f.home, "twarp.yaml"), later, later); err != nil {
		t.Fatal(err)
	}
	if response := request(t, daemon, ipc.OpUp); !response.OK || response.Summary != "applied and reloaded sing-box\nstarted" {
		t.Fatalf("up with a stale config = %+v", response)
	}
	for op, want := range map[string]string{ipc.OpDown: "stopped", ipc.OpApply: "applied and reloaded sing-box"} {
		if response := request(t, daemon, op); !response.OK || response.Summary != want {
			t.Fatalf("%s = %+v", op, response)
		}
	}
	if response := request(t, daemon, ipc.OpGeoUpdate); !response.OK || !strings.HasPrefix(response.Summary, "updated geoip-ru.srs: 10 bytes") {
		t.Fatalf("geo_update = %+v", response)
	}
	response := request(t, daemon, ipc.OpStatus)
	if !response.OK || response.Live == nil || response.Live.GatewayLive != "192.0.2.10:1080" {
		t.Fatalf("status = %+v", response)
	}

	calls, _, _ := f.snapshot()
	want := "daemon-cli:start,daemon-cli:apply,daemon-cli:start,daemon-cli:stop,daemon-cli:apply,daemon-cli:geo"
	if strings.Join(calls, ",") != want {
		t.Fatalf("calls = %v, want %s", calls, want)
	}

	f.applyErr = errors.New("sing-box check failed")
	if response := request(t, daemon, ipc.OpApply); response.OK || response.Code != ipc.CodeFailed || response.Error != "sing-box check failed" {
		t.Fatalf("failed apply = %+v", response)
	}
}

func TestOperationsAndNetworkApplySerialize(t *testing.T) {
	f, daemon := newFixture(t, "proxy.local:1080", "192.0.2.10:1080")
	startDaemon(t, daemon)
	f.mu.Lock()
	f.hold = make(chan struct{})
	f.answer = []string{"192.0.2.20"}
	f.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); request(t, daemon, ipc.OpDown) }()
	go func() { defer wg.Done(); daemon.CheckNetwork(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		calls, _, _ := f.snapshot()
		if len(calls) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no operation started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	hold := f.hold
	f.hold = nil
	f.mu.Unlock()
	close(hold)
	wg.Wait()

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.maxActive != 1 || len(f.calls) != 2 {
		t.Fatalf("calls = %v, max concurrent = %d, want 2 calls one at a time", f.calls, f.maxActive)
	}
}
