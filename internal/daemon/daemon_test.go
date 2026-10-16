package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/ipc"
)

// fakeOps records operations per actor and fails if two overlap.
type fakeOps struct {
	world *fakeWorld
	actor string
}

type fakeWorld struct {
	mu      sync.Mutex
	calls   []string // "actor op"
	audits  []string // "actor op result"
	running atomic.Int32
	overlap atomic.Bool
	// apply moves the live gateway to resolved, as a real Apply would
	resolved netip.AddrPort
	live     app.LiveConfig
	liveErr  error
	applyErr error
	hold     chan struct{} // when set, Apply waits on it
}

func (ops fakeOps) enter(op string) func() {
	if ops.world.running.Add(1) > 1 {
		ops.world.overlap.Store(true)
	}
	ops.world.mu.Lock()
	ops.world.calls = append(ops.world.calls, ops.actor+" "+op)
	ops.world.mu.Unlock()
	return func() { ops.world.running.Add(-1) }
}

func (ops fakeOps) Apply(context.Context) (string, error) {
	defer ops.enter("apply")()
	if ops.world.hold != nil {
		<-ops.world.hold
	}
	ops.world.mu.Lock()
	defer ops.world.mu.Unlock()
	if ops.world.applyErr != nil {
		return "", ops.world.applyErr
	}
	ops.world.live = app.LiveConfig{Gateway: ops.world.resolved, AppliedAt: time.Unix(2000, 0)}
	ops.world.liveErr = nil
	return "applied", nil
}

func (ops fakeOps) Start(context.Context) (string, error) {
	defer ops.enter("start")()
	return "started", nil
}

func (ops fakeOps) Stop(context.Context) (string, error) {
	defer ops.enter("stop")()
	return "stopped", nil
}

func (ops fakeOps) GeoUpdate(context.Context) (geo.Report, error) {
	defer ops.enter("geo")()
	return geo.Report{Files: []geo.FileReport{{Name: "geoip-ru.srs", Size: 10}}}, nil
}

func (ops fakeOps) AuditRoot(operation, result string) error {
	ops.world.mu.Lock()
	defer ops.world.mu.Unlock()
	ops.world.audits = append(ops.world.audits, ops.actor+" "+operation+" "+result)
	return nil
}

func (world *fakeWorld) snapshot() ([]string, []string) {
	world.mu.Lock()
	defer world.mu.Unlock()
	return append([]string(nil), world.calls...), append([]string(nil), world.audits...)
}

type fixture struct {
	world      *fakeWorld
	daemon     *Daemon
	configured string
	resolves   atomic.Int32
	resolveErr error
}

func newFixture(t *testing.T, configured string) *fixture {
	t.Helper()
	f := &fixture{
		world: &fakeWorld{
			resolved: netip.MustParseAddrPort("192.0.2.20:8080"),
			live:     app.LiveConfig{Gateway: netip.MustParseAddrPort("192.0.2.10:8080"), AppliedAt: time.Unix(1000, 0)},
		},
		configured: configured,
	}
	f.daemon = New(Deps{
		Ops:        func(actor string) Ops { return fakeOps{world: f.world, actor: actor} },
		Configured: func() (string, error) { return f.configured, nil },
		Resolve: func(context.Context, string) (netip.AddrPort, error) {
			f.resolves.Add(1)
			if f.resolveErr != nil {
				return netip.AddrPort{}, f.resolveErr
			}
			return f.world.resolved, nil
		},
		Live: func() (app.LiveConfig, error) {
			f.world.mu.Lock()
			defer f.world.mu.Unlock()
			return f.world.live, f.world.liveErr
		},
		Stale:  func(appliedAt time.Time) (bool, error) { return appliedAt.Before(time.Unix(1500, 0)), nil },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return f
}

func TestCheckNetworkReappliesOnlyOnAddressChange(t *testing.T) {
	f := newFixture(t, "proxyhost.local:8080")

	f.daemon.CheckNetwork(t.Context())
	calls, _ := f.world.snapshot()
	if want := []string{app.ActorDaemonNet + " apply"}; fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want one network apply", calls)
	}

	// same address on the next check: nothing to do
	f.daemon.CheckNetwork(t.Context())
	if calls, _ := f.world.snapshot(); len(calls) != 1 {
		t.Fatalf("calls = %v, want no second apply for an unchanged address", calls)
	}
}

func TestCheckNetworkKeepsConfigWhenResolveFails(t *testing.T) {
	f := newFixture(t, "proxyhost.local:8080")
	f.resolveErr = errors.New("i/o timeout")

	f.daemon.CheckNetwork(t.Context())
	if calls, _ := f.world.snapshot(); len(calls) != 0 {
		t.Fatalf("calls = %v, want no apply after a failed lookup", calls)
	}
	status := f.daemon.LiveStatus()
	if status.LastResolveError == "" || status.GatewayLive != "192.0.2.10:8080" {
		t.Fatalf("status = %+v, want the resolve error and the old live address", status)
	}

	f.resolveErr = nil
	f.daemon.CheckNetwork(t.Context())
	if status := f.daemon.LiveStatus(); status.LastResolveError != "" || status.GatewayLive != "192.0.2.20:8080" {
		t.Fatalf("status = %+v, want the error cleared and the new address", status)
	}
}

func TestCheckNetworkSkipsLiteralsAndMissingInstall(t *testing.T) {
	f := newFixture(t, "192.0.2.10:8080")
	f.daemon.CheckNetwork(t.Context())
	if f.resolves.Load() != 0 {
		t.Fatal("an IP literal must not be resolved")
	}

	f = newFixture(t, "proxyhost.local:8080")
	f.world.liveErr = fmt.Errorf("stat running config: %w", os.ErrNotExist)
	f.daemon.CheckNetwork(t.Context())
	if calls, _ := f.world.snapshot(); len(calls) != 0 {
		t.Fatalf("calls = %v, want no apply before install", calls)
	}
}

func TestHandleRunsOperationsWithActors(t *testing.T) {
	f := newFixture(t, "proxyhost.local:8080")
	for _, request := range []ipc.Request{
		{V: 1, Op: ipc.OpUp, Actor: ipc.ActorCLI},
		{V: 1, Op: ipc.OpDown, Actor: ipc.ActorTUI},
		{V: 1, Op: ipc.OpApply},
		{V: 1, Op: ipc.OpGeoUpdate},
	} {
		if response := f.daemon.Handle(t.Context(), request); !response.OK {
			t.Fatalf("Handle(%s) = %+v", request.Op, response)
		}
	}
	calls, audits := f.world.snapshot()
	wantCalls := []string{
		"daemon-cli apply", "daemon-cli start",
		"daemon-tui stop",
		"daemon-cli apply",
		"daemon-cli geo",
	}
	if fmt.Sprint(calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	wantAudits := []string{"daemon-cli up ok", "daemon-tui down ok", "daemon-cli geo_update ok"}
	if fmt.Sprint(audits) != fmt.Sprint(wantAudits) {
		t.Fatalf("audits = %v, want %v", audits, wantAudits)
	}

	f.world.applyErr = errors.New("sing-box check failed")
	if response := f.daemon.Handle(t.Context(), ipc.Request{V: 1, Op: ipc.OpUp}); response.OK || response.Error != "sing-box check failed" {
		t.Fatalf("Handle(up with failing apply) = %+v", response)
	}

	status := f.daemon.Handle(t.Context(), ipc.Request{V: 1, Op: ipc.OpStatus})
	if !status.OK || status.Live == nil || status.Live.GatewayConfigured != "proxyhost.local:8080" {
		t.Fatalf("Handle(status) = %+v", status)
	}
}

func TestStatusReportsStaleConfig(t *testing.T) {
	f := newFixture(t, "proxyhost.local:8080")
	if status := f.daemon.LiveStatus(); !status.Stale || status.GatewayLive != "192.0.2.10:8080" {
		t.Fatalf("status = %+v, want stale with the live address", status)
	}
	f.world.liveErr = os.ErrNotExist
	if status := f.daemon.LiveStatus(); status.GatewayLive != "" || status.Stale {
		t.Fatalf("status without config.json = %+v", status)
	}
}

func TestOperationsAreSerialized(t *testing.T) {
	f := newFixture(t, "proxyhost.local:8080")
	f.world.hold = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		f.daemon.Handle(context.Background(), ipc.Request{V: 1, Op: ipc.OpUp})
	}()
	go func() {
		defer wg.Done()
		f.daemon.CheckNetwork(context.Background())
	}()
	time.Sleep(50 * time.Millisecond)
	close(f.world.hold)
	wg.Wait()
	if f.world.overlap.Load() {
		t.Fatal("up and the network re-apply ran in parallel")
	}
}

func TestRunServesTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "twarpd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := newFixture(t, "192.0.2.10:8080")
	f.daemon.deps.Socket = filepath.Join(dir, "twarpd.sock")
	f.daemon.deps.AllowedUIDs = []int{os.Getuid()}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.daemon.Run(ctx) }()

	callCtx, cancelCall := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelCall()
	var response ipc.Response
	for {
		response, err = ipc.Call(callCtx, f.daemon.deps.Socket, ipc.Request{Op: ipc.OpDown, Actor: ipc.ActorCLI})
		if !errors.Is(err, ipc.ErrDaemonUnavailable) || callCtx.Err() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || response.Summary != "stopped" {
		t.Fatalf("Call(down) = (%+v, %v)", response, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v", err)
	}
}
