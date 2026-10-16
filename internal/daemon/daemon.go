// Package daemon is twarpd: the long-lived root process that runs twarp
// operations for its owner over a unix socket (internal/ipc) and re-applies
// the config when a network change moves the gateway host to another
// address.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/netwatch"
)

// Defaults for the network watch.
const (
	DefaultDebounce = 2 * time.Second
	DefaultTick     = 30 * time.Second
)

// Ops are the app.Service operations the daemon runs.
type Ops interface {
	Apply(ctx context.Context) (string, error)
	Start(ctx context.Context) (string, error)
	Stop(ctx context.Context) (string, error)
	GeoUpdate(ctx context.Context) (geo.Report, error)
	AuditRoot(operation, result string) error
}

// Deps are the daemon's boundaries; tests replace them with fakes.
type Deps struct {
	Socket      string
	AllowedUIDs []int
	// Ops returns the operations for an audit actor.
	Ops func(actor string) Ops
	// Configured returns gateway.socks as written in twarp.yaml.
	Configured func() (string, error)
	// Resolve resolves a gateway.socks host name (see gwaddr).
	Resolve func(ctx context.Context, hostport string) (netip.AddrPort, error)
	// Live reads the running config.json.
	Live func() (app.LiveConfig, error)
	// Stale reports whether the config sources changed after appliedAt.
	Stale func(appliedAt time.Time) (bool, error)
	// Events are network-change notifications; nil leaves only the tick.
	Events   <-chan struct{}
	Clock    netwatch.Clock
	Debounce time.Duration
	Tick     time.Duration
	Logger   *slog.Logger
}

// Daemon serves requests and watches the network.
type Daemon struct {
	deps Deps
	// ops serializes every operation: up, apply and the network re-apply
	// never run in parallel.
	ops sync.Mutex

	mu               sync.Mutex
	lastResolveError string
}

// New returns a Daemon with defaults filled in.
func New(deps Deps) *Daemon {
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	if deps.Debounce == 0 {
		deps.Debounce = DefaultDebounce
	}
	if deps.Tick == 0 {
		deps.Tick = DefaultTick
	}
	if deps.Clock == nil {
		deps.Clock = netwatch.RealClock
	}
	return &Daemon{deps: deps}
}

// Run listens on the socket and watches the network until ctx is done.
func (d *Daemon) Run(ctx context.Context) error {
	server, err := ipc.Listen(d.deps.Socket, d.deps.AllowedUIDs, d.Handle)
	if err != nil {
		return err
	}
	server.OnForbidden = func(uid int) {
		d.deps.Logger.Warn("refused request", "uid", uid)
		_ = d.deps.Ops(app.ActorDaemonCLI).AuditRoot("socket", fmt.Sprintf("forbidden: uid %d", uid))
	}
	d.deps.Logger.Info("twarpd listening", "socket", server.Addr())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		netwatch.Watch(ctx, d.deps.Events, d.deps.Debounce, d.deps.Tick, d.deps.Clock, d.CheckNetwork)
	}()
	err = server.Serve(ctx)
	cancel()
	<-watched
	return err
}

// Handle serves one request from an allowed peer.
func (d *Daemon) Handle(ctx context.Context, request ipc.Request) ipc.Response {
	if request.Op == ipc.OpStatus {
		return ipc.Response{OK: true, Live: d.LiveStatus()}
	}
	actor := app.ActorDaemonCLI
	if request.Actor == ipc.ActorTUI {
		actor = app.ActorDaemonTUI
	}
	ops := d.deps.Ops(actor)

	d.ops.Lock()
	defer d.ops.Unlock()
	summary, err := d.run(ctx, ops, request.Op)
	if request.Op != ipc.OpApply {
		// Apply writes its own root audit record
		result := "ok"
		if err != nil {
			result = "error: " + err.Error()
		}
		_ = ops.AuditRoot(request.Op, result)
	}
	if err != nil {
		d.deps.Logger.Error("operation failed", "op", request.Op, "actor", actor, "error", err)
		return ipc.Response{Error: err.Error()}
	}
	d.deps.Logger.Info("operation done", "op", request.Op, "actor", actor, "summary", summary)
	return ipc.Response{OK: true, Summary: summary}
}

func (d *Daemon) run(ctx context.Context, ops Ops, op string) (string, error) {
	switch op {
	case ipc.OpUp:
		applied, err := ops.Apply(ctx)
		if err != nil {
			return "", err
		}
		started, err := ops.Start(ctx)
		if err != nil {
			return "", fmt.Errorf("%s, but start failed: %w", applied, err)
		}
		return started, nil
	case ipc.OpDown:
		return ops.Stop(ctx)
	case ipc.OpApply:
		return ops.Apply(ctx)
	case ipc.OpGeoUpdate:
		report, err := ops.GeoUpdate(ctx)
		lines := make([]string, 0, len(report.Files))
		for _, file := range report.Files {
			lines = append(lines, fmt.Sprintf("updated %s: %d bytes", file.Name, file.Size))
		}
		return strings.Join(lines, "\n"), err
	default:
		return "", fmt.Errorf("unknown operation %q", op)
	}
}

// LiveStatus describes the running config for twarp status.
func (d *Daemon) LiveStatus() *ipc.LiveStatus {
	status := &ipc.LiveStatus{LastResolveError: d.resolveError()}
	if configured, err := d.deps.Configured(); err == nil {
		status.GatewayConfigured = configured
	}
	live, err := d.deps.Live()
	if err != nil {
		return status
	}
	status.GatewayLive = live.Gateway.String()
	status.ConfigAppliedAt = live.AppliedAt
	if d.deps.Stale != nil {
		status.Stale, _ = d.deps.Stale(live.AppliedAt)
	}
	return status
}

// CheckNetwork re-resolves a gateway.socks host name and re-applies the
// config when the address differs from the running one. The lookup runs
// outside the operation lock, so up/down never wait for it; a failed lookup
// keeps the running config. IP literals are never resolved.
func (d *Daemon) CheckNetwork(ctx context.Context) {
	configured, err := d.deps.Configured()
	if err != nil {
		d.deps.Logger.Warn("network check: read config", "error", err)
		return
	}
	host, _, err := net.SplitHostPort(configured)
	if err != nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	resolved, err := d.deps.Resolve(ctx, configured)
	if err != nil {
		d.setResolveError(fmt.Sprintf("%s does not resolve: %v", host, err))
		d.deps.Logger.Warn("gateway does not resolve, keeping the running config", "host", host, "error", err)
		return
	}
	d.setResolveError("")

	d.ops.Lock()
	defer d.ops.Unlock()
	// read under the lock: an apply that just ran may have moved it already
	live, err := d.deps.Live()
	if errors.Is(err, os.ErrNotExist) {
		return // not installed
	}
	old := "none"
	if err == nil {
		if live.Gateway == resolved {
			return
		}
		old = live.Gateway.String()
	}
	d.deps.Logger.Info("gateway address changed", "old", old, "new", resolved.String())
	summary, err := d.deps.Ops(app.ActorDaemonNet).Apply(ctx)
	if err != nil {
		d.deps.Logger.Error("re-apply after network change failed", "error", err)
		return
	}
	d.deps.Logger.Info("re-applied after network change", "summary", summary)
}

func (d *Daemon) setResolveError(message string) {
	d.mu.Lock()
	d.lastResolveError = message
	d.mu.Unlock()
}

func (d *Daemon) resolveError() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastResolveError
}
