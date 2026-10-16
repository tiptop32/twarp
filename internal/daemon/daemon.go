// Package daemon is twarpd: a root daemon that runs twarp operations for its
// owner over a unix socket, so up, down and apply need no sudo, and that
// re-applies the config when the gateway.socks host name moves to a new
// address after a network change.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/gwaddr"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/netwatch"
	"github.com/tiptop32/twarp/internal/singbox"
)

// ActorNet is the audit actor for re-applies after a network change.
const ActorNet = "daemon-net"

const (
	defaultDebounce = 2 * time.Second
	defaultTick     = 30 * time.Second
	// resolveCacheAge is how long an address found by the network check is
	// reused by the Apply it triggers, instead of resolving again under the
	// operation lock.
	resolveCacheAge = 30 * time.Second
	// maxConfigBytes bounds the running config.json read for status.
	maxConfigBytes = 4 << 20
)

// Service is the part of app.Service the daemon runs.
type Service interface {
	Apply(ctx context.Context) (string, error)
	Start(ctx context.Context) (string, error)
	Stop(ctx context.Context) (string, error)
	GeoUpdate(ctx context.Context) (geo.Report, error)
	Audit(operation, result string) error
}

// ResolveFunc resolves gateway.socks; see app.Deps.ResolveGateway.
type ResolveFunc func(ctx context.Context, hostport string) (netip.AddrPort, error)

// Deps are the daemon's boundaries. Tests replace each of them.
type Deps struct {
	Sys        config.Sys
	SocketPath string
	OwnerUID   int
	// NewService returns the app service for one audit actor. resolve is the
	// daemon's cached resolver and must become app.Deps.ResolveGateway.
	NewService func(actor string, resolve ResolveFunc) Service
	Lookup     gwaddr.LookupFunc
	// Source reports network changes; nil leaves only the periodic tick.
	Source   netwatch.Source
	After    netwatch.After
	Debounce time.Duration
	Tick     time.Duration
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

// Daemon serves one owner.
type Daemon struct {
	deps Deps
	// ops serializes every operation that changes the system: client requests
	// and network re-applies never run in parallel.
	ops sync.Mutex

	mu               sync.Mutex
	cachedHost       string
	cachedAddr       netip.AddrPort
	cachedAt         time.Time
	lastResolveError string
}

// New prepares a daemon; Run starts it.
func New(deps Deps) *Daemon {
	if deps.Debounce == 0 {
		deps.Debounce = defaultDebounce
	}
	if deps.Tick == 0 {
		deps.Tick = defaultTick
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logf == nil {
		deps.Logf = func(string, ...any) {}
	}
	return &Daemon{deps: deps}
}

// Run listens on the socket and watches the network until ctx is done. Only
// the owner and root may call it.
func (d *Daemon) Run(ctx context.Context) error {
	server, err := ipc.Listen(d.deps.SocketPath, []int{d.deps.OwnerUID, 0}, d.handle)
	if err != nil {
		return err
	}
	server.OnForbidden = func(peer ipc.Peer) {
		d.deps.Logf("forbidden request from uid %d", peer.UID)
		d.audit("daemon", "forbidden", fmt.Sprintf("uid %d", peer.UID))
	}
	d.deps.Logf("listening on %s for uid %d", d.deps.SocketPath, d.deps.OwnerUID)

	watchCtx, stopWatch := context.WithCancel(ctx)
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		d.CheckNetwork(watchCtx)
		var events <-chan struct{}
		if d.deps.Source != nil {
			events = d.deps.Source.Events()
		}
		netwatch.Watch(watchCtx, events, d.deps.Debounce, d.deps.Tick, d.deps.After, func(string) {
			d.CheckNetwork(watchCtx)
		})
	}()
	err = server.Serve(ctx)
	stopWatch()
	<-watching
	return err
}

func (d *Daemon) handle(ctx context.Context, _ ipc.Peer, request ipc.Request) ipc.Response {
	if request.Op == ipc.OpStatus {
		live, err := d.LiveStatus()
		if err != nil {
			return failed(err)
		}
		return ipc.Response{OK: true, Live: &live}
	}

	d.ops.Lock()
	defer d.ops.Unlock()
	service := d.deps.NewService("daemon-"+request.Actor, d.resolve)
	var summary string
	var err error
	switch request.Op {
	case ipc.OpUp:
		summary, err = d.up(ctx, service)
	case ipc.OpDown:
		summary, err = service.Stop(ctx)
	case ipc.OpApply:
		summary, err = service.Apply(ctx)
	case ipc.OpGeoUpdate:
		var report geo.Report
		report, err = service.GeoUpdate(ctx)
		summary = app.GeoReportText(report)
		if err != nil && summary != "" {
			err = fmt.Errorf("%s\n%w", summary, err)
		}
	default:
		return ipc.Response{Code: ipc.CodeBadRequest, Error: "unknown operation " + request.Op}
	}
	d.deps.Logf("%s by %s: %s", request.Op, request.Actor, outcome(summary, err))
	if err != nil {
		return failed(err)
	}
	return ipc.Response{OK: true, Summary: summary}
}

// up applies the config only when it changed since the last apply, because
// a reload of a running sing-box drops its connections, and then starts the
// tunnel.
func (d *Daemon) up(ctx context.Context, service Service) (string, error) {
	var lines []string
	live, err := d.LiveStatus()
	if err != nil || live.Stale || live.ConfigAppliedAt.IsZero() {
		summary, err := service.Apply(ctx)
		if err != nil {
			return "", err
		}
		lines = append(lines, summary)
	}
	summary, err := service.Start(ctx)
	if err != nil {
		return strings.Join(lines, "\n"), err
	}
	return strings.Join(append(lines, summary), "\n"), nil
}

// CheckNetwork resolves a gateway.socks host name and re-applies the config
// when the address differs from the one sing-box runs with. An IP literal is
// never resolved, and a failed lookup leaves the running config alone.
func (d *Daemon) CheckNetwork(ctx context.Context) {
	paths, cfg, err := d.loadConfig()
	if err != nil {
		d.deps.Logf("network check: %v", err)
		return
	}
	if gwaddr.IsLiteral(cfg.Gateway.Socks) {
		d.setResolveError("")
		return
	}
	live, _, err := readLiveGateway(paths.OutConfig())
	if errors.Is(err, os.ErrNotExist) {
		return // not installed yet
	}
	if err != nil {
		d.deps.Logf("network check: %v", err)
		return
	}
	// Resolve outside the operation lock: a missing .local name takes the
	// full lookup timeout, and up or down must not wait for it.
	addr, err := gwaddr.Resolve(ctx, d.deps.Lookup, cfg.Gateway.Socks)
	if err != nil {
		message := fmt.Sprintf("%s does not resolve: %v", hostOf(cfg.Gateway.Socks), err)
		if live.IsValid() {
			message += fmt.Sprintf("; running on %s", live)
		}
		if d.setResolveError(message) {
			d.deps.Logf("gateway %s", message)
		}
		return
	}
	d.remember(cfg.Gateway.Socks, addr)
	d.setResolveError("")
	if addr == live {
		return
	}

	d.ops.Lock()
	defer d.ops.Unlock()
	live, _, err = readLiveGateway(paths.OutConfig())
	if err == nil && addr == live {
		return // a client apply got there first
	}
	service := d.deps.NewService(ActorNet, d.resolve)
	summary, err := service.Apply(ctx)
	d.deps.Logf("gateway address changed old=%s new=%s: %s", live, addr, outcome(summary, err))
	if auditErr := service.Audit("gateway_change", fmt.Sprintf("%s -> %s: %s", live, addr, outcome(summary, err))); auditErr != nil {
		d.deps.Logf("audit: %v", auditErr)
	}
}

// LiveStatus describes the running config: the gateway address in
// config.json, when it was applied and whether the user config is newer.
func (d *Daemon) LiveStatus() (ipc.LiveStatus, error) {
	paths, cfg, err := d.loadConfig()
	if err != nil {
		return ipc.LiveStatus{}, err
	}
	status := ipc.LiveStatus{GatewayConfigured: cfg.Gateway.Socks}
	d.mu.Lock()
	status.LastResolveError = d.lastResolveError
	d.mu.Unlock()
	live, appliedAt, err := readLiveGateway(paths.OutConfig())
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return ipc.LiveStatus{}, err
	}
	if live.IsValid() {
		status.GatewayLive = live.String()
	}
	status.ConfigAppliedAt = appliedAt
	status.Stale = Stale(paths, appliedAt)
	return status, nil
}

// Stale reports whether twarp.yaml or secrets.yaml changed after appliedAt.
// Lstat only reads the inode, so it never follows a symlink planted in the
// user's directory.
func Stale(paths config.Paths, appliedAt time.Time) bool {
	for _, path := range []string{paths.ConfigFile(), paths.SecretsFile()} {
		if info, err := os.Lstat(path); err == nil && info.ModTime().After(appliedAt) {
			return true
		}
	}
	return false
}

// resolve is the gateway resolver of every app service the daemon creates.
// It reuses the address the network check has just found.
func (d *Daemon) resolve(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if !gwaddr.IsLiteral(hostport) {
		d.mu.Lock()
		cached, fresh := d.cachedAddr, d.cachedHost == hostport && d.deps.Now().Sub(d.cachedAt) < resolveCacheAge
		d.mu.Unlock()
		if fresh {
			return cached, nil
		}
	}
	addr, err := gwaddr.Resolve(ctx, d.deps.Lookup, hostport)
	if err == nil && !gwaddr.IsLiteral(hostport) {
		d.remember(hostport, addr)
	}
	return addr, err
}

func (d *Daemon) remember(hostport string, addr netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cachedHost, d.cachedAddr, d.cachedAt = hostport, addr, d.deps.Now()
}

// setResolveError records message and reports whether it changed, so a name
// that stays unresolvable is logged once, not every tick.
func (d *Daemon) setResolveError(message string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := d.lastResolveError != message
	d.lastResolveError = message
	return changed
}

func (d *Daemon) loadConfig() (config.Paths, config.Config, error) {
	paths, err := config.Resolve(d.deps.Sys)
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	return paths, cfg, nil
}

func (d *Daemon) audit(actor, operation, result string) {
	if d.deps.NewService == nil {
		return
	}
	if err := d.deps.NewService(actor, d.resolve).Audit(operation, result); err != nil {
		d.deps.Logf("audit: %v", err)
	}
}

// readLiveGateway returns the gateway outbound address in the running
// config.json and the file's mtime. The file belongs to root.
func readLiveGateway(path string) (netip.AddrPort, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return netip.AddrPort{}, time.Time{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return netip.AddrPort{}, time.Time{}, err
	}
	var running singbox.Config
	decoder := json.NewDecoder(io.LimitReader(file, maxConfigBytes))
	if err := decoder.Decode(&running); err != nil {
		return netip.AddrPort{}, info.ModTime(), fmt.Errorf("read running config %s: %w", path, err)
	}
	for _, outbound := range running.Outbounds {
		if outbound.Tag != app.OutboundGateway {
			continue
		}
		addr, err := netip.ParseAddr(outbound.Server)
		if err != nil {
			return netip.AddrPort{}, info.ModTime(), fmt.Errorf("running config %s: gateway server %q is not an IP address", path, outbound.Server)
		}
		return netip.AddrPortFrom(addr, outbound.ServerPort), info.ModTime(), nil
	}
	return netip.AddrPort{}, info.ModTime(), fmt.Errorf("running config %s has no gateway outbound", path)
}

func hostOf(hostport string) string {
	if index := strings.LastIndex(hostport, ":"); index > 0 {
		return strings.Trim(hostport[:index], "[]")
	}
	return hostport
}

func outcome(summary string, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.ReplaceAll(summary, "\n", "; ")
}

func failed(err error) ipc.Response {
	return ipc.Response{Code: ipc.CodeFailed, Error: err.Error()}
}
