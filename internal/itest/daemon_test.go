//go:build integration

package itest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/daemon"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/gwaddr"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
)

// switchingResolver answers gateway lookups with a settable address, like
// mDNS after the gateway host moved to another network.
type switchingResolver struct {
	mu   sync.Mutex
	addr string
}

func (r *switchingResolver) set(addr string) {
	r.mu.Lock()
	r.addr = addr
	r.mu.Unlock()
}

func (r *switchingResolver) lookup(context.Context, string, string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return []net.IP{net.ParseIP("fe80::1"), net.ParseIP(r.addr)}, nil
}

// renderingOps is the daemon's Apply without launchd: resolve, render, check
// with the real sing-box, write config.json.
type renderingOps struct {
	cfg      config.Config
	secrets  config.Secrets
	out      string
	resolver *switchingResolver
	applies  *int
	mu       *sync.Mutex
}

func (ops renderingOps) Apply(ctx context.Context) (string, error) {
	socks, err := gwaddr.Resolve(ctx, ops.resolver.lookup, ops.cfg.Gateway.Socks)
	if err != nil {
		return "", err
	}
	data, err := render.Render(ops.cfg, ops.secrets, nil, render.Options{
		Paths: config.Paths{Out: ops.out}, Inbound: render.InboundMixed, MixedPort: 1, GatewaySocks: socks,
	})
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(ops.out, "config.json.candidate")
	if err := render.WriteConfig(candidate, data); err != nil {
		return "", err
	}
	if output, err := checkConfigFile(candidate); err != nil {
		return "", fmt.Errorf("sing-box check: %w\n%s", err, output)
	}
	if err := os.Rename(candidate, filepath.Join(ops.out, "config.json")); err != nil {
		return "", err
	}
	ops.mu.Lock()
	*ops.applies++
	ops.mu.Unlock()
	return "applied", nil
}

func (renderingOps) Start(context.Context) (string, error)         { return "started", nil }
func (renderingOps) Stop(context.Context) (string, error)          { return "stopped", nil }
func (renderingOps) GeoUpdate(context.Context) (geo.Report, error) { return geo.Report{}, nil }
func (renderingOps) AuditRoot(string, string) error                { return nil }

func checkConfigFile(path string) (string, error) {
	command := exec.Command(singBoxPath, "check", "-c", path)
	command.Dir = filepath.Dir(path)
	output, err := command.CombinedOutput()
	return string(output), err
}

// The gateway host changes address after a network switch: the daemon gets
// a network event, re-resolves gateway.socks, re-applies once, and the new
// config passes sing-box check with the direct /32 for the gateway host still
// third in the route rules.
func TestDaemonReappliesWhenTheGatewayMoves(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(filepath.Join(out, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	compileGeoRuleSets(t, out)
	if err := render.WriteRuleSet(filepath.Join(out, "rules"), nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Gateway: config.GatewayConfig{
			Socks: "proxy.example:1080", Domains: []string{"intra.example"}, DNS: "100.64.0.53",
			AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		},
		Direct:   config.DirectConfig{DNS: "192.0.2.53"},
		VPN:      config.VPNConfig{DNS: "https://198.51.100.53/dns-query"},
		ClashAPI: "127.0.0.1:9090",
		LogLevel: "warn",
	}
	resolver := &switchingResolver{addr: "192.0.2.10"}
	var (
		mu      sync.Mutex
		applies int
	)
	ops := renderingOps{cfg: cfg, secrets: syntheticSecrets(t, "twarpd-itest"), out: out, resolver: resolver, applies: &applies, mu: &mu}
	if _, err := ops.Apply(t.Context()); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	mu.Lock()
	applies = 0
	mu.Unlock()

	socketDir, err := os.MkdirTemp("", "twarpd-itest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	events := make(chan struct{}, 1)
	configPath := filepath.Join(out, "config.json")
	twarpd := daemon.New(daemon.Deps{
		Socket:      filepath.Join(socketDir, "twarpd.sock"),
		AllowedUIDs: []int{os.Getuid()},
		Ops:         func(string) daemon.Ops { return ops },
		Configured:  func() (string, error) { return cfg.Gateway.Socks, nil },
		Resolve: func(ctx context.Context, hostport string) (netip.AddrPort, error) {
			return gwaddr.Resolve(ctx, resolver.lookup, hostport)
		},
		Live:     func() (app.LiveConfig, error) { return app.ReadLiveConfig(configPath) },
		Events:   events,
		Debounce: 20 * time.Millisecond,
		Tick:     time.Hour,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- twarpd.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run() = %v", err)
		}
	}()

	// unchanged address: an event does not re-apply
	events <- struct{}{}
	time.Sleep(200 * time.Millisecond)
	if got := applyCount(&mu, &applies); got != 0 {
		t.Fatalf("applies after an event without a move = %d, want 0", got)
	}

	resolver.set("192.0.2.20")
	events <- struct{}{}
	deadline := time.Now().Add(10 * time.Second)
	for applyCount(&mu, &applies) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := applyCount(&mu, &applies); got != 1 {
		t.Fatalf("applies after the gateway moved = %d, want 1", got)
	}

	live, err := app.ReadLiveConfig(configPath)
	if err != nil || live.Gateway != netip.MustParseAddrPort("192.0.2.20:1080") {
		t.Fatalf("running gateway = %v, %v; want 192.0.2.20:1080", live.Gateway, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var rendered singbox.Config
	if err := json.Unmarshal(data, &rendered); err != nil {
		t.Fatal(err)
	}
	if rules := rendered.Route.Rules; len(rules) < 3 || len(rules[2].IPCIDR) != 1 || rules[2].IPCIDR[0] != "192.0.2.20/32" || rules[2].Outbound != "direct" {
		t.Fatalf("route rules = %#v, want the moved gateway host direct as rule 3", rendered.Route.Rules)
	}

	callCtx, cancelCall := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelCall()
	response, err := ipc.Call(callCtx, filepath.Join(socketDir, "twarpd.sock"), ipc.Request{Op: ipc.OpStatus, Actor: ipc.ActorCLI})
	if err != nil || response.Live == nil || response.Live.GatewayLive != "192.0.2.20:1080" || response.Live.GatewayConfigured != "proxy.example:1080" {
		t.Fatalf("status over the socket = (%+v, %v)", response.Live, err)
	}
}

// A peer with another uid is refused before any operation runs. Creating
// such a peer needs root, so this stays a unit test in internal/ipc.
func TestDaemonRefusesForeignUID(t *testing.T) {
	t.Skip("needs a second local user and root to connect as it; covered by ipc.TestServerRejectsForeignUID")
}

func applyCount(mu *sync.Mutex, applies *int) int {
	mu.Lock()
	defer mu.Unlock()
	return *applies
}
