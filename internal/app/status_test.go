package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/socksprobe"
	"github.com/tiptop32/twarp/internal/sysexec"
)

var (
	checkTunnelRouteOutput    = []byte("   route to: 1.1.1.1\ndestination: default\n       mask: default\n  interface: utun9\n      flags: <UP,DONE,STATIC,PRCLONING,GLOBAL>\n")
	checkTunnelIfconfigOutput = []byte("utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000\n\tinet 172.19.0.1 --> 172.19.0.1 netmask 0xfffffffc\n")
	checkTunnelPrintCall      = sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}
)

func runCheckTunnel(t *testing.T, expect []sysexec.ExpectedCall) (Status, *sysexec.Fake) {
	t.Helper()
	runner := &sysexec.Fake{Expect: expect}
	service := New(Deps{Runner: runner}, ActorTUI)
	var status Status
	service.checkTunnel(context.Background(), &status)
	return status, runner
}

func TestCheckTunnelReportsRunningOwnTunnel(t *testing.T) {
	status, runner := runCheckTunnel(t, []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: checkTunnelRouteOutput}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun9"}}, Response: sysexec.Response{Output: checkTunnelIfconfigOutput}},
		{Call: checkTunnelPrintCall, Response: sysexec.Response{Output: []byte("state = running\n")}},
	})
	if !status.TunnelActive || status.TunnelInterface != "utun9" || status.TunnelAddr != "172.19.0.1" {
		t.Fatalf("status = %+v, want active utun9 tunnel", status)
	}
	check, ok := tunnelCheck(status)
	if !ok || check.Level != LevelOK || !strings.Contains(check.Detail, "holds the default route") {
		t.Fatalf("tunnel check = (%s, %q), want OK holding the route", check.Level, check.Detail)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTunnelRejectsStaleOwnTunnel(t *testing.T) {
	for name, printResponse := range map[string]sysexec.Response{
		"service absent": {Err: errors.New("Could not find specified service")},
		"service stopped": {
			Output: []byte("dev.twarp.singbox => {\n\tstate = not running\n}\n"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			status, runner := runCheckTunnel(t, []sysexec.ExpectedCall{
				{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: checkTunnelRouteOutput}},
				{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun9"}}, Response: sysexec.Response{Output: checkTunnelIfconfigOutput}},
				{Call: checkTunnelPrintCall, Response: printResponse},
			})
			if status.TunnelActive {
				t.Fatalf("status = %+v, want TunnelActive false for a stale own utun", status)
			}
			check, ok := tunnelCheck(status)
			if !ok || check.Level != LevelFail {
				t.Fatalf("tunnel check = (%s, %q), want FAIL", check.Level, check.Detail)
			}
			for _, want := range []string{"stale route: utun9 172.19.0.1", "is not running", "run: twarp up"} {
				if !strings.Contains(check.Detail, want) {
					t.Errorf("detail = %q, want %q", check.Detail, want)
				}
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckTunnelFailsOnUnexpectedPrintError(t *testing.T) {
	printErr := errors.New("launchctl print: connect failed: Broken pipe")
	status, runner := runCheckTunnel(t, []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: checkTunnelRouteOutput}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun9"}}, Response: sysexec.Response{Output: checkTunnelIfconfigOutput}},
		{Call: checkTunnelPrintCall, Response: sysexec.Response{Err: printErr}},
	})
	if status.TunnelActive {
		t.Fatalf("status = %+v, want TunnelActive false when the service cannot be inspected", status)
	}
	check, ok := tunnelCheck(status)
	if !ok || check.Level != LevelFail {
		t.Fatalf("tunnel check = (%s, %q), want FAIL", check.Level, check.Detail)
	}
	if !strings.Contains(check.Detail, "inspect sing-box service") {
		t.Errorf("detail = %q, want the inspection failure", check.Detail)
	}
	for _, unwanted := range []string{"stale route", "twarp up"} {
		if strings.Contains(check.Detail, unwanted) {
			t.Errorf("detail = %q, want no %q", check.Detail, unwanted)
		}
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTunnelKeepsForeignAndPhysicalRoutesWithoutPrint(t *testing.T) {
	status, runner := runCheckTunnel(t, []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: []byte("   route to: 1.1.1.1\ndestination: default\n  interface: en0\n")}},
	})
	if status.TunnelActive {
		t.Fatalf("status = %+v, want TunnelActive false for a physical route", status)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func tunnelCheck(status Status) (Check, bool) {
	for _, check := range status.Checks {
		if check.Name == "tunnel" {
			return check, true
		}
	}
	return Check{}, false
}

func runCheckGateway(t *testing.T, dial func() net.Conn, creds *socksprobe.Credentials, network bool) Status {
	t.Helper()
	service := New(Deps{Dial: func(context.Context, string, string) (net.Conn, error) { return dial(), nil }}, ActorCLI)
	cfg := config.Config{Gateway: config.GatewayConfig{Socks: "192.0.2.10:1080", DNS: "100.64.0.53"}}
	var status Status
	service.checkGateway(t.Context(), &status, cfg, liveState{}, creds, network)
	return status
}

func gatewayCheck(t *testing.T, status Status) Check {
	t.Helper()
	for _, check := range status.Checks {
		if check.Name == "gateway" {
			return check
		}
	}
	t.Fatalf("no gateway check in %+v", status.Checks)
	return Check{}
}

func TestCheckGatewayRunsSOCKSHandshake(t *testing.T) {
	creds := &socksprobe.Credentials{User: "proxy", Password: "synthetic-password"}
	closedAfterAccept := func() net.Conn {
		server, client := net.Pipe()
		_ = server.Close()
		return client
	}
	tests := []struct {
		name      string
		dial      func() net.Conn
		creds     *socksprobe.Credentials
		network   bool
		level     Level
		detail    string
		reachable bool
	}{
		{"no auth", socksprobe.FakeServer{}.Dial, nil, false, LevelOK, "192.0.2.10:1080 is reachable", true},
		{"auth", socksprobe.FakeServer{Creds: creds}.Dial, creds, false, LevelOK, "192.0.2.10:1080 is reachable", true},
		{"port open, not SOCKS", closedAfterAccept, nil, false, LevelFail, "not a SOCKS5 server", false},
		{"auth required, none configured", socksprobe.FakeServer{Creds: creds}.Dial, nil, false, LevelFail, "probably requires a username and password", false},
		{"wrong password", socksprobe.FakeServer{Creds: creds}.Dial, &socksprobe.Credentials{User: "proxy", Password: "wrong"}, false, LevelFail, "SOCKS auth rejected", false},
		{"network: upstream up", socksprobe.FakeServer{}.Dial, nil, true, LevelOK, "connects to 100.64.0.53:53", true},
		{"network: upstream VPN down", socksprobe.FakeServer{ConnectReply: 0x03}.Dial, nil, true, LevelFail, "192.0.2.10:1080: upstream VPN is down", true},
		{"network: connect refused", socksprobe.FakeServer{ConnectReply: 0x05}.Dial, nil, true, LevelFail, "CONNECT to 100.64.0.53:53 failed", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := runCheckGateway(t, tt.dial, tt.creds, tt.network)
			check := gatewayCheck(t, status)
			if check.Level != tt.level || !strings.Contains(check.Detail, tt.detail) || status.GatewayReachable != tt.reachable {
				t.Fatalf("gateway = (%s, %q, reachable %v), want (%s, %q, %v)", check.Level, check.Detail, status.GatewayReachable, tt.level, tt.detail, tt.reachable)
			}
		})
	}
}

// 2026-10-16: twarp.yaml pointed at .173 while sing-box ran on .105 for a
// week, and status said OK because it probed the yaml address.
func TestCheckGatewayProbesTheLiveAddress(t *testing.T) {
	var dialed []string
	service := New(Deps{Dial: func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return socksprobe.FakeServer{}.Dial(), nil
	}}, ActorCLI)
	live := liveState{gateway: netip.MustParseAddrPort("192.0.2.105:8080")}

	var status Status
	service.checkGateway(t.Context(), &status, config.Config{Gateway: config.GatewayConfig{Socks: "192.0.2.173:8080"}}, live, nil, false)
	check := gatewayCheck(t, status)
	if check.Level != LevelWarn || !strings.Contains(check.Detail, "sing-box runs on 192.0.2.105:8080, but twarp.yaml has 192.0.2.173:8080; run: twarp apply") {
		t.Fatalf("gateway = (%s, %q), want a stale-address warning", check.Level, check.Detail)
	}
	if status.GatewayLive != "192.0.2.105:8080" || status.GatewaySocks != "192.0.2.173:8080" || dialed[0] != "192.0.2.105:8080" {
		t.Fatalf("status = %+v, dialed %v; want the live address probed", status, dialed)
	}

	status = Status{}
	service.checkGateway(t.Context(), &status, config.Config{Gateway: config.GatewayConfig{Socks: "proxyhost.local:8080"}}, live, nil, false)
	if check := gatewayCheck(t, status); check.Level != LevelOK || check.Detail != "configured proxyhost.local:8080 → live 192.0.2.105:8080 is reachable" {
		t.Fatalf("gateway by name = (%s, %q)", check.Level, check.Detail)
	}
}

func TestLiveGatewaySources(t *testing.T) {
	out := t.TempDir()
	home := t.TempDir()
	paths := config.Paths{Home: home, Out: out}
	service := New(Deps{}, ActorCLI)
	if live := service.liveGateway(t.Context(), paths); live.gateway.IsValid() || live.stale {
		t.Fatalf("liveGateway(not installed) = %+v", live)
	}

	running := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"gateway","server":"192.0.2.105","server_port":8080}]}`
	if err := os.WriteFile(paths.OutConfig(), []byte(running), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(paths.OutConfig(), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ConfigFile(), []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := service.liveGateway(t.Context(), paths)
	if live.gateway != netip.MustParseAddrPort("192.0.2.105:8080") || !live.stale {
		t.Fatalf("liveGateway(config.json) = %+v, want the running address and stale", live)
	}

	service.deps.Daemon = func(context.Context) (*ipc.LiveStatus, error) {
		return &ipc.LiveStatus{GatewayLive: "192.0.2.20:8080", LastResolveError: "proxyhost.local does not resolve"}, nil
	}
	live = service.liveGateway(t.Context(), paths)
	if live.gateway != netip.MustParseAddrPort("192.0.2.20:8080") || live.stale || live.resolveError == "" {
		t.Fatalf("liveGateway(daemon) = %+v, want the daemon's view", live)
	}

	service.deps.Daemon = func(context.Context) (*ipc.LiveStatus, error) { return nil, ipc.ErrDaemonUnavailable }
	if live := service.liveGateway(t.Context(), paths); live.gateway != netip.MustParseAddrPort("192.0.2.105:8080") {
		t.Fatalf("liveGateway(daemon down) = %+v, want the config.json fallback", live)
	}

	var status Status
	checkLive(&status, liveState{gateway: netip.MustParseAddrPort("192.0.2.20:8080"), stale: true, resolveError: "proxyhost.local does not resolve"})
	got := fmt.Sprint(status.Checks)
	for _, want := range []string{"proxyhost.local does not resolve; running on 192.0.2.20:8080", "changed after the last apply; run: twarp apply"} {
		if !strings.Contains(got, want) {
			t.Errorf("checks = %s, want %q", got, want)
		}
	}
}
