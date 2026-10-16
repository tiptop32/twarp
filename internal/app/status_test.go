package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
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
			for _, want := range []string{"stale route: utun9 172.19.0.1", "is not running", "sudo twarp start"} {
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
	for _, unwanted := range []string{"stale route", "sudo twarp start"} {
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
	service.checkGateway(t.Context(), &status, cfg, creds, network)
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
