package app

import (
	"context"
	"errors"
	"strings"
	"testing"

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
