package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func launchdFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "launchd", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var (
	routeCall     = sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}
	printCall     = sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}
	bootoutCall   = sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}
	disableCall   = sysexec.Call{Name: "launchctl", Args: []string{"disable", "system/dev.twarp.singbox"}}
	enableCall    = sysexec.Call{Name: "launchctl", Args: []string{"enable", "system/dev.twarp.singbox"}}
	kickstartCall = sysexec.Call{Name: "launchctl", Args: []string{"kickstart", "-k", "system/dev.twarp.singbox"}}
	bootstrapCall = sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}
)

func TestRunStartAndStopRequireRoot(t *testing.T) {
	for _, command := range []string{"start", "stop"} {
		fixture := newCLIRenderFixture(t, 0)
		fixture.deps.Sys = cliTestSys{euid: 501, env: map[string]string{}}
		fixture.deps.Runner = &sysexec.Fake{}
		fixture.deps.FS = &cliFakeFS{}
		_, stderr, code := runCLIForTest([]string{command}, fixture.deps)
		if code != 1 || !strings.Contains(stderr, "run with sudo") {
			t.Fatalf("%s as user = (%d, %q), want run with sudo", command, code, stderr)
		}
	}
}

func TestRunStartRequiresInstall(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	fixture.deps.Runner = &sysexec.Fake{}
	fixture.deps.FS = &cliFakeFS{stats: map[string]error{launchd.SingBoxPlistPath: os.ErrNotExist}}
	_, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 1 || !strings.Contains(stderr, "sudo twarp install") {
		t.Fatalf("start without install = (%d, %q), want install hint", code, stderr)
	}
}

func TestRunStartRefusesWhileAnotherVPNHoldsRoute(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-utun-outline.txt")}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun7"}}, Response: sysexec.Response{Output: launchdFixture(t, "ifconfig-utun-outline.txt")}},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	_, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 1 || !strings.Contains(stderr, "another VPN holds the default route") {
		t.Fatalf("start with foreign VPN = (%d, %q), want refusal", code, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStartLoadsUnloadedService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-en0.txt")}},
		{Call: printCall, Response: sysexec.Response{Err: errors.New("Could not find service")}},
		{Call: enableCall},
		{Call: bootstrapCall},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "started") {
		t.Fatalf("start = (%d, %q, %q), want started", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStartRestartsLoadedButInactiveService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-en0.txt")}},
		{Call: printCall, Response: sysexec.Response{Output: []byte("state = not running\n")}},
		{Call: enableCall},
		{Call: kickstartCall},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "started") {
		t.Fatalf("start = (%d, %q, %q), want started", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStartEnablesActiveTunnel(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-utun-own.txt")}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun9"}}, Response: sysexec.Response{Output: launchdFixture(t, "ifconfig-utun-own.txt")}},
		{Call: enableCall},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, _, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "already running") {
		t.Fatalf("start = (%d, %q), want already running", code, stdout)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStartEnablesRunningServiceWithoutRoute(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-en0.txt")}},
		{Call: printCall, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: enableCall},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "does not hold the default route yet") {
		t.Fatalf("start = (%d, %q, %q), want running status", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

// stop must persist a disabled flag: bootout alone lets launchd relaunch the
// KeepAlive/RunAtLoad daemon after reboot.
func TestRunStopPersistsDisabledStateIdempotently(t *testing.T) {
	for _, response := range []sysexec.Response{{}, {Err: errors.New("Boot-out failed: 3: No such process")}} {
		fixture := newCLIRenderFixture(t, 0)
		runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
			{Call: bootoutCall, Response: response},
			{Call: disableCall},
		}}
		fixture.deps.Runner = runner
		fixture.deps.FS = &cliFakeFS{}
		stdout, stderr, code := runCLIForTest([]string{"stop"}, fixture.deps)
		if code != 0 || !strings.Contains(stdout, "stopped") {
			t.Fatalf("stop = (%d, %q, %q), want stopped", code, stdout, stderr)
		}
		if err := runner.Verify(); err != nil {
			t.Fatal(err)
		}
	}
}

// start after stop must clear the persisted disabled flag before kickstart or
// bootstrap, otherwise launchd keeps the service off.
func TestRunStartReenablesAfterStop(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		printResp sysexec.Response
		then      sysexec.Call
	}{
		{name: "booted out", printResp: sysexec.Response{Err: errors.New("Could not find service")}, then: bootstrapCall},
		{name: "loaded but inactive", printResp: sysexec.Response{Output: []byte("state = exited\n")}, then: kickstartCall},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := newCLIRenderFixture(t, 0)
			runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
				{Call: routeCall, Response: sysexec.Response{Output: launchdFixture(t, "route-en0.txt")}},
				{Call: printCall, Response: scenario.printResp},
				{Call: enableCall},
				{Call: scenario.then},
			}}
			fixture.deps.Runner = runner
			fixture.deps.FS = &cliFakeFS{}
			stdout, stderr, code := runCLIForTest([]string{"start"}, fixture.deps)
			if code != 0 || !strings.Contains(stdout, "started") {
				t.Fatalf("start = (%d, %q, %q), want started", code, stdout, stderr)
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
