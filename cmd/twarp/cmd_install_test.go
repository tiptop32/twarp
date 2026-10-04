package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestRunInstallUsesLaunchdInstall(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	notLoaded := errors.New("service not found")
	absent := errors.New("No such process")
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.3\n")}},
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: []byte("interface: en0\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "gui/501/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json.candidate")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.GeoPlistPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"enable", sysexec.SystemTarget()}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}},
	}}
	filesystem := &cliFakeFS{}
	fixture.deps.Runner = runner
	fixture.deps.FS = filesystem
	fixture.deps.Executable = func() (string, error) { return "/test/twarp", nil }

	stdout, stderr, code := runCLIForTest([]string{"install"}, fixture.deps)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "check: twarp status") {
		t.Fatalf("install = (%d, %q, %q), want success hint", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if len(filesystem.writes) != 5 {
		t.Fatalf("filesystem writes = %v, want staged and promoted config, two plists, newsyslog", filesystem.writes)
	}
}

func TestRunUninstallUsesLaunchdUninstallAndKeepsData(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}},
	}}
	filesystem := &cliFakeFS{}
	fixture.deps.Runner = runner
	fixture.deps.FS = filesystem
	stdout, stderr, code := runCLIForTest([]string{"uninstall"}, fixture.deps)
	if code != 0 || stderr != "" {
		t.Fatalf("uninstall = (%d, %q, %q), want success", code, stdout, stderr)
	}
	for _, want := range []string{"uninstalled; config kept in " + fixture.home, "rules in " + fixture.out} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if len(filesystem.removes) != 3 {
		t.Fatalf("filesystem removes = %v, want three service files", filesystem.removes)
	}
}

func TestRunInstallAndUninstallRequireRoot(t *testing.T) {
	for _, command := range []string{"install", "uninstall"} {
		stdout, stderr, code := runCLIForTest([]string{command}, cliDeps{Sys: cliTestSys{euid: 501}})
		if code != 1 || stdout != "" || !strings.Contains(stderr, "run with sudo") {
			t.Errorf("%s = (%d, %q, %q), want sudo error", command, code, stdout, stderr)
		}
	}
}

func TestRunInstallHoldsStateLockUntilRuleSetWrite(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	lockPath := filepath.Join(fixture.home, "gateway-ips.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	notLoaded := errors.New("service not found")
	absent := errors.New("No such process")
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.3\n")}},
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: []byte("interface: en0\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "gui/501/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json.candidate")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.GeoPlistPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"enable", sysexec.SystemTarget()}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}},
	}}
	configWritten := make(chan struct{})
	continueInstall := make(chan struct{})
	filesystem := &cliFakeFS{onWrite: func(path string) {
		if path == filepath.Join(fixture.out, "config.json") {
			close(configWritten)
			<-continueInstall
		}
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = filesystem
	fixture.deps.Executable = func() (string, error) { return "/test/twarp", nil }

	installDone := make(chan int, 1)
	go func() {
		_, _, code := runCLIForTest([]string{"install"}, fixture.deps)
		installDone <- code
	}()
	<-configWritten

	store := state.New(state.Options{
		File: filepath.Join(fixture.home, "gateway-ips.json"), LockFile: lockPath,
		AuditFile: filepath.Join(fixture.home, "audit.jsonl"), AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		GatewaySocks: netip.MustParseAddr("192.168.1.10"),
		OnChange: func(prefixes []netip.Prefix) error {
			return render.WriteRuleSet(filepath.Join(fixture.out, "rules"), prefixes)
		},
	})
	addDone := make(chan error, 1)
	go func() {
		_, err := store.Add(context.Background(), "cli", "100.64.23.9", "", false)
		addDone <- err
	}()
	select {
	case err := <-addDone:
		close(continueInstall)
		<-installDone
		t.Fatalf("gateway add completed before install wrote its rule-set: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(continueInstall)
	if code := <-installDone; code != 0 {
		t.Fatalf("install code = %d, want 0", code)
	}
	if err := <-addDone; err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(fixture.out, "rules", "gateway-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "100.64.23.9/32") {
		t.Fatalf("gateway rule-set lost concurrent add: %s", data)
	}
}
