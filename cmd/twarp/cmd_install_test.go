package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/launchd"
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
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.GeoPlistPath}}},
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
	if len(filesystem.writes) != 4 {
		t.Fatalf("filesystem writes = %v, want config, two plists, newsyslog", filesystem.writes)
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
