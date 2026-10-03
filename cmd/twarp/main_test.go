package main

import (
	"bytes"
	"os"
	"os/user"
	"strings"
	"testing"
)

func TestRunUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Errorf("stderr = %q, want unknown command message", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Errorf("run(%q) = %d, want 0", args, code)
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("run(%q) stdout = %q, want usage", args, stdout.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("run(%q) stderr = %q, want empty", args, stderr.String())
		}
	}
}

func TestRunWithDepsDispatchesGeoUsingInjectedSystem(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithDeps([]string{"geo", "update"}, &stdout, &stderr, cliDeps{Sys: cliTestSys{euid: 501}})
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "run with sudo") {
		t.Fatalf("geo update = (%d, %q, %q), want injected non-root refusal", code, stdout.String(), stderr.String())
	}
}

type cliTestSys struct {
	euid int
	env  map[string]string
}

func (system cliTestSys) Geteuid() int { return system.euid }

func (system cliTestSys) Getenv(name string) string { return system.env[name] }

func (cliTestSys) LookupUser(name string) (*user.User, error) {
	return nil, user.UnknownUserError(name)
}

func (cliTestSys) Stat(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

func TestRunSubcommandHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"render", "-h"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestRunSubcommandBadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"render", "-nope"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}
