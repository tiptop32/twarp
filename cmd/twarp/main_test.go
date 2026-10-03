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

func TestRunStubs(t *testing.T) {
	names := []string{"render", "apply", "install", "uninstall", "status", "mcp"}
	for _, name := range names {
		var stdout, stderr bytes.Buffer
		if code := run([]string{name}, &stdout, &stderr); code != 1 {
			t.Errorf("%s: exit code = %d, want 1", name, code)
		}
		want := "twarp " + name + ": not implemented"
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("%s: stderr = %q, want %q", name, stderr.String(), want)
		}
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
