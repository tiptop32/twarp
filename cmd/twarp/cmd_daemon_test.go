package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRunDaemonRefusesUnsafeStarts(t *testing.T) {
	untrusted := filepath.Join(t.TempDir(), "open")
	if err := os.MkdirAll(untrusted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0o777); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(untrusted, "twarp")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	owner := map[string]string{"TWARP_OWNER_UID": "501", "TWARP_OWNER_GID": "20", "TWARP_OWNER_USER": "alice"}
	tests := []struct {
		name string
		sys  cliTestSys
		want string
	}{
		{"not root", cliTestSys{euid: 501, env: owner}, "must run as root"},
		{"no owner", cliTestSys{euid: 0, env: map[string]string{}}, "TWARP_OWNER_UID"},
		{"user-writable binary", cliTestSys{euid: 0, env: owner}, "refusing to run a binary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := cliDeps{Sys: tt.sys, Executable: func() (string, error) { return binary, nil }}
			_, stderr, code := runCLIForTest([]string{"daemon"}, deps)
			if code != 1 || !strings.Contains(stderr, tt.want) {
				t.Fatalf("daemon = (%d, %q), want refusal containing %q", code, stderr, tt.want)
			}
		})
	}
	if _, stderr, code := runCLIForTest([]string{"daemon", "extra"}, cliDeps{Sys: cliTestSys{euid: 0}}); code != 2 {
		t.Fatalf("daemon extra = (%d, %q), want usage error", code, stderr)
	}
}

func TestDaemonIsHiddenFromUsage(t *testing.T) {
	stdout, _, _ := runCLIForTest([]string{"help"}, cliDeps{Sys: cliTestSys{euid: 501}})
	if regexp.MustCompile(`(?m)^\s+daemon\s`).MatchString(stdout) {
		t.Fatalf("usage lists the hidden daemon command:\n%s", stdout)
	}
}
