package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDaemonRefusesUnsafeEnvironment(t *testing.T) {
	directory := t.TempDir()
	writable := filepath.Join(directory, "twarp")
	if err := os.WriteFile(writable, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	owner := map[string]string{"TWARP_OWNER_UID": "501", "TWARP_OWNER_GID": "20", "TWARP_OWNER_USER": "alice"}
	executable := func() (string, error) { return writable, nil }
	tests := []struct {
		name string
		deps cliDeps
		want string
	}{
		{name: "user", deps: cliDeps{Sys: cliTestSys{euid: 501, env: owner}, Executable: executable}, want: "must run as root"},
		{name: "no owner", deps: cliDeps{Sys: cliTestSys{euid: 0, env: map[string]string{}}, Executable: executable}, want: "TWARP_OWNER_UID, TWARP_OWNER_GID and TWARP_OWNER_USER are required"},
		{name: "root owner", deps: cliDeps{Sys: cliTestSys{euid: 0, env: map[string]string{"TWARP_OWNER_UID": "0", "TWARP_OWNER_GID": "0", "TWARP_OWNER_USER": "root"}}, Executable: executable}, want: "must be a regular user"},
		{name: "writable binary", deps: cliDeps{Sys: cliTestSys{euid: 0, env: owner}, Executable: executable}, want: "refusing to serve from a replaceable binary"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, code := runCLIForTest([]string{"daemon"}, test.deps)
			if code != 1 || stdout != "" || !strings.Contains(stderr, test.want) {
				t.Fatalf("daemon = (%d, %q, %q), want %q", code, stdout, stderr, test.want)
			}
		})
	}
	if _, stderr, code := runCLIForTest([]string{"daemon", "extra"}, cliDeps{Sys: cliTestSys{euid: 0}}); code != 2 || !strings.Contains(stderr, "unexpected arguments") {
		t.Fatalf("daemon extra = (%d, %q)", code, stderr)
	}
	var usage strings.Builder
	runWithDeps([]string{"help"}, &usage, &usage, cliDeps{})
	if strings.Contains(usage.String(), "  daemon ") {
		t.Fatalf("usage lists the hidden daemon command:\n%s", usage.String())
	}
}
