package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/launchd"
)

// fakeDaemon answers ipc requests in place of twarpd.
type fakeDaemon struct {
	mu       sync.Mutex
	requests []ipc.Request
	summary  string
	err      error
	live     *ipc.LiveStatus
}

func (daemon *fakeDaemon) call(_ context.Context, request ipc.Request) (ipc.Response, error) {
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	daemon.requests = append(daemon.requests, request)
	if daemon.err != nil {
		return ipc.Response{Error: daemon.err.Error()}, daemon.err
	}
	return ipc.Response{OK: true, Summary: daemon.summary, Live: daemon.live}, nil
}

func (daemon *fakeDaemon) ops() string {
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	ops := make([]string, 0, len(daemon.requests))
	for _, request := range daemon.requests {
		ops = append(ops, request.Op)
	}
	return strings.Join(ops, ",")
}

func unavailableDaemon(context.Context, ipc.Request) (ipc.Response, error) {
	return ipc.Response{}, ipc.ErrDaemonUnavailable
}

// installedSys reports the sing-box plist as installed.
type installedSys struct{ cliTestSys }

func (installedSys) Stat(name string) (os.FileInfo, error) {
	if name == launchd.SingBoxPlistPath {
		return os.Stat(os.TempDir())
	}
	return nil, os.ErrNotExist
}

func TestRunUpAndDownGoThroughDaemon(t *testing.T) {
	daemon := &fakeDaemon{summary: "started; check: twarp status"}
	deps := cliDeps{Sys: installedSys{cliTestSys{euid: 501}}, IPC: daemon.call}
	stdout, stderr, code := runCLIForTest([]string{"up"}, deps)
	if code != 0 || stdout != "started; check: twarp status\n" || stderr != "" {
		t.Fatalf("up = (%d, %q, %q)", code, stdout, stderr)
	}
	daemon.summary = "stopped; start again: twarp up"
	if stdout, _, code := runCLIForTest([]string{"down"}, deps); code != 0 || !strings.Contains(stdout, "stopped") {
		t.Fatalf("down = (%d, %q)", code, stdout)
	}
	if daemon.ops() != "up,down" || daemon.requests[0].Actor != ipc.ActorCLI {
		t.Fatalf("requests = %+v, want up then down from the CLI", daemon.requests)
	}
}

func TestRunUpWithoutInstallOrDaemon(t *testing.T) {
	daemon := &fakeDaemon{}
	_, stderr, code := runCLIForTest([]string{"up"}, cliDeps{Sys: cliTestSys{euid: 501}, IPC: daemon.call})
	if code != 1 || !strings.Contains(stderr, "not installed; run once: sudo twarp install") || daemon.ops() != "" {
		t.Fatalf("up before install = (%d, %q), ops %q", code, stderr, daemon.ops())
	}

	_, stderr, code = runCLIForTest([]string{"down"}, cliDeps{Sys: installedSys{cliTestSys{euid: 501}}, IPC: unavailableDaemon})
	if code != 1 || !strings.Contains(stderr, "twarpd is not running") || !strings.Contains(stderr, "sudo launchctl kickstart system/dev.twarp.daemon") {
		t.Fatalf("down without twarpd = (%d, %q), want kickstart hint", code, stderr)
	}

	failing := &fakeDaemon{err: errors.New("sing-box check failed")}
	_, stderr, code = runCLIForTest([]string{"up"}, cliDeps{Sys: installedSys{cliTestSys{euid: 501}}, IPC: failing.call})
	if code != 1 || !strings.Contains(stderr, "twarp up: sing-box check failed") {
		t.Fatalf("up with failing daemon = (%d, %q)", code, stderr)
	}
}

func TestRunWithoutArgumentsOpensTUIOnlyInTerminal(t *testing.T) {
	stdout, _, code := runCLIForTest(nil, cliDeps{Sys: cliTestSys{euid: 501}, IsTerminal: func(io.Writer) bool { return false }})
	if code != 0 || !strings.Contains(stdout, "Usage: twarp") {
		t.Fatalf("twarp without a terminal = (%d, %q), want usage", code, stdout)
	}
	lines := strings.Split(stdout, "\n")
	commandsAt := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == "Commands:" {
			commandsAt = index
		}
	}
	if commandsAt < 0 || !strings.HasPrefix(strings.TrimSpace(lines[commandsAt+1]), "up ") || !strings.HasPrefix(strings.TrimSpace(lines[commandsAt+2]), "down ") {
		t.Fatalf("usage must list up and down first:\n%s", stdout)
	}
}
