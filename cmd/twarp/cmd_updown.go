package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/launchd"
)

const (
	// daemonOpTimeout covers sing-box check and a reload; geo update downloads.
	daemonOpTimeout     = 60 * time.Second
	daemonGeoTimeout    = 3 * time.Minute
	daemonStatusTimeout = 5 * time.Second
	daemonKickstartHint = "sudo launchctl kickstart system/dev.twarp.daemon"
)

// callDaemon sends one request to twarpd; tests replace deps.IPC.
func (deps cliDeps) callDaemon(ctx context.Context, request ipc.Request) (ipc.Response, error) {
	if deps.IPC != nil {
		return deps.IPC(ctx, request)
	}
	return ipc.Call(ctx, ipc.SocketPath(deps.Sys.Getenv), request)
}

// runViaDaemon runs a root operation through twarpd for a non-root user, so
// no sudo password is needed after install.
func runViaDaemon(command, op string, stdout, stderr io.Writer, deps cliDeps) int {
	timeout := daemonOpTimeout
	if op == ipc.OpGeoUpdate {
		timeout = daemonGeoTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, err := deps.callDaemon(ctx, ipc.Request{Op: op, Actor: ipc.ActorCLI})
	switch {
	case errors.Is(err, ipc.ErrDaemonUnavailable):
		if !installed(deps) {
			_, _ = fmt.Fprintf(stderr, "twarp %s: not installed; run once: sudo twarp install\n", command)
		} else {
			_, _ = fmt.Fprintf(stderr, "twarp %s: twarpd is not running; start it: %s (or run: sudo twarp %s)\n", command, daemonKickstartHint, command)
		}
		return 1
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "twarp %s: %v\n", command, err)
		return 1
	}
	if response.Summary != "" {
		_, _ = fmt.Fprintln(stdout, response.Summary)
	}
	return 0
}

// installed reports whether sudo twarp install has run.
func installed(deps cliDeps) bool {
	if deps.Sys == nil {
		return false
	}
	_, err := deps.Sys.Stat(launchd.SingBoxPlistPath)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// runUp turns the tunnel on: apply, then start. Without sudo it goes
// through twarpd.
func runUp(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("up", args, stderr); done {
		return code
	}
	if deps.Sys.Geteuid() != 0 {
		if !installed(deps) {
			_, _ = fmt.Fprintln(stderr, "twarp up: not installed; run once: sudo twarp install")
			return 1
		}
		return runViaDaemon("up", ipc.OpUp, stdout, stderr, deps)
	}
	service := deps.app(app.ActorCLI)
	if _, err := service.Apply(context.Background()); err != nil {
		return lifecycleError("up", stderr, err)
	}
	message, err := service.Start(context.Background())
	if err != nil {
		return lifecycleError("up", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}

// runDown turns the tunnel off; see app.Service.Stop.
func runDown(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("down", args, stderr); done {
		return code
	}
	if deps.Sys.Geteuid() != 0 {
		return runViaDaemon("down", ipc.OpDown, stdout, stderr, deps)
	}
	message, err := deps.app(app.ActorCLI).Stop(context.Background())
	if err != nil {
		return lifecycleError("down", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}
