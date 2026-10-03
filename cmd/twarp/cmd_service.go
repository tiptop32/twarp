package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

// runStart turns the tunnel on without reinstalling: it loads the installed
// sing-box daemon, or restarts it when it is loaded but not routing.
func runStart(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("start", args, stderr); done {
		return code
	}
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp start: run with sudo")
		return 1
	}
	if _, err := deps.FS.Stat(launchd.SingBoxPlistPath); errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(stderr, "twarp start: not installed: run sudo twarp install")
		return 1
	} else if err != nil {
		return lifecycleError("start", stderr, err)
	}

	ctx := context.Background()
	conflict, err := launchd.DetectConflict(ctx, deps.Runner)
	if err != nil {
		return lifecycleError("start", stderr, err)
	}
	switch {
	case conflict.OwnTUN:
		_, _ = fmt.Fprintf(stdout, "already running on %s\n", conflict.Interface)
		return 0
	case conflict.Hint != "":
		return lifecycleError("start", stderr, fmt.Errorf("%s (%s %s)", conflict.Hint, conflict.Interface, conflict.Addr))
	}

	// A loaded service that does not hold the route has crashed or was stopped
	// by launchd; kickstart restarts it. An unloaded one needs bootstrap.
	service, printErr := deps.Runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if printErr == nil {
		if strings.Contains(string(service), "state = running") {
			_, _ = fmt.Fprintln(stdout, "sing-box is running but does not hold the default route yet; check: twarp status")
			return 0
		}
		err = sysexec.Kickstart(ctx, deps.Runner, sysexec.SystemTarget())
	} else {
		err = sysexec.Bootstrap(ctx, deps.Runner, "system", launchd.SingBoxPlistPath)
	}
	if err != nil {
		return lifecycleError("start", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, "started; check: twarp status")
	return 0
}

// runStop turns the tunnel off and keeps everything installed, so the default
// route returns to the network (or to another VPN) until twarp start.
func runStop(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("stop", args, stderr); done {
		return code
	}
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp stop: run with sudo")
		return 1
	}
	if err := sysexec.Bootout(context.Background(), deps.Runner, sysexec.SystemTarget()); err != nil {
		return lifecycleError("stop", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, "stopped; start again: sudo twarp start")
	return 0
}
