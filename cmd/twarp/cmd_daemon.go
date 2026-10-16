package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/signal"
	"syscall"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/daemon"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/netwatch"
)

// runDaemon is twarpd. launchd starts it as root from the plist that install
// writes, with TWARP_OWNER_UID, TWARP_OWNER_GID and TWARP_OWNER_USER set. It
// is not listed in usage.
func runDaemon(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("daemon", args, stderr); done {
		return code
	}
	if err := checkDaemonEnvironment(deps); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp daemon: %v\n", err)
		return 1
	}
	owner, _ := config.OwnerFromEnv(deps.Sys)
	// Every read of the owner's files as root now refuses symlinks, special
	// files and files of other users.
	fsutil.GuardUserFiles(owner.UID)

	logger := log.New(stdout, "twarpd: ", log.LstdFlags)
	source, err := netwatch.Open()
	if err != nil {
		logger.Printf("network events unavailable, checking every 30s only: %v", err)
		source = nil
	}
	if source != nil {
		defer func() { _ = source.Close() }()
	}
	twarpd := daemon.New(daemon.Deps{
		Sys:        deps.Sys,
		SocketPath: ipc.SocketPath(deps.Sys),
		OwnerUID:   owner.UID,
		NewService: func(actor string, resolve daemon.ResolveFunc) daemon.Service {
			return deps.appWithResolver(actor, resolve)
		},
		Lookup: deps.LookupIP,
		Source: source,
		Logf:   logger.Printf,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := twarpd.Run(ctx); err != nil {
		logger.Printf("stopped: %v", err)
		return 1
	}
	logger.Printf("stopped")
	return 0
}

// checkDaemonEnvironment refuses to serve without root, without an owner, or
// from a binary that a non-root user could replace.
func checkDaemonEnvironment(deps cliDeps) error {
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		return errors.New("must run as root; launchd starts it after sudo twarp install")
	}
	owner, ok := config.OwnerFromEnv(deps.Sys)
	if !ok || owner.User == "" {
		return errors.New("TWARP_OWNER_UID, TWARP_OWNER_GID and TWARP_OWNER_USER are required; sudo twarp install sets them")
	}
	if owner.UID == 0 {
		return errors.New("the owner must be a regular user, not root")
	}
	if deps.Executable == nil {
		return errors.New("cannot find the twarp executable")
	}
	executable, err := deps.Executable()
	if err != nil {
		return fmt.Errorf("find the twarp executable: %w", err)
	}
	if _, err := fsutil.TrustedExecutable(executable, 0); err != nil {
		return fmt.Errorf("refusing to serve from a replaceable binary: %w", err)
	}
	return nil
}

var _ daemon.Service = (*app.Service)(nil)
