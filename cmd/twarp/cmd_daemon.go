package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/daemon"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/gwaddr"
	"github.com/tiptop32/twarp/internal/ipc"
	"github.com/tiptop32/twarp/internal/netwatch"
)

// runDaemon is the hidden "twarp daemon" that launchd runs as
// dev.twarp.daemon. Its log goes to stdout, which the plist sends to
// twarpd.log.
func runDaemon(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("daemon", args, stderr); done {
		return code
	}
	if deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp daemon: must run as root (launchd starts it as dev.twarp.daemon)")
		return 1
	}
	ownerUID, _, owner, ok := config.Owner(deps.Sys)
	if !ok || owner == "" {
		_, _ = fmt.Fprintln(stderr, "twarp daemon: TWARP_OWNER_UID, TWARP_OWNER_GID and TWARP_OWNER_USER are required; reinstall: sudo twarp install")
		return 1
	}
	if deps.Executable == nil {
		_, _ = fmt.Fprintln(stderr, "twarp daemon: cannot resolve the twarp executable")
		return 1
	}
	executable, err := deps.Executable()
	if err == nil {
		_, err = fsutil.TrustedPath(executable, 0)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp daemon: refusing to run a binary a non-root user could replace: %v; install it with make install\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logger := slog.New(slog.NewTextHandler(stdout, nil))

	var events <-chan struct{}
	if source, err := netwatch.OpenRoutingSocket(); err != nil {
		logger.Warn("network events unavailable, checking on the tick only", "error", err)
	} else {
		defer func() { _ = source.Close() }()
		events = source.Events()
	}

	configPath := func() string { return config.Paths{Out: config.OutputDir(deps.Sys)}.OutConfig() }
	twarpd := daemon.New(daemon.Deps{
		Socket:      ipc.SocketPath(deps.Sys.Getenv),
		AllowedUIDs: []int{ownerUID, 0},
		Ops:         func(actor string) daemon.Ops { return deps.app(actor) },
		Configured: func() (string, error) {
			paths, err := config.Resolve(deps.Sys)
			if err != nil {
				return "", err
			}
			cfg, err := config.Load(paths.ConfigFile())
			if err != nil {
				return "", err
			}
			return cfg.Gateway.Socks, nil
		},
		Resolve: func(ctx context.Context, hostport string) (netip.AddrPort, error) {
			return gwaddr.Resolve(ctx, deps.LookupIP, hostport)
		},
		Live: func() (app.LiveConfig, error) { return app.ReadLiveConfig(configPath()) },
		Stale: func(appliedAt time.Time) (bool, error) {
			paths, err := config.Resolve(deps.Sys)
			if err != nil {
				return false, err
			}
			return app.ConfigStale(paths, appliedAt)
		},
		Events: events,
		Logger: logger,
	})
	logger.Info("twarpd starting", "owner", owner, "uid", ownerUID)
	if err := twarpd.Run(ctx); err != nil {
		logger.Error("twarpd stopped", "error", err)
		return 1
	}
	logger.Info("twarpd stopped")
	return 0
}
