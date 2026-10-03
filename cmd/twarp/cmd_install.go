package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

func runInstall(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, stop := parseLifecycleArgs("install", args, stderr); stop {
		return code
	}
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp install: run with sudo")
		return 1
	}
	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		return lifecycleError("install", stderr, err)
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return lifecycleError("install", stderr, err)
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil {
		return lifecycleError("install", stderr, err)
	}

	var prefixes []netip.Prefix
	options := launchd.Options{
		Paths: paths, Config: cfg, Secrets: secrets,
		GeoUpdate: func(ctx context.Context) error {
			_, err := geo.Update(ctx, geo.Options{Dir: paths.GeoDir(), AuditFile: rootAuditFile(deps.Sys)})
			return err
		},
		RenderConfig: func() ([]byte, error) {
			var err error
			prefixes, err = state.ReadPrefixes(paths.CorpIPsFile(), paths.LockFile())
			if err != nil {
				return nil, err
			}
			return render.Render(cfg, secrets, prefixes, render.Options{Paths: paths, Inbound: render.InboundTUN})
		},
		WriteRuleSet: func(directory string) error {
			return render.WriteRuleSet(directory, prefixes)
		},
	}
	if err := launchd.Install(context.Background(), launchd.Deps{
		Runner: deps.Runner, Sys: deps.Sys, FS: deps.FS, Executable: deps.Executable,
	}, options); err != nil {
		return lifecycleError("install", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, "installed sing-box and geo launchd services")
	_, _ = fmt.Fprintln(stdout, "check: twarp status")
	return 0
}

func runUninstall(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, stop := parseLifecycleArgs("uninstall", args, stderr); stop {
		return code
	}
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp uninstall: run with sudo")
		return 1
	}
	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		return lifecycleError("uninstall", stderr, err)
	}
	if err := launchd.Uninstall(context.Background(), launchd.Deps{
		Runner: deps.Runner, Sys: deps.Sys, FS: deps.FS, Executable: deps.Executable,
	}); err != nil {
		return lifecycleError("uninstall", stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "uninstalled; config kept in %s, rules in %s\n", paths.Home, paths.Out)
	return 0
}

func parseLifecycleArgs(command string, args []string, stderr io.Writer) (int, bool) {
	fs := flag.NewFlagSet("twarp "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 2, true
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "twarp %s: unexpected arguments: %v\n", command, fs.Args())
		return 2, true
	}
	return 0, false
}

func lifecycleError(command string, stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "twarp %s: %v\n", command, err)
	return 1
}

func rootAuditFile(system config.Sys) string {
	directory := system.Getenv("TWARP_LOG_DIR")
	if directory == "" {
		directory = defaultRootLogDir
	}
	return filepath.Join(directory, "audit.jsonl")
}
