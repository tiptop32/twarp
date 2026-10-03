package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

func runGateway(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.Sys.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "twarp gateway: do not run gateway with sudo")
		return 1
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: twarp gateway add|rm|ls")
		return 2
	}

	store, rulesDir, err := newGatewayStore(deps)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway: %v\n", err)
		return 1
	}
	switch args[0] {
	case "add":
		code := runGatewayAdd(store, args[1:], stdout, stderr)
		warnNotInstalled(stderr, rulesDir, code)
		return code
	case "rm":
		code := runGatewayRemove(store, args[1:], stdout, stderr)
		warnNotInstalled(stderr, rulesDir, code)
		return code
	case "ls":
		return runGatewayList(store, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "twarp gateway: unknown command %q\n", args[0])
		return 2
	}
}

func newGatewayStore(deps cliDeps) (*state.Store, string, error) {
	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return nil, "", err
	}
	host, _, err := net.SplitHostPort(cfg.Gateway.Socks)
	if err != nil {
		return nil, "", fmt.Errorf("parse gateway.socks: %w", err)
	}
	gatewaySocks, err := netip.ParseAddr(host)
	if err != nil {
		return nil, "", fmt.Errorf("gateway.socks host must be an IP address: %w", err)
	}

	var running func() bool
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err == nil {
		if deps.Clash != nil {
			running = deps.Clash(cfg, secrets)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	return state.New(state.Options{
		File:          paths.GatewayIPsFile(),
		LockFile:      paths.LockFile(),
		AuditFile:     paths.AuditFile(),
		AllowedRanges: cfg.Gateway.AllowedRanges,
		GatewaySocks:  gatewaySocks,
		OnChange:      render.OnChangeWriter(paths.RulesDir()),
		Running:       running,
	}), paths.RulesDir(), nil
}

func runGatewayAdd(store *state.Store, args []string, stdout, stderr io.Writer) int {
	input, comment, force, err := parseGatewayAddArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway add: %v\n", err)
		return 2
	}
	result, err := store.Add(context.Background(), "cli", input, comment, force)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway add: %v\n", err)
		return 1
	}
	switch result.Status {
	case state.AddStatusAdded:
		_, _ = fmt.Fprintf(stdout, "added %s\n", result.CIDR)
	case state.AddStatusAlreadyPresent:
		_, _ = fmt.Fprintf(stdout, "already present: %s\n", result.CIDR)
	case state.AddStatusCoveredBy:
		_, _ = fmt.Fprintf(stdout, "covered by %s: %s\n", result.CoveredBy, result.CIDR)
	}
	printWarnings(stderr, result.Warnings)
	return 0
}

func parseGatewayAddArgs(args []string) (input, comment string, force bool, err error) {
	positionals := make([]string, 0, 1)
	for index := 0; index < len(args); index++ {
		switch arg := args[index]; {
		case arg == "--force":
			force = true
		case arg == "--comment":
			index++
			if index >= len(args) {
				return "", "", false, errors.New("--comment requires a value")
			}
			comment = args[index]
		case strings.HasPrefix(arg, "--comment="):
			comment = strings.TrimPrefix(arg, "--comment=")
		case strings.HasPrefix(arg, "-"):
			return "", "", false, fmt.Errorf("unknown flag %q", arg)
		default:
			positionals = append(positionals, arg)
		}
	}
	if len(positionals) != 1 {
		return "", "", false, errors.New("usage: twarp gateway add <cidr> [--comment text] [--force]")
	}
	return positionals[0], comment, force, nil
}

func runGatewayRemove(store *state.Store, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(stderr, "twarp gateway rm: usage: twarp gateway rm <cidr>")
		return 2
	}
	result, err := store.Remove(context.Background(), "cli", args[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway rm: %v\n", err)
		return 1
	}
	if result.Status == state.RemoveStatusRemoved {
		_, _ = fmt.Fprintf(stdout, "removed %s\n", result.CIDR)
	} else {
		_, _ = fmt.Fprintf(stdout, "not found: %s\n", result.CIDR)
	}
	printWarnings(stderr, result.Warnings)
	return 0
}

func runGatewayList(store *state.Store, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp gateway ls: usage: twarp gateway ls")
		return 2
	}
	entries, err := store.List()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway ls: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(stdout, "no gateway CIDRs")
		return 0
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "CIDR\tADDED_BY\tADDED_AT\tCOMMENT")
	for _, entry := range entries {
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", entry.CIDR, entry.AddedBy, entry.AddedAt.UTC().Format(time.RFC3339), entry.Comment)
	}
	if err := table.Flush(); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway ls: write output: %v\n", err)
		return 1
	}
	return 0
}

func printWarnings(stderr io.Writer, warnings []string) {
	for _, warning := range warnings {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
}

// warnNotInstalled explains why a successful change did not reach sing-box yet.
func warnNotInstalled(stderr io.Writer, rulesDir string, code int) {
	if code == 0 && !render.Installed(rulesDir) {
		_, _ = fmt.Fprintln(stderr, "warning: twarp is not installed yet: saved to gateway-ips.json; sudo twarp install will write the rule-set")
	}
}
