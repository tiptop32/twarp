package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tiptop32/twarp/internal/app"
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

	gateway, err := deps.app(app.ActorCLI).Gateway()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway: %v\n", err)
		return 1
	}
	switch args[0] {
	case "add":
		code := runGatewayAdd(gateway, args[1:], stdout, stderr)
		warnNotInstalled(stderr, gateway, code)
		return code
	case "rm":
		code := runGatewayRemove(gateway, args[1:], stdout, stderr)
		warnNotInstalled(stderr, gateway, code)
		return code
	case "ls":
		return runGatewayList(gateway, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "twarp gateway: unknown command %q\n", args[0])
		return 2
	}
}

func runGatewayAdd(gateway *app.Gateway, args []string, stdout, stderr io.Writer) int {
	input, comment, force, err := parseGatewayAddArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway add: %v\n", err)
		return 2
	}
	result, err := gateway.AddGatewayCIDR(context.Background(), app.AddGatewayRequest{CIDR: input, Comment: comment, Force: force})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway add: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, app.AddResultText(result))
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

func runGatewayRemove(gateway *app.Gateway, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(stderr, "twarp gateway rm: usage: twarp gateway rm <cidr>")
		return 2
	}
	result, err := gateway.RemoveGatewayCIDR(context.Background(), args[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway rm: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, app.RemoveResultText(result))
	printWarnings(stderr, result.Warnings)
	return 0
}

func runGatewayList(gateway *app.Gateway, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp gateway ls: usage: twarp gateway ls")
		return 2
	}
	entries, err := gateway.ListGatewayCIDRs(context.Background())
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
func warnNotInstalled(stderr io.Writer, gateway *app.Gateway, code int) {
	if code == 0 && !gateway.Installed() {
		_, _ = fmt.Fprintln(stderr, "warning: "+app.NotInstalledWarning)
	}
}
