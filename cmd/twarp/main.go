// Command twarp manages an external sing-box and splits traffic into corp, direct and vpn flows.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
)

// command is one twarp subcommand.
type command struct {
	name    string
	summary string
}

var commands = []command{
	{"migrate", "convert legacy config into twarp format"},
	{"import", "import a VPN URI as the vpn outbound"},
	{"render", "render sing-box config.json"},
	{"apply", "render, check and hot-reload sing-box"},
	{"install", "install the sing-box launchd daemon"},
	{"uninstall", "remove the sing-box launchd daemon"},
	{"corp-ip", "manage the corp CIDR list"},
	{"geo", "update geoip/geosite rule-sets"},
	{"status", "show daemon and routing status"},
	{"mcp", "run the MCP server on stdio"},
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type cliDeps struct {
	Sys    config.Sys
	Stdin  io.Reader
	Random io.Reader
	Clash  func(config.Config, config.Secrets) func() bool
}

func defaultCLIDeps() cliDeps {
	return cliDeps{
		Sys:    config.OSSys{},
		Stdin:  os.Stdin,
		Random: rand.Reader,
		Clash: func(cfg config.Config, secrets config.Secrets) func() bool {
			return singbox.Clash{Addr: cfg.ClashAPI, Secret: secrets.ClashSecret}.RunningFunc()
		},
	}
}

// run dispatches args to a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	return runWithDeps(args, stdout, stderr, defaultCLIDeps())
}

func runWithDeps(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return 0
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	case "import":
		return runImport(args[1:], stdout, stderr, deps)
	case "corp-ip":
		return runCorpIP(args[1:], stdout, stderr, deps)
	case "geo":
		return runGeo(args[1:], stdout, stderr, geoDeps{Sys: config.OSSys{}})
	}
	for _, c := range commands {
		if c.name == args[0] {
			return runStub(c, args[1:], stderr)
		}
	}
	_, _ = fmt.Fprintf(stderr, "twarp: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

// runStub parses common flags and reports that the command is not implemented yet.
func runStub(c command, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("twarp "+c.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "twarp %s: not implemented\n", c.name)
	return 1
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: twarp <command> [flags]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		_, _ = fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}
