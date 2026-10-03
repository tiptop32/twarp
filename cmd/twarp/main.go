// Command twarp manages an external sing-box and splits traffic into gateway, direct and vpn flows.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
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
	{"gateway", "manage gateway CIDRs"},
	{"geo", "update geoip/geosite rule-sets"},
	{"status", "show daemon and routing status"},
	{"mcp", "run the MCP server on stdio"},
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type cliDeps struct {
	Sys          config.Sys
	Stdin        io.Reader
	Random       io.Reader
	Clash        func(config.Config, config.Secrets) func() bool
	Runner       sysexec.Runner
	FS           launchd.FS
	Executable   func() (string, error)
	Dial         func(context.Context, string, string) (net.Conn, error)
	HTTPClient   *http.Client
	LookupIP     func(context.Context, string, string) ([]net.IP, error)
	Now          func() time.Time
	MCPTransport mcpTransportFactory
}

func defaultCLIDeps() cliDeps {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	dialer := &net.Dialer{}
	return cliDeps{
		Sys:        config.OSSys{},
		Stdin:      os.Stdin,
		Random:     rand.Reader,
		Runner:     sysexec.ExecRunner{},
		FS:         launchd.OSFS{},
		Executable: os.Executable,
		Dial:       dialer.DialContext,
		HTTPClient: httpClient,
		LookupIP:   net.DefaultResolver.LookupIP,
		Now:        time.Now,
		MCPTransport: func(io.Reader, io.Writer) mcpTransport {
			return stdioMCPTransport()
		},
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
	case "render":
		return runRender(args[1:], stdout, stderr, deps)
	case "apply":
		return runApply(args[1:], stdout, stderr, deps)
	case "install":
		return runInstall(args[1:], stdout, stderr, deps)
	case "uninstall":
		return runUninstall(args[1:], stdout, stderr, deps)
	case "gateway":
		return runGateway(args[1:], stdout, stderr, deps)
	case "geo":
		return runGeo(args[1:], stdout, stderr, geoDeps{Sys: deps.Sys})
	case "status":
		return runStatus(args[1:], stdout, stderr, deps)
	case "mcp":
		return runMCP(args[1:], stdout, stderr, deps)
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
