package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/config"
)

func runImport(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	var name string
	if len(args) == 2 && args[0] == "--name" && config.ValidTunnelName(args[1]) {
		name = args[1]
	} else if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: twarp import [--name TUNNEL] (name: ASCII letters, digits or hyphens); the URI is read from stdin only")
		return 2
	}
	if deps.Sys.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "twarp import: do not run import with sudo")
		return 1
	}

	rawBytes, err := io.ReadAll(deps.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: read stdin: %v\n", err)
		return 1
	}
	raw := strings.TrimSpace(string(rawBytes))
	if raw == "" {
		_, _ = fmt.Fprintln(stderr, "twarp import: paste the VPN URI on stdin: twarp import < key.txt")
		return 1
	}
	service := app.New(app.Deps{Sys: deps.Sys}, app.ActorCLI)
	protocol, err := service.ImportVPN(name, raw, deps.Random)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: %v\n", err)
		return 1
	}
	target := "vpn"
	if name != "" {
		target = "vpn-" + name
	}
	_, _ = fmt.Fprintf(stdout, "imported %s outbound (%s)\n", target, protocol)
	return 0
}
