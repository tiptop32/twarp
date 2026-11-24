package main

import (
	"context"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/app"
)

func runXray(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	const usage = "Usage: twarp xray {install|uninstall} TUNNEL"
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, _ = fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(args) != 2 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	ctx := context.Background()
	service := deps.app(app.ActorCLI)
	var message string
	var err error
	switch args[0] {
	case "install":
		err = service.InstallXray(ctx, args[1])
		message = "Xray is listening; to load routes: twarp apply; to probe: twarp status --net"
	case "uninstall":
		err = service.UninstallXray(ctx, args[1])
		message = "Xray login agent removed; sing-box routes are unchanged"
	default:
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp xray: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}
