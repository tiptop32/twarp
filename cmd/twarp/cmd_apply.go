package main

import (
	"context"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/ipc"
)

// runApply re-renders, checks and reloads sing-box; see app.Service.Apply.
func runApply(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, stop := parseNoArgs("apply", args, stderr); stop {
		return code
	}
	if deps.Sys.Geteuid() != 0 {
		return runViaDaemon("apply", ipc.OpApply, stdout, stderr, deps)
	}
	message, err := deps.app(app.ActorCLI).Apply(context.Background())
	if err != nil {
		return lifecycleError("apply", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}
