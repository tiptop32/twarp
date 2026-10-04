package main

import (
	"context"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/app"
)

// runApply re-renders, checks and reloads sing-box; see app.Service.Apply.
func runApply(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, stop := parseNoArgs("apply", args, stderr); stop {
		return code
	}
	message, err := deps.app(app.ActorCLI).Apply(context.Background())
	if err != nil {
		return lifecycleError("apply", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}
