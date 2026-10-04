package main

import (
	"context"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/app"
)

// runStart turns the tunnel on without reinstalling; see app.Service.Start.
func runStart(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("start", args, stderr); done {
		return code
	}
	message, err := deps.app(app.ActorCLI).Start(context.Background())
	if err != nil {
		return lifecycleError("start", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}

// runStop turns the tunnel off and keeps it installed; see app.Service.Stop.
func runStop(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, done := parseNoArgs("stop", args, stderr); done {
		return code
	}
	message, err := deps.app(app.ActorCLI).Stop(context.Background())
	if err != nil {
		return lifecycleError("stop", stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, message)
	return 0
}
