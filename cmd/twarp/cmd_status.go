package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/app"
)

func runStatus(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	flags := flag.NewFlagSet("twarp status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	checkNetwork := flags.Bool("net", false, "check the public egress address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "twarp status: unexpected arguments: %v\n", flags.Args())
		return 2
	}

	status := deps.app(app.ActorCLI).Status(context.Background(), app.StatusOptions{Network: *checkNetwork})
	for _, check := range status.Checks {
		_, _ = fmt.Fprintf(stdout, "%-4s %s: %s\n", check.Level, check.Name, check.Detail)
	}
	if status.Failed() {
		return 1
	}
	return 0
}
