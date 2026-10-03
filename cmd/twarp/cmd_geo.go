package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
)

const defaultRootLogDir = "/usr/local/var/log/twarp"

type geoDeps struct {
	Sys     config.Sys
	Options geo.Options
}

func runGeo(args []string, stdout, stderr io.Writer, deps geoDeps) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: twarp geo update")
		return 2
	}
	if args[0] != "update" {
		_, _ = fmt.Fprintf(stderr, "twarp geo: unknown command %q\n", args[0])
		return 2
	}

	fs := flag.NewFlagSet("twarp geo update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "twarp geo update: unexpected arguments: %v\n", fs.Args())
		return 2
	}
	if deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp geo update: run with sudo: geo/ is owned by root")
		return 1
	}

	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp geo update: %v\n", err)
		return 1
	}
	options := deps.Options
	options.Dir = paths.GeoDir()
	options.AuditFile = rootAuditFile(deps.Sys)

	report, err := geo.Update(context.Background(), options)
	for _, file := range report.Files {
		_, _ = fmt.Fprintf(stdout, "updated %s: %d bytes, mtime %s\n", file.Name, file.Size, file.ModTime.UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp geo update: %v\n", err)
		return 1
	}
	return 0
}
