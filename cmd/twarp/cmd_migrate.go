package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/migrate"
)

func runMigrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("twarp migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	system := config.OSSys{}
	from := fs.String("from", filepath.Join(system.Getenv("HOME"), ".warp.yaml"), "legacy warp config path")
	force := fs.Bool("force", false, "overwrite existing twarp config and state")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if system.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "twarp migrate: do not run migrate with sudo")
		return 1
	}
	paths, err := config.Resolve(system)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp migrate: %v\n", err)
		return 1
	}
	report, err := migrate.Run(migrate.Options{From: *from, Paths: paths, Force: *force, Sys: system})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp migrate: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\nwrote %s (%d CIDRs)\n", report.ConfigWritten, report.StateWritten, report.CIDRs)
	for _, warning := range report.Warnings {
		_, _ = fmt.Fprintf(stdout, "warning: %s\n", warning)
	}
	return 0
}
