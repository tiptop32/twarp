package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/uri"
)

func runImport(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp import: the URI is read from stdin only, so it never lands in shell history")
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
	outbound, err := uri.Parse(raw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: %v\n", err)
		return 1
	}

	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(paths.Home, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: create home: %v\n", err)
		return 1
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(stderr, "twarp import: %v\n", err)
		return 1
	}
	if secrets.ClashSecret == "" {
		secretBytes := make([]byte, 32)
		if _, err := io.ReadFull(deps.Random, secretBytes); err != nil {
			_, _ = fmt.Fprintf(stderr, "twarp import: generate clash secret: %v\n", err)
			return 1
		}
		secrets.ClashSecret = hex.EncodeToString(secretBytes)
	}
	secrets.VPNURI = raw
	if err := config.SaveSecrets(paths.SecretsFile(), secrets); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp import: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "imported vpn outbound: %s:%d (reality, sni %s)\n", outbound.Server, outbound.ServerPort, outbound.TLS.ServerName)
	return 0
}
