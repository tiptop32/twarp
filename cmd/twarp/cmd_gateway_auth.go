package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tiptop32/twarp/internal/config"
)

// runGatewayAuth stores or clears the SOCKS username/password of the gateway
// in secrets.yaml. Credentials come from stdin only (first line user, second
// line password), so they never land in shell history.
func runGatewayAuth(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	fs := flag.NewFlagSet("twarp gateway auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	clearAuth := fs.Bool("clear", false, "remove the gateway SOCKS credentials")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp gateway auth: credentials are read from stdin only (user, then password, one per line), so they never land in shell history")
		return 2
	}

	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway auth: %v\n", err)
		return 1
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(stderr, "twarp gateway auth: %v\n", err)
		return 1
	}

	if *clearAuth {
		secrets.GatewaySocksUser, secrets.GatewaySocksPassword = "", ""
	} else {
		user, password, err := readGatewayCredentials(deps.Stdin)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "twarp gateway auth: %v\n", err)
			return 1
		}
		secrets.GatewaySocksUser, secrets.GatewaySocksPassword = user, password
	}

	if err := os.MkdirAll(paths.Home, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway auth: create home: %v\n", err)
		return 1
	}
	if err := config.SaveSecrets(paths.SecretsFile(), secrets); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp gateway auth: %v\n", err)
		return 1
	}
	if *clearAuth {
		_, _ = fmt.Fprintln(stdout, "removed gateway SOCKS credentials; apply them: twarp apply")
	} else {
		_, _ = fmt.Fprintf(stdout, "saved gateway SOCKS credentials for user %s; apply them: twarp apply\n", secrets.GatewaySocksUser)
	}
	return 0
}

// readGatewayCredentials reads "user\npassword" from stdin. Only the line
// endings are trimmed: a password may contain spaces.
func readGatewayCredentials(stdin io.Reader) (string, string, error) {
	if stdin == nil {
		return "", "", errors.New("no stdin")
	}
	data, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return "", "", fmt.Errorf("read stdin: %w", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return "", "", errors.New("put the user on the first line and the password on the second: twarp gateway auth < creds.txt")
	}
	if err := config.ValidateGatewayAuth(lines[0], lines[1]); err != nil {
		return "", "", err
	}
	return lines[0], lines[1], nil
}
