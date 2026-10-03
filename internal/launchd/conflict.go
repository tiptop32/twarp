package launchd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tiptop32/twarp/internal/sysexec"
)

const conflictingVPNHint = "another VPN (Outline/warp?) holds the default route; quit it first"

// Conflict describes the interface currently holding the default route.
type Conflict struct {
	Interface string
	Addr      string
	Hint      string
	OwnTUN    bool
}

// DetectConflict checks whether another tunnel owns the IPv4 default route.
func DetectConflict(ctx context.Context, runner sysexec.Runner) (Conflict, error) {
	output, err := runner.Run(ctx, "route", "-n", "get", "1.1.1.1")
	if err != nil {
		return Conflict{}, fmt.Errorf("inspect default route: %w", err)
	}

	interfaceName := fieldValue(string(output), "interface:")
	if interfaceName == "" {
		return Conflict{}, errors.New("inspect default route: interface is missing")
	}
	if !strings.HasPrefix(interfaceName, "utun") {
		return Conflict{}, nil
	}

	output, err = runner.Run(ctx, "ifconfig", interfaceName)
	if err != nil {
		return Conflict{}, fmt.Errorf("inspect tunnel %s: %w", interfaceName, err)
	}
	address := inetAddress(string(output))
	if address == "" {
		return Conflict{}, fmt.Errorf("inspect tunnel %s: IPv4 address is missing", interfaceName)
	}
	if address == "172.19.0.1" {
		return Conflict{Interface: interfaceName, Addr: address, OwnTUN: true}, nil
	}
	return Conflict{Interface: interfaceName, Addr: address, Hint: conflictingVPNHint}, nil
}

// CheckBrewService rejects a sing-box instance loaded by brew services.
func CheckBrewService(ctx context.Context, runner sysexec.Runner, uid int) error {
	targets := []string{
		"system/homebrew.mxcl.sing-box",
		sysexec.GUIDomain(uid) + "/homebrew.mxcl.sing-box",
	}
	for _, target := range targets {
		if _, err := runner.Run(ctx, "launchctl", "print", target); err == nil {
			return errors.New("brew services sing-box is loaded; run: brew services stop sing-box")
		}
	}
	return nil
}

func fieldValue(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			return fields[1]
		}
	}
	return ""
}

func inetAddress(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "inet" {
			return fields[1]
		}
	}
	return ""
}
