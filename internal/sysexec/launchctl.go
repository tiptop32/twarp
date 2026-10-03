package sysexec

import (
	"context"
	"strconv"
	"strings"
)

const (
	// Label is the system launchd service label for sing-box.
	Label = "dev.twarp.singbox"
	// GeoLabel is the per-user launchd service label for geo updates.
	GeoLabel = "dev.twarp.geo"
)

// SystemTarget returns the launchctl target for the system sing-box service.
func SystemTarget() string {
	return "system/" + Label
}

// GUIDomain returns the launchctl domain for uid.
func GUIDomain(uid int) string {
	return "gui/" + strconv.Itoa(uid)
}

// GUITarget returns the launchctl target for the per-user geo service.
func GUITarget(uid int) string {
	return GUIDomain(uid) + "/" + GeoLabel
}

// Bootstrap loads a service plist into a launchd domain.
func Bootstrap(ctx context.Context, runner Runner, domain, plistPath string) error {
	_, err := runner.Run(ctx, "launchctl", "bootstrap", domain, plistPath)
	return err
}

// Bootout removes a service by its target (domain/label). An absent service is
// treated as success to make uninstall idempotent. The target form is used on
// purpose: on macOS 15 an unloaded service addressed by plist path fails with
// "5: Input/output error", which cannot be told apart from a real failure.
func Bootout(ctx context.Context, runner Runner, target string) error {
	output, err := runner.Run(ctx, "launchctl", "bootout", target)
	if err == nil {
		return nil
	}
	detail := string(output) + "\n" + err.Error()
	if strings.Contains(detail, "No such process") ||
		strings.Contains(detail, "Could not find specified service") {
		return nil
	}
	return err
}

// Kill sends signal to a launchd service target.
func Kill(ctx context.Context, runner Runner, signal, target string) error {
	_, err := runner.Run(ctx, "launchctl", "kill", signal, target)
	return err
}

// Kickstart restarts a launchd service target immediately.
func Kickstart(ctx context.Context, runner Runner, target string) error {
	_, err := runner.Run(ctx, "launchctl", "kickstart", "-k", target)
	return err
}
