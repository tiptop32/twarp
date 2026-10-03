package singbox

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/tiptop32/twarp/internal/sysexec"
)

const (
	// MinMajor is the minimum supported sing-box major version.
	MinMajor = 1
	// MinMinor is the minimum supported sing-box minor version.
	MinMinor = 14
)

// Check validates a sing-box configuration with the selected binary.
func Check(ctx context.Context, runner sysexec.Runner, bin, configPath string) error {
	output, err := runner.Run(ctx, bin, "check", "-c", configPath)
	if err != nil {
		return commandError("check sing-box config", output, err)
	}
	return nil
}

// Version returns the sing-box version after enforcing the supported minimum.
func Version(ctx context.Context, runner sysexec.Runner, bin string) (string, error) {
	output, err := runner.Run(ctx, bin, "version")
	if err != nil {
		return "", commandError("read sing-box version", output, err)
	}

	firstLine, _, _ := strings.Cut(string(output), "\n")
	fields := strings.Fields(strings.TrimSuffix(firstLine, "\r"))
	if len(fields) < 3 || fields[0] != "sing-box" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected sing-box version output: %q", firstLine)
	}
	version := fields[2]
	if err := RequireMinVersion(version, MinMajor, MinMinor); err != nil {
		return "", err
	}
	return version, nil
}

// RequireMinVersion rejects versions older than major.minor. Pre-release
// suffixes do not affect the comparison because sing-box compatibility is
// defined at the major/minor boundary.
func RequireMinVersion(version string, major, minor int) error {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("parse sing-box version %q: need major.minor", version)
	}
	actualMajor, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("parse sing-box version %q: major: %w", version, err)
	}
	actualMinor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("parse sing-box version %q: minor: %w", version, err)
	}
	if actualMajor < major || actualMajor == major && actualMinor < minor {
		return fmt.Errorf("sing-box %s is too old: need %d.%d or newer", version, major, minor)
	}
	return nil
}

// Reload asks launchd to deliver SIGHUP to the system sing-box service.
func Reload(ctx context.Context, runner sysexec.Runner) error {
	return sysexec.Kill(ctx, runner, "SIGHUP", sysexec.SystemTarget())
}

func commandError(operation string, output []byte, err error) error {
	detail := strings.TrimSpace(string(output))
	if detail == "" || strings.Contains(err.Error(), detail) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w: %s", operation, err, detail)
}
