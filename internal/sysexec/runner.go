// Package sysexec provides testable adapters for operating-system commands.
package sysexec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const maxErrorOutput = 4 * 1024

// Runner executes an external command and returns its combined standard output
// and standard error.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner executes commands using os/exec.
type ExecRunner struct{}

// Run executes name with args and returns its combined output. Command errors
// include the command, exit status, and at most 4 KiB of trimmed output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err == nil {
		return output, nil
	}

	command := strings.Join(append([]string{name}, args...), " ")
	detail := strings.TrimSpace(string(output))
	if len(detail) > maxErrorOutput {
		detail = detail[:maxErrorOutput]
	}
	if detail == "" {
		return output, fmt.Errorf("%s: %w", command, err)
	}
	return output, fmt.Errorf("%s: %w: %s", command, err, detail)
}
