package sysexec_test

import (
	"context"
	"errors"
	"testing"

	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestLaunchctlTargets(t *testing.T) {
	if got, want := sysexec.SystemTarget(), "system/dev.twarp.singbox"; got != want {
		t.Errorf("SystemTarget() = %q, want %q", got, want)
	}
	if got, want := sysexec.GUIDomain(501), "gui/501"; got != want {
		t.Errorf("GUIDomain() = %q, want %q", got, want)
	}
	if got, want := sysexec.GUITarget(501), "gui/501/dev.twarp.geo"; got != want {
		t.Errorf("GUITarget() = %q, want %q", got, want)
	}
	if sysexec.Label != "dev.twarp.singbox" || sysexec.GeoLabel != "dev.twarp.geo" {
		t.Errorf("labels = (%q, %q), want (%q, %q)",
			sysexec.Label, sysexec.GeoLabel, "dev.twarp.singbox", "dev.twarp.geo")
	}
}

func TestPrintState(t *testing.T) {
	tests := []struct {
		name   string
		output []byte
		err    error
		want   sysexec.ServiceState
	}{
		{
			name:   "service running",
			output: []byte("dev.twarp.singbox => {\n\tstate = running\n}\n"),
			want:   sysexec.ServiceRunning,
		},
		{
			name:   "service loaded but stopped",
			output: []byte("dev.twarp.singbox => {\n\tstate = not running\n}\n"),
			want:   sysexec.ServiceStopped,
		},
		{
			name: "print says could not find service",
			err:  errors.New("launchctl print system/dev.twarp.singbox: exit status 113: Could not find service \"dev.twarp.singbox\" in domain"),
			want: sysexec.ServiceMissing,
		},
		{
			name:   "print output says could not find specified service",
			output: []byte("Could not find specified service\n"),
			err:    errors.New("exit status 113"),
			want:   sysexec.ServiceMissing,
		},
		{
			name: "unexpected print failure stays unknown",
			err:  errors.New("launchctl print: connect failed: Broken pipe"),
			want: sysexec.ServiceUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sysexec.PrintState(test.output, test.err); got != test.want {
				t.Fatalf("PrintState() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLaunchctlHelpersUseExactArgv(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, sysexec.Runner) error
		args []string
	}{
		{
			name: "bootstrap",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Bootstrap(ctx, runner, "system", "/Library/LaunchDaemons/dev.twarp.singbox.plist")
			},
			args: []string{"bootstrap", "system", "/Library/LaunchDaemons/dev.twarp.singbox.plist"},
		},
		{
			name: "bootout",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Bootout(ctx, runner, sysexec.GUITarget(501))
			},
			args: []string{"bootout", "gui/501/dev.twarp.geo"},
		},
		{
			name: "kill",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Kill(ctx, runner, "SIGHUP", "system/dev.twarp.singbox")
			},
			args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"},
		},
		{
			name: "kickstart",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Kickstart(ctx, runner, "system/dev.twarp.singbox")
			},
			args: []string{"kickstart", "-k", "system/dev.twarp.singbox"},
		},
		{
			name: "disable",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Disable(ctx, runner, "system/dev.twarp.singbox")
			},
			args: []string{"disable", "system/dev.twarp.singbox"},
		},
		{
			name: "enable",
			call: func(ctx context.Context, runner sysexec.Runner) error {
				return sysexec.Enable(ctx, runner, "system/dev.twarp.singbox")
			},
			args: []string{"enable", "system/dev.twarp.singbox"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
				Call: sysexec.Call{Name: "launchctl", Args: test.args},
			}}}
			if err := test.call(context.Background(), fake); err != nil {
				t.Fatalf("helper error = %v", err)
			}
			if err := fake.Verify(); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestBootoutIgnoresMissingService(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		runnerErr error
	}{
		{
			name:      "output says no such process",
			output:    "Boot-out failed: 3: No such process\n",
			runnerErr: errors.New("exit status 3"),
		},
		{
			name:      "error says service not found",
			runnerErr: errors.New("launchctl bootout: exit status 113: Could not find specified service"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
				Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}},
				Response: sysexec.Response{
					Output: []byte(test.output),
					Err:    test.runnerErr,
				},
			}}}
			if err := sysexec.Bootout(context.Background(), fake, sysexec.SystemTarget()); err != nil {
				t.Fatalf("Bootout() error = %v, want nil", err)
			}
			if err := fake.Verify(); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestBootoutReturnsOtherErrors(t *testing.T) {
	wantErr := errors.New("permission denied")
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call:     sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}},
		Response: sysexec.Response{Err: wantErr},
	}}}

	err := sysexec.Bootout(context.Background(), fake, sysexec.SystemTarget())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Bootout() error = %v, want %v", err, wantErr)
	}
}

// On macOS 15 an unloaded service addressed by plist path fails with
// "5: Input/output error"; that is not proof of absence, so it must surface.
func TestBootoutDoesNotHideIOError(t *testing.T) {
	ioErr := errors.New("launchctl bootout gui/501/dev.twarp.geo: exit status 5: Boot-out failed: 5: Input/output error")
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call:     sysexec.Call{Name: "launchctl", Args: []string{"bootout", "gui/501/dev.twarp.geo"}},
		Response: sysexec.Response{Err: ioErr},
	}}}

	if err := sysexec.Bootout(context.Background(), fake, sysexec.GUITarget(501)); !errors.Is(err, ioErr) {
		t.Fatalf("Bootout() error = %v, want %v", err, ioErr)
	}
}
