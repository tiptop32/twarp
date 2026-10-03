package singbox_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestCheckUsesExactArgv(t *testing.T) {
	t.Parallel()

	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{
			Name: "/opt/homebrew/bin/sing-box",
			Args: []string{"check", "-c", "/etc/twarp/config.json"},
		},
	}}}

	if err := singbox.Check(
		context.Background(), fake, "/opt/homebrew/bin/sing-box", "/etc/twarp/config.json",
	); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestCheckReportsCommandOutput(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("exit status 1")
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{Name: "sing-box", Args: []string{"check", "-c", "broken.json"}},
		Response: sysexec.Response{
			Output: []byte("FATAL parse config: invalid character\n"),
			Err:    wantErr,
		},
	}}}

	err := singbox.Check(context.Background(), fake, "sing-box", "broken.json")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Check() error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "FATAL parse config: invalid character") {
		t.Fatalf("Check() error = %q, want command output", err)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVersionUsesExactArgvAndRequiresMinimum(t *testing.T) {
	t.Parallel()

	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{Name: "/custom/sing-box", Args: []string{"version"}},
		Response: sysexec.Response{
			Output: []byte("sing-box version 1.14.2\n\nEnvironment: go1.27 darwin/arm64\n"),
		},
	}}}

	got, err := singbox.Version(context.Background(), fake, "/custom/sing-box")
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if got != "1.14.2" {
		t.Fatalf("Version() = %q, want %q", got, "1.14.2")
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestRequireMinVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		major   int
		minor   int
		wantErr string
	}{
		{name: "minimum", version: "1.14.0", major: 1, minor: 14},
		{name: "minimum beta", version: "1.14.0-beta.3", major: 1, minor: 14},
		{name: "newer release candidate", version: "1.15.0-rc.1", major: 1, minor: 14},
		{name: "new major", version: "2.0.0", major: 1, minor: 14},
		{
			name: "too old", version: "1.13.1", major: 1, minor: 14,
			wantErr: "sing-box 1.13.1 is too old: need 1.14 or newer",
		},
		{name: "malformed", version: "development", major: 1, minor: 14, wantErr: "parse sing-box version"},
		{name: "missing minor", version: "1", major: 1, minor: 14, wantErr: "parse sing-box version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := singbox.RequireMinVersion(test.version, test.major, test.minor)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("RequireMinVersion(%q, %d, %d) error = %v", test.version, test.major, test.minor, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"RequireMinVersion(%q, %d, %d) error = %v, want error containing %q",
					test.version, test.major, test.minor, err, test.wantErr,
				)
			}
		})
	}
}

func TestVersionRejectsOldSingBox(t *testing.T) {
	t.Parallel()

	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call:     sysexec.Call{Name: "sing-box", Args: []string{"version"}},
		Response: sysexec.Response{Output: []byte("sing-box version 1.13.1\n")},
	}}}

	_, err := singbox.Version(context.Background(), fake, "sing-box")
	if err == nil || err.Error() != "sing-box 1.13.1 is too old: need 1.14 or newer" {
		t.Fatalf("Version() error = %v", err)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVersionReportsUnexpectedOutput(t *testing.T) {
	t.Parallel()

	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call:     sysexec.Call{Name: "sing-box", Args: []string{"version"}},
		Response: sysexec.Response{Output: []byte("not sing-box\n")},
	}}}

	_, err := singbox.Version(context.Background(), fake, "sing-box")
	if err == nil || !strings.Contains(err.Error(), "unexpected sing-box version output") {
		t.Fatalf("Version() error = %v, want unexpected output", err)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestReloadUsesExactLaunchctlArgv(t *testing.T) {
	t.Parallel()

	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{
			Name: "launchctl",
			Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"},
		},
	}}}

	if err := singbox.Reload(context.Background(), fake); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}
