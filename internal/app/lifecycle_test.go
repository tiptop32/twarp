package app

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/sysexec"
)

var (
	startRouteOutput = []byte("   route to: 1.1.1.1\ndestination: default\n  interface: en0\n")
	startPrintCall   = sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}
)

type startFileInfo struct{}

func (startFileInfo) Name() string       { return "dev.twarp.singbox.plist" }
func (startFileInfo) Size() int64        { return 100 }
func (startFileInfo) Mode() fs.FileMode  { return 0o600 }
func (startFileInfo) ModTime() time.Time { return time.Time{} }
func (startFileInfo) IsDir() bool        { return false }
func (startFileInfo) Sys() any           { return nil }

type startFakeFS struct{}

func (startFakeFS) MkdirAll(string, fs.FileMode) error { return nil }
func (startFakeFS) Chown(string, int, int) error       { return nil }
func (startFakeFS) WriteFile(string, []byte, fs.FileMode) error {
	return nil
}
func (startFakeFS) WriteFileOwned(string, []byte, fs.FileMode, int, int) error {
	return nil
}
func (startFakeFS) WriteFileCandidate(string, []byte, fs.FileMode) (string, error) {
	return "", nil
}
func (startFakeFS) PromoteFile(string, string) error { return nil }
func (startFakeFS) ReadFile(string) ([]byte, error)  { return nil, os.ErrNotExist }
func (startFakeFS) Remove(string) error              { return nil }
func (startFakeFS) Stat(string) (os.FileInfo, error) { return startFileInfo{}, nil }

func TestStartFailsOnUnexpectedPrintError(t *testing.T) {
	printErr := errors.New("launchctl print: connect failed: Broken pipe")
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: startRouteOutput}},
		{Call: startPrintCall, Response: sysexec.Response{Err: printErr}},
	}}
	service := New(Deps{Runner: runner, FS: startFakeFS{}, Sys: testSys{euid: 0}}, ActorTUI)

	_, err := service.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "inspect sing-box service") {
		t.Fatalf("Start() error = %v, want inspect sing-box service failure", err)
	}
	if !errors.Is(err, printErr) {
		t.Fatalf("Start() error = %v, want it to wrap %v", err, printErr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestStartTreatsKnownAbsenceAsUnload(t *testing.T) {
	for name, printResponse := range map[string]struct {
		response sysexec.Response
		call     sysexec.Call
	}{
		"service absent": {
			response: sysexec.Response{Err: errors.New("launchctl print: exit status 113: Could not find service")},
			call:     sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", "/Library/LaunchDaemons/dev.twarp.singbox.plist"}},
		},
		"service stopped": {
			response: sysexec.Response{Output: []byte("dev.twarp.singbox => {\n\tstate = not running\n}\n")},
			call:     sysexec.Call{Name: "launchctl", Args: []string{"kickstart", "-k", "system/dev.twarp.singbox"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
				{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: startRouteOutput}},
				{Call: startPrintCall, Response: printResponse.response},
				{Call: sysexec.Call{Name: "launchctl", Args: []string{"enable", "system/dev.twarp.singbox"}}},
				{Call: printResponse.call},
			}}
			service := New(Deps{Runner: runner, FS: startFakeFS{}, Sys: testSys{euid: 0}}, ActorTUI)

			summary, err := service.Start(context.Background())
			if err != nil || summary != "started; check: twarp status" {
				t.Fatalf("Start() = (%q, %v), want started summary", summary, err)
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
