package sysexec_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestExecRunnerReturnsCombinedOutput(t *testing.T) {
	runner := sysexec.ExecRunner{}

	output, err := runner.Run(context.Background(), "/bin/echo", "hello", "twarp")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := string(output), "hello twarp\n"; got != want {
		t.Fatalf("Run() output = %q, want %q", got, want)
	}
}

func TestExecRunnerReportsCommandAndExitStatus(t *testing.T) {
	runner := sysexec.ExecRunner{}

	_, err := runner.Run(context.Background(), "/usr/bin/false", "example")
	if err == nil {
		t.Fatal("Run() error = nil, want command failure")
	}
	for _, want := range []string{"/usr/bin/false example", "exit status"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Run() error = %q, want it to contain %q", err, want)
		}
	}
}

func TestExecRunnerLimitsErrorOutput(t *testing.T) {
	runner := sysexec.ExecRunner{}

	_, err := runner.Run(context.Background(), "/bin/sh", "-c", "printf '%05000d' 0; exit 9")
	if err == nil {
		t.Fatal("Run() error = nil, want command failure")
	}
	const marker = "exit status 9: "
	markerAt := strings.LastIndex(err.Error(), marker)
	if markerAt < 0 {
		t.Fatalf("Run() error = %q, want marker %q", err, marker)
	}
	detail := err.Error()[markerAt+len(marker):]
	if len(detail) != 4*1024 {
		t.Fatalf("Run() error output length = %d, want %d", len(detail), 4*1024)
	}
	if strings.Trim(detail, "0") != "" {
		t.Fatalf("Run() error output contains unexpected bytes")
	}
}

func TestFakeRunsExpectedCallsInOrder(t *testing.T) {
	wantErr := errors.New("second failed")
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{
			Call:     sysexec.Call{Name: "first", Args: []string{"one"}},
			Response: sysexec.Response{Output: []byte("first output")},
		},
		{
			Call:     sysexec.Call{Name: "second", Args: []string{"two", "three"}},
			Response: sysexec.Response{Output: []byte("second output"), Err: wantErr},
		},
	}}

	output, err := fake.Run(context.Background(), "first", "one")
	if err != nil || string(output) != "first output" {
		t.Fatalf("first Run() = (%q, %v), want (%q, nil)", output, err, "first output")
	}
	output, err = fake.Run(context.Background(), "second", "two", "three")
	if !errors.Is(err, wantErr) || string(output) != "second output" {
		t.Fatalf("second Run() = (%q, %v), want (%q, %v)", output, err, "second output", wantErr)
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	wantCalls := []sysexec.Call{
		{Name: "first", Args: []string{"one"}},
		{Name: "second", Args: []string{"two", "three"}},
	}
	if !reflect.DeepEqual(fake.Calls, wantCalls) {
		t.Fatalf("Calls = %#v, want %#v", fake.Calls, wantCalls)
	}
}

func TestFakeRejectsExtraCall(t *testing.T) {
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{Name: "only", Args: []string{"once"}},
	}}}
	if _, err := fake.Run(context.Background(), "only", "once"); err != nil {
		t.Fatalf("expected Run() error = %v", err)
	}

	_, err := fake.Run(context.Background(), "extra", "call")
	if err == nil || !strings.Contains(err.Error(), "unexpected call: extra call") {
		t.Fatalf("extra Run() error = %v, want unexpected call", err)
	}
	if err := fake.Verify(); err == nil || !strings.Contains(err.Error(), "+ extra call") {
		t.Fatalf("Verify() error = %v, want extra call diff", err)
	}
}

func TestFakeReportsMissingCall(t *testing.T) {
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{Name: "missing", Args: []string{"call"}},
	}}}

	if err := fake.Verify(); err == nil || !strings.Contains(err.Error(), "- missing call") {
		t.Fatalf("Verify() error = %v, want missing call diff", err)
	}
}

func TestFakeRejectsWrongArguments(t *testing.T) {
	fake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
		Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", "want.plist"}},
	}}}

	_, err := fake.Run(context.Background(), "launchctl", "bootstrap", "system", "got.plist")
	if err == nil || !strings.Contains(err.Error(), "unexpected call: launchctl bootstrap system got.plist") {
		t.Fatalf("Run() error = %v, want wrong-arguments failure", err)
	}
	verifyErr := fake.Verify()
	if verifyErr == nil ||
		!strings.Contains(verifyErr.Error(), "+ launchctl bootstrap system got.plist") ||
		!strings.Contains(verifyErr.Error(), "- launchctl bootstrap system want.plist") {
		t.Fatalf("Verify() error = %v, want actual and expected call diff", verifyErr)
	}
}

func TestFakeSupportsConcurrentCalls(t *testing.T) {
	const callCount = 64
	fake := &sysexec.Fake{Expect: make([]sysexec.ExpectedCall, callCount)}
	for index := range fake.Expect {
		fake.Expect[index].Call = sysexec.Call{Name: "same", Args: []string{"argv"}}
	}

	errorsSeen := make(chan error, callCount)
	var wait sync.WaitGroup
	for range callCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := fake.Run(context.Background(), "same", "argv")
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Errorf("Run() error = %v", err)
		}
	}
	if err := fake.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(fake.Calls) != callCount {
		t.Fatalf("len(Calls) = %d, want %d", len(fake.Calls), callCount)
	}
}
