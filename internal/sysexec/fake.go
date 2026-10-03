package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Call records one command invocation.
type Call struct {
	Name string
	Args []string
}

// Response is returned for a matching expected call.
type Response struct {
	Output []byte
	Err    error
}

// ExpectedCall pairs an expected invocation with its prepared response.
type ExpectedCall struct {
	Call
	Response
}

// Fake is a thread-safe Runner that verifies a prepared call sequence.
type Fake struct {
	mu sync.Mutex

	Expect []ExpectedCall
	Calls  []Call

	next       int
	unexpected []Call
}

// Run records the call and returns the next response when the argv matches.
func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	call := Call{Name: name, Args: slices.Clone(args)}
	f.Calls = append(f.Calls, call)
	if f.next >= len(f.Expect) || !equalCall(call, f.Expect[f.next].Call) {
		f.unexpected = append(f.unexpected, call)
		return nil, fmt.Errorf("unexpected call: %s", formatCall(call))
	}

	response := f.Expect[f.next].Response
	f.next++
	return bytes.Clone(response.Output), response.Err
}

// Verify reports unexpected calls and expectations that were not consumed.
func (f *Fake) Verify() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.unexpected) == 0 && f.next == len(f.Expect) {
		return nil
	}

	var report strings.Builder
	report.WriteString("fake verification failed:")
	if len(f.unexpected) > 0 {
		report.WriteString("\nunexpected calls:")
		for _, call := range f.unexpected {
			fmt.Fprintf(&report, "\n+ %s", formatCall(call))
		}
	}
	if f.next < len(f.Expect) {
		report.WriteString("\nremaining expected calls:")
		for _, expected := range f.Expect[f.next:] {
			fmt.Fprintf(&report, "\n- %s", formatCall(expected.Call))
		}
	}
	return errors.New(report.String())
}

func equalCall(left, right Call) bool {
	return left.Name == right.Name && slices.Equal(left.Args, right.Args)
}

func formatCall(call Call) string {
	return strings.Join(append([]string{call.Name}, call.Args...), " ")
}
