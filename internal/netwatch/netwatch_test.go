package netwatch

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock hands out timer channels that the test fires by duration.
type fakeClock struct {
	mu      sync.Mutex
	pending map[time.Duration][]chan time.Time
	armed   chan time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{pending: map[time.Duration][]chan time.Time{}, armed: make(chan time.Duration, 64)}
}

func (clock *fakeClock) after(d time.Duration) <-chan time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	channel := make(chan time.Time, 1)
	clock.pending[d] = append(clock.pending[d], channel)
	clock.armed <- d
	return channel
}

// fire fires every pending timer of duration d.
func (clock *fakeClock) fire(d time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	for _, channel := range clock.pending[d] {
		channel <- time.Time{}
	}
	clock.pending[d] = nil
}

// waitArmed waits until Watch has asked for a timer of duration d.
func (clock *fakeClock) waitArmed(t *testing.T, d time.Duration) {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case got := <-clock.armed:
			if got == d {
				return
			}
		case <-timeout:
			t.Fatalf("Watch never armed a %s timer", d)
		}
	}
}

const (
	debounce = 2 * time.Second
	tick     = 30 * time.Second
)

func startWatch(t *testing.T, events chan struct{}, clock *fakeClock) (<-chan string, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	calls := make(chan string, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, events, debounce, tick, clock.after, func(reason string) { calls <- reason })
	}()
	clock.waitArmed(t, tick)
	return calls, cancel, done
}

func TestWatchMergesBurstIntoOneCall(t *testing.T) {
	clock := newFakeClock()
	events := make(chan struct{})
	calls, cancel, done := startWatch(t, events, clock)
	defer func() { cancel(); <-done }()

	for range 5 {
		events <- struct{}{}
	}
	clock.waitArmed(t, debounce)
	clock.fire(debounce)
	if reason := <-calls; reason != ReasonNetwork {
		t.Fatalf("reason = %q, want network", reason)
	}
	select {
	case reason := <-calls:
		t.Fatalf("extra call %q after one burst", reason)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestWatchTicksWithoutEvents(t *testing.T) {
	clock := newFakeClock()
	calls, cancel, done := startWatch(t, make(chan struct{}), clock)
	defer func() { cancel(); <-done }()

	clock.fire(tick)
	if reason := <-calls; reason != ReasonTick {
		t.Fatalf("reason = %q, want tick", reason)
	}
	clock.waitArmed(t, tick)
}

func TestWatchStopsOnCancelAndClosedSource(t *testing.T) {
	clock := newFakeClock()
	_, cancel, done := startWatch(t, make(chan struct{}), clock)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after cancel")
	}

	events := make(chan struct{})
	_, cancel, done = startWatch(t, events, newFakeClock())
	defer cancel()
	close(events)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after the source closed")
	}
}

func TestRelevant(t *testing.T) {
	for message, want := range map[change]bool{
		{kind: kindAddress}:                   true,
		{kind: kindInterface}:                 true,
		{kind: kindRoute, defaultRoute: true}: true,
		{kind: kindRoute}:                     false,
		{kind: kindOther}:                     false,
	} {
		if got := relevant(message); got != want {
			t.Errorf("relevant(%+v) = %t, want %t", message, got, want)
		}
	}
}

func TestSignalNeverBlocks(t *testing.T) {
	events := make(chan struct{}, 1)
	signal(events)
	signal(events)
	if len(events) != 1 {
		t.Fatalf("pending events = %d, want 1", len(events))
	}
}
