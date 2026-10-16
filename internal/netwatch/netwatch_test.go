package netwatch

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock hands out timers the test fires by duration.
type fakeClock struct {
	mu      sync.Mutex
	pending map[time.Duration][]chan time.Time
	created chan time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{pending: map[time.Duration][]chan time.Time{}, created: make(chan time.Duration, 64)}
}

func (clock *fakeClock) After(d time.Duration) <-chan time.Time {
	timer := make(chan time.Time, 1)
	clock.mu.Lock()
	clock.pending[d] = append(clock.pending[d], timer)
	clock.mu.Unlock()
	clock.created <- d
	return timer
}

// waitTimer blocks until a timer of d was created.
func (clock *fakeClock) waitTimer(t *testing.T, d time.Duration) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-clock.created:
			if got == d {
				return
			}
		case <-timeout:
			t.Fatalf("no %s timer was created", d)
		}
	}
}

// fire fires the oldest pending timer of d.
func (clock *fakeClock) fire(t *testing.T, d time.Duration) {
	t.Helper()
	clock.mu.Lock()
	defer clock.mu.Unlock()
	timers := clock.pending[d]
	if len(timers) == 0 {
		t.Fatalf("no pending %s timer", d)
	}
	timers[0] <- time.Time{}
	clock.pending[d] = timers[1:]
}

const (
	testDebounce = 2 * time.Second
	testTick     = 30 * time.Second
)

func startWatch(t *testing.T, events chan struct{}) (*fakeClock, chan struct{}, context.CancelFunc, chan struct{}) {
	t.Helper()
	clock := newFakeClock()
	calls := make(chan struct{}, 16)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var source <-chan struct{}
	if events != nil {
		source = events
	}
	go func() {
		defer close(done)
		Watch(ctx, source, testDebounce, testTick, clock, func(context.Context) { calls <- struct{}{} })
	}()
	clock.waitTimer(t, testTick)
	return clock, calls, cancel, done
}

func expectCalls(t *testing.T, calls chan struct{}, want int) {
	t.Helper()
	for i := 0; i < want; i++ {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatalf("got %d calls, want %d", i, want)
		}
	}
	select {
	case <-calls:
		t.Fatalf("got more than %d calls", want)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestWatchDebouncesBursts(t *testing.T) {
	events := make(chan struct{})
	clock, calls, cancel, done := startWatch(t, events)
	defer func() { cancel(); <-done }()

	for range 5 {
		events <- struct{}{}
	}
	clock.waitTimer(t, testDebounce)
	expectCalls(t, calls, 0)
	clock.fire(t, testDebounce)
	expectCalls(t, calls, 1)

	// the next burst gets its own window
	events <- struct{}{}
	clock.waitTimer(t, testDebounce)
	clock.fire(t, testDebounce)
	expectCalls(t, calls, 1)
}

func TestWatchTicksWithoutEvents(t *testing.T) {
	clock, calls, cancel, done := startWatch(t, make(chan struct{}))
	defer func() { cancel(); <-done }()

	clock.fire(t, testTick)
	expectCalls(t, calls, 1)
	clock.waitTimer(t, testTick)
	clock.fire(t, testTick)
	expectCalls(t, calls, 1)
}

func TestWatchWithoutSourceStillTicks(t *testing.T) {
	clock, calls, cancel, done := startWatch(t, nil)
	defer func() { cancel(); <-done }()

	clock.fire(t, testTick)
	expectCalls(t, calls, 1)
}

func TestWatchSurvivesClosedSource(t *testing.T) {
	events := make(chan struct{})
	clock, calls, cancel, done := startWatch(t, events)
	defer func() { cancel(); <-done }()

	close(events)
	clock.fire(t, testTick)
	expectCalls(t, calls, 1)
}

func TestWatchStopsOnCancel(t *testing.T) {
	_, _, cancel, done := startWatch(t, make(chan struct{}))
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after cancel")
	}
}
