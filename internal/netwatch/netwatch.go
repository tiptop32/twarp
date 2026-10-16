// Package netwatch turns network-change notifications into calls of a
// callback: a burst of events within the debounce window is one call, and a
// periodic tick covers events the source missed.
package netwatch

import (
	"context"
	"time"
)

// Source delivers one value per notification that may mean the network
// changed (address added or removed, interface state, default route).
type Source interface {
	Events() <-chan struct{}
	Close() error
}

// Clock creates timers; tests replace it.
type Clock interface {
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the wall clock.
var RealClock Clock = realClock{}

// Watch calls fn once per burst of events (debounce after the first event of
// the burst) and every tick without events, until ctx is done. A nil events
// channel means the source is unavailable: only the tick runs.
func Watch(ctx context.Context, events <-chan struct{}, debounce, tick time.Duration, clock Clock, fn func(context.Context)) {
	if clock == nil {
		clock = RealClock
	}
	var burst <-chan time.Time
	ticker := clock.After(tick)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if burst == nil {
				burst = clock.After(debounce)
			}
		case <-burst:
			burst = nil
			fn(ctx)
			ticker = clock.After(tick)
		case <-ticker:
			fn(ctx)
			ticker = clock.After(tick)
		}
	}
}
