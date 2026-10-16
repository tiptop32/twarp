// Package netwatch reports network changes: an address appears or goes away,
// an interface changes state, or the default route moves. Events in a burst
// are merged, and a periodic tick covers changes the source missed.
package netwatch

import (
	"context"
	"time"
)

// Reasons passed to the Watch callback.
const (
	ReasonNetwork = "network"
	ReasonTick    = "tick"
)

// Source delivers one value per network change it sees.
type Source interface {
	Events() <-chan struct{}
	Close() error
}

// After returns a channel that receives once d has passed, like time.After.
// Tests replace it to drive the clock by hand.
type After func(d time.Duration) <-chan time.Time

// Watch calls fn once per burst of events: the first event opens a window of
// debounce, and the events inside it are merged into one call. fn also runs
// when tick passes without a call. Watch returns when ctx is done or the
// source closes its channel; fn runs on the caller's goroutine, so calls never
// overlap.
func Watch(ctx context.Context, events <-chan struct{}, debounce, tick time.Duration, after After, fn func(reason string)) {
	if after == nil {
		after = time.After
	}
	ticker := after(tick)
	var window <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				return
			}
			if window == nil {
				window = after(debounce)
			}
		case <-window:
			window = nil
			fn(ReasonNetwork)
			ticker = after(tick)
		case <-ticker:
			fn(ReasonTick)
			ticker = after(tick)
		}
	}
}

// change is a routing socket message reduced to what matters here.
type change struct {
	kind         changeKind
	defaultRoute bool
}

type changeKind int

const (
	kindOther changeKind = iota
	kindAddress
	kindInterface
	kindRoute
)

// relevant reports whether a routing message is a network change: address
// and interface messages always are, route messages only for the default
// route. Other route traffic, such as per-destination cloning, is constant.
func relevant(message change) bool {
	switch message.kind {
	case kindAddress, kindInterface:
		return true
	case kindRoute:
		return message.defaultRoute
	default:
		return false
	}
}

// signal sends a non-blocking event: one pending event is enough, because
// Watch merges a burst into one call anyway.
func signal(events chan struct{}) {
	select {
	case events <- struct{}{}:
	default:
	}
}
