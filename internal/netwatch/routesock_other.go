//go:build !darwin

package netwatch

import "errors"

// RoutingSocket is only available on macOS.
type RoutingSocket struct{}

// OpenRoutingSocket fails outside macOS; callers fall back to the tick.
func OpenRoutingSocket() (*RoutingSocket, error) {
	return nil, errors.New("routing socket notifications are only supported on macOS")
}

// Events is never ready.
func (*RoutingSocket) Events() <-chan struct{} { return nil }

// Close does nothing.
func (*RoutingSocket) Close() error { return nil }
