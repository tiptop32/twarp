//go:build !darwin && !linux

package ipc

import (
	"errors"
	"net"
)

// peerUID is unsupported here: without kernel credentials every caller is
// refused.
func peerUID(net.Conn) (int, error) {
	return 0, errors.New("peer credentials are not supported on this system")
}
