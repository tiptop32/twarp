//go:build !darwin && !linux

package ipc

import "errors"

func peerUIDFromFD(int) (int, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
