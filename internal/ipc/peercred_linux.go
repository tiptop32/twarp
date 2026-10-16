//go:build linux

package ipc

import "golang.org/x/sys/unix"

// peerUIDFromFD reads the peer uid from the kernel (SO_PEERCRED). twarp runs
// on macOS; Linux support keeps the socket tests running in CI containers.
func peerUIDFromFD(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
