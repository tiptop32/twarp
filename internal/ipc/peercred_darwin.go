//go:build darwin

package ipc

import "golang.org/x/sys/unix"

// peerUID reads the uid of the process on the other end of fd from the
// kernel (LOCAL_PEERCRED), not from anything the client sends.
func peerUIDFromFD(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
