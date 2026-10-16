//go:build linux

package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID asks the kernel for the uid of the connecting process (SO_PEERCRED).
// Linux is not a twarp target; this keeps the authorization tests meaningful
// in Linux CI.
func peerUID(connection net.Conn) (int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return int(credential.Uid), nil
}
