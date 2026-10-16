//go:build darwin

package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID asks the kernel for the effective uid of the connecting process
// (LOCAL_PEERCRED). It cannot be forged by the client.
func peerUID(connection net.Conn) (int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return int(credential.Uid), nil
}
