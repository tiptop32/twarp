package socksprobe

import (
	"io"
	"net"
)

// FakeServer is a minimal SOCKS5 server for tests: it answers the method
// negotiation, checks credentials when Creds is set and replies to one
// CONNECT with ConnectReply (0 is success).
type FakeServer struct {
	Creds        *Credentials
	ConnectReply byte
}

// Dial returns the client end of a pipe served by f.
func (f FakeServer) Dial() net.Conn {
	server, client := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		f.Serve(server)
	}()
	return client
}

// Serve handles one client on conn.
func (f FakeServer) Serve(conn net.Conn) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != version5 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	want := byte(methodNoAuth)
	if f.Creds != nil {
		want = methodUser
	}
	offered := false
	for _, method := range methods {
		offered = offered || method == want
	}
	if !offered {
		_, _ = conn.Write([]byte{version5, methodNone})
		return
	}
	if _, err := conn.Write([]byte{version5, want}); err != nil {
		return
	}
	if f.Creds != nil && !f.checkCredentials(conn) {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	size := 4
	if request[3] == atypIPv6 {
		size = 16
	}
	if _, err := io.ReadFull(conn, make([]byte, size+2)); err != nil {
		return
	}
	_, _ = conn.Write([]byte{version5, f.ConnectReply, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func (f FakeServer) checkCredentials(conn net.Conn) bool {
	read := func() string {
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return ""
		}
		value := make([]byte, length[0])
		if _, err := io.ReadFull(conn, value); err != nil {
			return ""
		}
		return string(value)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return false
	}
	user, password := read(), read()
	ok := user == f.Creds.User && password == f.Creds.Password
	status := byte(1)
	if ok {
		status = 0
	}
	_, _ = conn.Write([]byte{userAuthVer, status})
	return ok
}
