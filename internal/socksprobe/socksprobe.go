// Package socksprobe checks a SOCKS5 server without proxying traffic: the
// method negotiation, optional username/password auth (RFC 1929) and, on
// request, one CONNECT.
package socksprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// Probe errors.
var (
	ErrNotSOCKS5     = errors.New("not a SOCKS5 server")
	ErrNoMethod      = errors.New("no acceptable SOCKS5 auth method")
	ErrAuthRejected  = errors.New("SOCKS auth rejected")
	ErrUpstreamDown  = errors.New("upstream network unreachable")
	ErrConnectFailed = errors.New("SOCKS CONNECT failed")
)

const (
	version5      = 0x05
	methodNoAuth  = 0x00
	methodUser    = 0x02
	methodNone    = 0xff
	userAuthVer   = 0x01
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypFQDN      = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repNetUnreach = 0x03
)

// Credentials are SOCKS5 username/password credentials.
type Credentials struct {
	User     string
	Password string
}

// Handshake negotiates the auth method on conn and authenticates when the
// server asks for username/password. Offering credentials also offers
// no-auth, so a server without auth still passes. ctx bounds the exchange
// through a connection deadline.
func Handshake(ctx context.Context, conn net.Conn, creds *Credentials) error {
	defer setDeadline(ctx, conn)()
	greeting := []byte{version5, 1, methodNoAuth}
	if creds != nil {
		greeting = []byte{version5, 2, methodNoAuth, methodUser}
	}
	// a peer that accepts and closes fails on the write (pipe) or the read
	// (TCP); either way it never answered as SOCKS5
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("%w: %w", ErrNotSOCKS5, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("%w: %w", ErrNotSOCKS5, err)
	}
	if reply[0] != version5 {
		return ErrNotSOCKS5
	}
	switch reply[1] {
	case methodNoAuth:
		return nil
	case methodUser:
		if creds == nil {
			return fmt.Errorf("%w: the server requires a username and password", ErrNoMethod)
		}
		return authenticate(conn, *creds)
	case methodNone:
		if creds == nil {
			// what an auth-only server answers to a no-auth greeting
			return fmt.Errorf("%w: the server probably requires a username and password", ErrNoMethod)
		}
		return ErrNoMethod
	default:
		return fmt.Errorf("%w: unexpected method %#x", ErrNotSOCKS5, reply[1])
	}
}

func authenticate(conn net.Conn, creds Credentials) error {
	if len(creds.User) == 0 || len(creds.User) > 255 || len(creds.Password) == 0 || len(creds.Password) > 255 {
		return errors.New("SOCKS username and password must be 1 to 255 bytes")
	}
	request := make([]byte, 0, 3+len(creds.User)+len(creds.Password))
	request = append(request, userAuthVer, byte(len(creds.User)))
	request = append(request, creds.User...)
	request = append(request, byte(len(creds.Password)))
	request = append(request, creds.Password...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("send credentials: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if reply[1] != repSuccess {
		return ErrAuthRejected
	}
	return nil
}

// Connect sends one CONNECT to target on a negotiated conn. A "network
// unreachable" reply is ErrUpstreamDown: the server is up, but its upstream
// (for a VPN gateway, the tunnel) is not.
func Connect(ctx context.Context, conn net.Conn, target netip.AddrPort) error {
	defer setDeadline(ctx, conn)()
	addr := target.Addr().Unmap()
	request := []byte{version5, cmdConnect, 0}
	if addr.Is4() {
		request = append(request, atypIPv4)
	} else {
		request = append(request, atypIPv6)
	}
	request = append(request, addr.AsSlice()...)
	request = append(request, byte(target.Port()>>8), byte(target.Port()))
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("send connect: %w", err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if header[0] != version5 {
		return ErrNotSOCKS5
	}
	switch header[1] {
	case repSuccess:
	case repNetUnreach:
		return ErrUpstreamDown
	default:
		return fmt.Errorf("%w: %s", ErrConnectFailed, replyText(header[1]))
	}
	return skipBoundAddr(conn, header[3])
}

func skipBoundAddr(conn net.Conn, atyp byte) error {
	var size int
	switch atyp {
	case atypIPv4:
		size = 4
	case atypIPv6:
		size = 16
	case atypFQDN:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("read bound address: %w", err)
		}
		size = int(length[0])
	default:
		return fmt.Errorf("%w: unexpected address type %#x", ErrNotSOCKS5, atyp)
	}
	if _, err := io.ReadFull(conn, make([]byte, size+2)); err != nil {
		return fmt.Errorf("read bound address: %w", err)
	}
	return nil
}

func replyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "not allowed by ruleset"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("reply %#x", code)
	}
}

// setDeadline applies ctx's deadline to conn and returns the reset.
func setDeadline(ctx context.Context, conn net.Conn) func() {
	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}
	_ = conn.SetDeadline(deadline)
	return func() { _ = conn.SetDeadline(time.Time{}) }
}
