// Package gwaddr turns gateway.socks into the address sing-box dials. An IP
// literal is used as is; a host name goes through the system resolver, which
// on macOS also answers mDNS (.local) names.
package gwaddr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Timeout bounds one lookup. A missing .local name times out instead of
// failing fast, so callers must not wait for it while holding locks.
const Timeout = 5 * time.Second

// LookupFunc matches net.Resolver.LookupIP.
type LookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// IsLiteral reports whether the host of hostport is an IP address. Only
// host names are resolved, and only they can change with the network.
func IsLiteral(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err == nil
}

// Resolve returns the address for hostport. A host name resolves to its
// first IPv4 address, like dns.strategy prefer_ipv4, else to its first IPv6
// address that is neither link-local nor loopback: mDNS lists fe80:: first,
// and sing-box cannot dial it without an interface zone.
func Resolve(ctx context.Context, lookup LookupFunc, hostport string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse gateway.socks: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("parse gateway.socks: invalid port")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}
	if lookup == nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: resolver is unavailable", host)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	addr, err := choose(ips)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func choose(ips []net.IP) (netip.Addr, error) {
	var v6 netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !usable(addr) {
			continue
		}
		if addr.Is4() {
			return addr, nil
		}
		if !v6.IsValid() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6, nil
	}
	if len(ips) == 0 {
		return netip.Addr{}, errors.New("no addresses returned")
	}
	return netip.Addr{}, errors.New("only loopback, link-local or unspecified addresses returned")
}

func usable(addr netip.Addr) bool {
	return !addr.IsLoopback() && !addr.IsUnspecified() && !addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() && !addr.IsMulticast()
}
