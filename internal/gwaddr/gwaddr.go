// Package gwaddr resolves the gateway.socks address to the IPv4 endpoint
// sing-box dials.
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

// ResolveTimeout bounds a name lookup: a missing .local name answers with a
// timeout rather than an error.
const ResolveTimeout = 5 * time.Second

// ErrNoIPv4 is returned when a name resolves without a usable IPv4 address.
var ErrNoIPv4 = errors.New("no IPv4 address")

// LookupFunc matches net.Resolver.LookupIP.
type LookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// Resolve returns the endpoint for hostport. An IP literal is returned as is
// without touching the network. A name resolves through lookup (the system
// resolver, which sees mDNS .local names) to its first IPv4 address: mDNS
// answers a link-local IPv6 address first, which sing-box cannot dial
// without a zone, and the typical gateway (cisco-socks-server) listens on
// IPv4 only.
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
		return netip.AddrPort{}, fmt.Errorf("resolve %s: no resolver", host)
	}
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	addr, err := pickIPv4(ips)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func pickIPv4(ips []net.IP) (netip.Addr, error) {
	rejected := false
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
			rejected = true
			continue
		}
		return addr, nil
	}
	if rejected {
		return netip.Addr{}, fmt.Errorf("%w: only loopback, unspecified or multicast addresses", ErrNoIPv4)
	}
	return netip.Addr{}, ErrNoIPv4
}
