//go:build darwin

package netwatch

import (
	"net/netip"
	"os"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routeSource reads the AF_ROUTE socket, which needs no cgo and no
// SystemConfiguration framework.
type routeSource struct {
	file   *os.File
	events chan struct{}
}

// Open starts reading the routing socket. The socket is non-blocking and
// wrapped in an os.File, so reads go through the runtime poller and Close
// interrupts a pending read.
func Open() (Source, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	source := &routeSource{file: os.NewFile(uintptr(fd), "routing socket"), events: make(chan struct{}, 1)}
	go source.read()
	return source, nil
}

func (source *routeSource) Events() <-chan struct{} { return source.events }

func (source *routeSource) Close() error { return source.file.Close() }

func (source *routeSource) read() {
	defer close(source.events)
	buffer := make([]byte, 1<<16)
	for {
		n, err := source.file.Read(buffer)
		if err != nil {
			return
		}
		if containsChange(buffer[:n]) {
			signal(source.events)
		}
	}
}

// containsChange parses routing socket messages and reports whether any of
// them is a network change. Unparseable data counts as a change: a missed
// change costs more than one extra lookup.
func containsChange(data []byte) bool {
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	if err != nil {
		return true
	}
	for _, message := range messages {
		if relevant(classify(message)) {
			return true
		}
	}
	return false
}

func classify(message route.Message) change {
	switch typed := message.(type) {
	case *route.InterfaceAddrMessage:
		return change{kind: kindAddress}
	case *route.InterfaceMessage:
		return change{kind: kindInterface}
	case *route.RouteMessage:
		switch typed.Type {
		case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
			return change{kind: kindRoute, defaultRoute: isDefault(typed)}
		}
	}
	return change{kind: kindOther}
}

// isDefault reports a route to 0.0.0.0/0 or ::/0: an unspecified destination
// whose netmask is absent or zero.
func isDefault(message *route.RouteMessage) bool {
	if len(message.Addrs) <= unix.RTAX_DST {
		return false
	}
	destination := addrOf(message.Addrs[unix.RTAX_DST])
	if !destination.IsValid() || !destination.IsUnspecified() {
		return false
	}
	if len(message.Addrs) > unix.RTAX_NETMASK {
		if mask := addrOf(message.Addrs[unix.RTAX_NETMASK]); mask.IsValid() && !mask.IsUnspecified() {
			return false
		}
	}
	return true
}

func addrOf(addr route.Addr) netip.Addr {
	switch typed := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(typed.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(typed.IP)
	}
	return netip.Addr{}
}
