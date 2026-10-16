//go:build darwin

package netwatch

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// RoutingSocket is a Source reading the AF_ROUTE socket.
type RoutingSocket struct {
	file   *os.File
	events chan struct{}
	once   sync.Once
}

// OpenRoutingSocket starts reading routing messages.
func OpenRoutingSocket() (*RoutingSocket, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("open routing socket: %w", err)
	}
	socket := &RoutingSocket{file: os.NewFile(uintptr(fd), "route"), events: make(chan struct{}, 1)}
	go socket.read()
	return socket, nil
}

// Events delivers a value per relevant message; extra values coalesce.
func (socket *RoutingSocket) Events() <-chan struct{} { return socket.events }

// Close stops reading and closes Events.
func (socket *RoutingSocket) Close() error {
	var err error
	socket.once.Do(func() { err = socket.file.Close() })
	return err
}

func (socket *RoutingSocket) read() {
	defer close(socket.events)
	buffer := make([]byte, 64<<10)
	for {
		n, err := socket.file.Read(buffer)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				_ = socket.Close()
			}
			return
		}
		if !relevant(buffer[:n]) {
			continue
		}
		select {
		case socket.events <- struct{}{}:
		default:
		}
	}
}

// relevant reports whether a routing socket read may mean a network change:
// interface addresses, interface state, or the default route.
func relevant(data []byte) bool {
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	if err != nil {
		// unknown layout: a spurious check is cheaper than a missed change
		return true
	}
	for _, message := range messages {
		switch typed := message.(type) {
		case *route.InterfaceAddrMessage, *route.InterfaceMessage:
			return true
		case *route.RouteMessage:
			if typed.Type == unix.RTM_ADD || typed.Type == unix.RTM_DELETE || typed.Type == unix.RTM_CHANGE {
				if isDefaultRoute(typed) {
					return true
				}
			}
		}
	}
	return false
}

func isDefaultRoute(message *route.RouteMessage) bool {
	if len(message.Addrs) <= unix.RTAX_DST {
		return false
	}
	switch destination := message.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		return destination.IP == [4]byte{}
	case *route.Inet6Addr:
		return destination.IP == [16]byte{}
	}
	return false
}
