//go:build darwin

package netwatch

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func routeMessage(t *testing.T, kind int, destination [4]byte) []byte {
	t.Helper()
	message := route.RouteMessage{
		Version: unix.RTM_VERSION, Type: kind, ID: 1, Seq: 1,
		Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{IP: destination}, unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}}},
	}
	data, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// newAddrMessage is a bare RTM_NEWADDR (struct ifa_msghdr without sockaddrs).
func newAddrMessage() []byte {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(data)))
	data[2] = unix.RTM_VERSION
	data[3] = unix.RTM_NEWADDR
	binary.LittleEndian.PutUint16(data[12:14], 4) // ifam_index
	return data
}

func TestRelevant(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"default route added", routeMessage(t, unix.RTM_ADD, [4]byte{}), true},
		{"default route deleted", routeMessage(t, unix.RTM_DELETE, [4]byte{}), true},
		{"host route added", routeMessage(t, unix.RTM_ADD, [4]byte{192, 0, 2, 42}), false},
		{"default route lookup", routeMessage(t, unix.RTM_GET, [4]byte{}), false},
		{"address added", newAddrMessage(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := relevant(tt.data); got != tt.want {
				t.Fatalf("relevant() = %v, want %v", got, tt.want)
			}
		})
	}
}
