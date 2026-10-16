//go:build darwin

package netwatch

import (
	"encoding/hex"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// newAddrFixture is an RTM_NEWADDR message as the darwin kernel sends it: a
// 20-byte ifa_msghdr (version 5, type 0x0c, addrs RTA_IFA, index 4) and one
// sockaddr_in for 192.0.2.10.
const newAddrFixture = "2400" + "05" + "0c" + "20000000" + "00000000" + "0400" + "0000" + "00000000" +
	"1002" + "0000" + "c000020a" + "0000000000000000"

func TestContainsChangeParsesNewAddr(t *testing.T) {
	data, err := hex.DecodeString(newAddrFixture)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	if err != nil || len(messages) != 1 {
		t.Fatalf("ParseRIB() = (%v, %v), want one message", messages, err)
	}
	if _, ok := messages[0].(*route.InterfaceAddrMessage); !ok {
		t.Fatalf("message = %T, want *route.InterfaceAddrMessage", messages[0])
	}
	if !containsChange(data) {
		t.Fatal("RTM_NEWADDR is not reported as a change")
	}
}

func TestContainsChangeFiltersRoutes(t *testing.T) {
	marshal := func(message *route.RouteMessage) []byte {
		t.Helper()
		data, err := message.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	defaultRoute := marshal(&route.RouteMessage{
		Version: unix.RTM_VERSION, Type: unix.RTM_ADD, ID: 1, Seq: 1,
		Addrs: []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
			unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},
			unix.RTAX_NETMASK: &route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
		},
	})
	hostRoute := marshal(&route.RouteMessage{
		Version: unix.RTM_VERSION, Type: unix.RTM_ADD, ID: 1, Seq: 2,
		Addrs: []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{IP: [4]byte{198, 51, 100, 7}},
			unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},
		},
	})
	if !containsChange(defaultRoute) {
		t.Fatal("default route change is not reported")
	}
	if containsChange(hostRoute) {
		t.Fatal("host route is reported as a network change")
	}
}
