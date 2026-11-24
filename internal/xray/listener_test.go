package xray_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/sysexec"
	"github.com/tiptop32/twarp/internal/xray"
)

func TestCheckPortsRejectsForeignTCPAndUDPListeners(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var port int
			if network == "tcp" {
				socket, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = socket.Close() }()
				port = socket.Addr().(*net.TCPAddr).Port
			} else {
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = socket.Close() }()
				port = socket.LocalAddr().(*net.UDPAddr).Port
			}
			runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{{
				Call:     sysexec.Call{Name: "launchctl", Args: []string{"print", "gui/501/dev.twarp.xray-vpn2"}},
				Response: sysexec.Response{Err: errors.New("Could not find service")},
			}}}
			tunnels := []config.Tunnel{{Name: "vpn2", Xray: &config.XrayPorts{Listen: uint16(port)}}}
			err := xray.CheckPorts(t.Context(), runner, 501, tunnels)
			if err == nil || !strings.Contains(err.Error(), "/"+network+":") {
				t.Fatalf("foreign %s socket was not rejected: %v", network, err)
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
