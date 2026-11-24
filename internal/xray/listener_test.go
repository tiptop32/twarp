package xray_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

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

func TestWaitReadyRejectsTCPOnlyJob(t *testing.T) {
	const target = "gui/501/dev.twarp.xray-vpn2"
	const pid = "1234"
	printJob := sysexec.ExpectedCall{
		Call:     sysexec.Call{Name: "launchctl", Args: []string{"print", target}},
		Response: sysexec.Response{Output: []byte("pid = " + pid + "\n")},
	}
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		printJob,
		{Call: sysexec.Call{Name: "/usr/sbin/lsof", Args: []string{"-nP", "-t", "-a", "-p", pid, "-iTCP@127.0.0.1:19080", "-sTCP:LISTEN"}}, Response: sysexec.Response{Output: []byte(pid)}},
		printJob,
		{Call: sysexec.Call{Name: "/usr/sbin/lsof", Args: []string{"-nP", "-t", "-a", "-p", pid, "-iUDP@127.0.0.1:19080"}}, Response: sysexec.Response{Err: errors.New("no UDP socket")}},
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := xray.WaitReady(ctx, runner, target, 19080); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TCP-only job reported ready: %v", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}
