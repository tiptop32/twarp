//go:build integration && darwin

package singbox_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestVPNProxyPortAcceptsOnlyExpectedOwner(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	previous := fmt.Appendf(nil, `{"inbounds":[{"tag":"vpn-proxy-in","listen":"127.0.0.1","listen_port":%d}]}`, port)
	ports := []singbox.LoopbackListener{{Port: port, Tag: singbox.VPNProxyTag, Field: "vpn_proxy_port"}}
	if _, err := singbox.CheckLoopbackPorts(t.Context(), reportedJobPID(1), ports, previous); err == nil {
		t.Fatal("foreign listener accepted")
	}
	owned := reportedJobPID(os.Getpid())
	if pending, err := singbox.CheckLoopbackPorts(t.Context(), owned, ports, previous); err != nil || len(pending) != 0 {
		t.Fatalf("installed listener not reused: pending=%v, err=%v", pending, err)
	}
	if err := singbox.WaitLoopbackPorts(t.Context(), owned, sysexec.SystemTarget(), ports); err != nil {
		t.Fatalf("installed listener not ready: %v", err)
	}
}

// Use the real socket plus lsof; only the system launchd PID lookup is stubbed.
type reportedJobPID int

func (pid reportedJobPID) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "launchctl" && len(args) == 2 && args[0] == "print" && args[1] == sysexec.SystemTarget() {
		return fmt.Appendf(nil, "state = running\n\tpid = %d\n", pid), nil
	}
	return (sysexec.ExecRunner{}).Run(ctx, name, args...)
}
