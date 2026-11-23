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
	if reused, err := singbox.CheckVPNProxyPort(t.Context(), reportedJobPID(1), port, previous); err == nil || reused {
		t.Fatalf("foreign listener accepted: reused=%t, err=%v", reused, err)
	}
	owned := reportedJobPID(os.Getpid())
	if reused, err := singbox.CheckVPNProxyPort(t.Context(), owned, port, previous); err != nil || !reused {
		t.Fatalf("installed listener not accepted: reused=%t, err=%v", reused, err)
	}
	if err := singbox.WaitVPNProxy(t.Context(), owned, port); err != nil {
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
