package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tiptop32/twarp/internal/sysexec"
)

const (
	// VPNProxyTag identifies the listener in both generated and installed configs.
	VPNProxyTag = "vpn-proxy-in"
	// VPNProxyListen restricts the VPN-only listener to IPv4 loopback.
	VPNProxyListen = "127.0.0.1"
)

// CheckVPNProxyPort checks that a new listener can bind, or that the installed
// sing-box already owns the requested port. It reports whether it is reused.
func CheckVPNProxyPort(ctx context.Context, runner sysexec.Runner, port uint16, previous []byte) (bool, error) {
	if port == 0 {
		return false, nil
	}
	addr := proxyAddress(port)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", addr)
	if err == nil {
		return false, listener.Close()
	}

	var cfg struct{ Inbounds []Inbound }
	if json.Unmarshal(previous, &cfg) == nil {
		for _, inbound := range cfg.Inbounds {
			if inbound.Tag == VPNProxyTag && inbound.Listen == VPNProxyListen && inbound.ListenPort == port &&
				proxyOwned(ctx, runner, addr) {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("cannot bind vpn_proxy_port %s: %w", addr, err)
}

// WaitVPNProxy waits until the configured listener belongs to the sing-box
// job, rather than accepting any process that happened to bind the port.
func WaitVPNProxy(ctx context.Context, runner sysexec.Runner, port uint16) error {
	if port == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr := proxyAddress(port)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !proxyOwned(ctx, runner, addr) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("sing-box did not start VPN proxy at %s: %w", addr, ctx.Err())
		case <-ticker.C:
		}
	}
	return nil
}

func proxyAddress(port uint16) string {
	return net.JoinHostPort(VPNProxyListen, strconv.Itoa(int(port)))
}

func proxyOwned(ctx context.Context, runner sysexec.Runner, addr string) bool {
	status, err := runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		pid, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = ")
		if !ok {
			continue
		}
		if value, err := strconv.Atoi(pid); err != nil || value <= 1 {
			return false
		}
		output, err := runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-t", "-a", "-p", pid, "-iTCP@"+addr, "-sTCP:LISTEN")
		return err == nil && strings.TrimSpace(string(output)) == pid
	}
	return false
}
