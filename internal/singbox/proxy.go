package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/tiptop32/twarp/internal/sysexec"
)

const (
	// VPNProxyTag identifies the listener in both generated and installed configs.
	VPNProxyTag = "vpn-proxy-in"
	// VPNProxyListen restricts the VPN-only listener to IPv4 loopback.
	VPNProxyListen = "127.0.0.1"
)

// LoopbackListener is a TCP port owned by a launchd job.
type LoopbackListener struct {
	Port  uint16
	Tag   string
	Field string
}

// CheckLoopbackPorts verifies each bind before deployment. It returns the
// listeners we must verify again after reload because they are not yet live.
func CheckLoopbackPorts(ctx context.Context, runner sysexec.Runner, listeners []LoopbackListener, previous []byte) ([]LoopbackListener, error) {
	var newListeners []LoopbackListener
	var installed struct{ Inbounds []Inbound }
	var decoded bool
	for _, spec := range listeners {
		addr := proxyAddress(spec.Port)
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", addr)
		if err == nil {
			if err := listener.Close(); err != nil {
				return nil, err
			}
			newListeners = append(newListeners, spec)
			continue
		}
		if !decoded {
			if json.Unmarshal(previous, &installed) != nil {
				installed.Inbounds = nil
			}
			decoded = true
		}
		if !reusesLoopbackPort(ctx, runner, addr, spec, installed.Inbounds) {
			return nil, fmt.Errorf("cannot bind %s %s: %w", spec.Field, addr, err)
		}
	}
	return newListeners, nil
}

func reusesLoopbackPort(ctx context.Context, runner sysexec.Runner, addr string, spec LoopbackListener, previous []Inbound) bool {
	for _, inbound := range previous {
		if inbound.Tag == spec.Tag && inbound.Listen == VPNProxyListen && inbound.ListenPort == spec.Port {
			return sysexec.OwnsTCPListener(ctx, runner, sysexec.SystemTarget(), addr)
		}
	}
	return false
}

// WaitLoopbackPorts verifies that the expected launchd job owns each listener.
func WaitLoopbackPorts(ctx context.Context, runner sysexec.Runner, target string, listeners []LoopbackListener) error {
	if len(listeners) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for _, spec := range listeners {
		addr := proxyAddress(spec.Port)
		for !sysexec.OwnsTCPListener(ctx, runner, target, addr) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s did not start %s at %s: %w", target, spec.Field, addr, ctx.Err())
			case <-ticker.C:
			}
		}
	}
	return nil
}

func proxyAddress(port uint16) string {
	return net.JoinHostPort(VPNProxyListen, strconv.Itoa(int(port)))
}
