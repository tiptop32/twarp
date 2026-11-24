package xray

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
)

// AgentLabel is the per-tunnel launchd service name.
func AgentLabel(name string) string { return "dev.twarp.xray-" + name }

// CheckPorts rejects unrelated listeners before sing-box commits new routes.
// An unbound port is valid: the owner may not be logged in yet.
func CheckPorts(ctx context.Context, runner sysexec.Runner, uid int, tunnels []config.Tunnel) error {
	for _, tunnel := range tunnels {
		if tunnel.Xray == nil {
			continue
		}
		target := sysexec.GUIDomain(uid) + "/" + AgentLabel(tunnel.Name)
		if err := CheckPort(ctx, runner, target, tunnel.Xray.Listen); err != nil {
			return fmt.Errorf("VPN tunnel %q: %w", tunnel.Name, err)
		}
	}
	return nil
}

// CheckPort accepts a free loopback port or one already owned by this job.
func CheckPort(ctx context.Context, runner sysexec.Runner, target string, port uint16) error {
	address := net.JoinHostPort(singbox.VPNProxyListen, strconv.Itoa(int(port)))
	network := net.ListenConfig{}
	if tcp, err := network.Listen(ctx, "tcp4", address); err == nil {
		if err := tcp.Close(); err != nil {
			return err
		}
	} else if !sysexec.OwnsTCPListener(ctx, runner, target, address) {
		return fmt.Errorf("cannot bind Xray listen_port %s/tcp: %w", address, err)
	}
	if udp, err := network.ListenPacket(ctx, "udp4", address); err == nil {
		return udp.Close()
	} else if !sysexec.OwnsUDPListener(ctx, runner, target, address) {
		return fmt.Errorf("cannot bind Xray listen_port %s/udp: %w", address, err)
	}
	return nil
}
