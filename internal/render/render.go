// Package render builds and atomically writes sing-box configuration files.
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/uri"
	"github.com/tiptop32/twarp/internal/xray"
)

const (
	// InboundTUN selects the production TUN inbound.
	InboundTUN = "tun"
	// InboundMixed selects the local mixed inbound used by tests and diagnostics.
	InboundMixed = "mixed"
)

// TUNDNS is the peer address of the TUN subnet. Port 53 traffic routed into
// the TUN is hijacked by sing-box, so this address works as a system DNS
// server for gateway domains.
const TUNDNS = "172.19.0.2"

var directSuffixes = []string{"ru", "su", "xn--p1ai"}

// DirectSuffixes returns the ASCII domain suffixes routed direct.
func DirectSuffixes() []string { return append([]string(nil), directSuffixes...) }

// Options controls filesystem paths and testable sing-box endpoints.
type Options struct {
	Paths     config.Paths
	Inbound   string
	MixedPort uint16
	Outbounds map[string]singbox.Outbound
	// GatewaySocks is the resolved gateway.socks endpoint (see gwaddr). When
	// unset, gateway.socks must be an IP literal.
	GatewaySocks netip.AddrPort
}

// Render returns a complete sing-box configuration as indented JSON.
func Render(cfg config.Config, secrets config.Secrets, prefixes []netip.Prefix, opts Options) ([]byte, error) {
	if _, err := RenderRuleSet(prefixes); err != nil {
		return nil, err
	}
	ruleSets, err := routeRuleSets(opts.Paths, cfg.VPN.ForceProviderDomains)
	if err != nil {
		return nil, err
	}
	inbound, err := renderInbound(opts)
	if err != nil {
		return nil, err
	}
	socks, err := gatewayEndpoint(cfg, opts.GatewaySocks)
	if err != nil {
		return nil, err
	}
	host, port, socksPrefix := socks.Addr().String(), socks.Port(), hostPrefix(socks.Addr())
	vpn, err := uri.Parse(secrets.VPNURI)
	if err != nil {
		return nil, fmt.Errorf("parse VPN URI: %w", err)
	}
	if vpn.Network == "xhttp" {
		return nil, errors.New("primary VPN does not support XHTTP; use a named tunnel with xray configured")
	}
	// Keep the historical default HTTPS port for the primary resolver.
	dns, err := vpnDNS(cfg.VPN.DNS, "remote", "vpn", false)
	if err != nil {
		return nil, err
	}

	outbounds := []singbox.Outbound{
		{Type: "direct", Tag: "direct"},
		{
			Type: "socks", Tag: "gateway", Server: host, ServerPort: port, Version: "5",
			Username: secrets.GatewaySocksUser, Password: secrets.GatewaySocksPassword,
		},
		vpn,
	}
	servers := make([]singbox.DNSServer, 0, 4+len(cfg.VPN.Tunnels))
	servers = append(servers,
		singbox.DNSServer{Type: "tcp", Tag: "gateway", Server: cfg.Gateway.DNS, Detour: "gateway"},
		singbox.DNSServer{Type: "udp", Tag: "direct", Server: cfg.Direct.DNS},
		singbox.DNSServer{Type: "local", Tag: "local"}, dns,
	)
	inbounds := []singbox.Inbound{inbound}
	for _, tunnel := range cfg.VPN.Tunnels {
		raw := secrets.VPNURIs[tunnel.Name]
		if raw == "" {
			return nil, fmt.Errorf("VPN tunnel %q: import a VPN URI first", tunnel.Name)
		}
		outbound, err := uri.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("VPN tunnel %q: invalid VPN URI", tunnel.Name)
		}
		if outbound.Network == "xhttp" && tunnel.Xray == nil {
			return nil, fmt.Errorf("VPN tunnel %q: XHTTP requires xray configured", tunnel.Name)
		}
		outbound.Tag = tunnel.Tag()
		if tunnel.Xray != nil {
			if secrets.ClashSecret == "" {
				return nil, fmt.Errorf("VPN tunnel %q: generate local credentials with twarp import", tunnel.Name)
			}
			ports := *tunnel.Xray
			if (socks.Addr().Unmap().String() == singbox.VPNProxyListen && (socks.Port() == ports.Listen || socks.Port() == ports.Bridge)) ||
				(opts.Inbound == InboundMixed && (opts.MixedPort == ports.Listen || opts.MixedPort == ports.Bridge)) {
				return nil, fmt.Errorf("VPN tunnel %q: Xray ports conflict with an existing endpoint", tunnel.Name)
			}
			if addr, err := netip.ParseAddr(outbound.Server); err == nil && addr.Unmap().IsLoopback() &&
				(outbound.ServerPort == ports.Listen || outbound.ServerPort == ports.Bridge) {
				return nil, fmt.Errorf("VPN tunnel %q: Xray ports conflict with its upstream endpoint", tunnel.Name)
			}
			inbounds = append(inbounds, singbox.Inbound{
				Type: "direct", Tag: xray.BridgeTag(tunnel), Listen: singbox.VPNProxyListen, ListenPort: ports.Bridge,
				Network: "tcp", OverrideAddress: outbound.Server, OverridePort: outbound.ServerPort,
			})
			outbound = xray.LocalOutbound(tunnel, secrets.ClashSecret)
		}
		dns, err := vpnDNS(tunnel.DNS, outbound.Tag+"-dns", outbound.Tag, tunnel.DNSExplicit)
		if err != nil {
			return nil, fmt.Errorf("VPN tunnel %q: %w", tunnel.Name, err)
		}
		outbounds = append(outbounds, outbound)
		servers = append(servers, dns)
	}
	for i := range outbounds {
		if override, ok := opts.Outbounds[outbounds[i].Tag]; ok {
			outbounds[i] = override
		}
	}

	if cfg.VPNProxy != 0 {
		if socks.Addr().Unmap().String() == singbox.VPNProxyListen && socks.Port() == cfg.VPNProxy {
			return nil, errors.New("vpn_proxy_port conflicts with the resolved gateway SOCKS endpoint")
		}
		proxy := singbox.Inbound{Type: "mixed", Tag: singbox.VPNProxyTag, Listen: singbox.VPNProxyListen, ListenPort: cfg.VPNProxy}
		if cfg.VPNProxyTLSCert != "" {
			proxy.Type = "http"
			proxy.TLS = &singbox.InboundTLS{Enabled: true, CertificatePath: cfg.VPNProxyTLSCert, KeyPath: cfg.VPNProxyTLSKey}
		}
		inbounds = append(inbounds, proxy)
	}

	generated := singbox.Config{
		Log:       singbox.Log{Level: cfg.LogLevel},
		Inbounds:  inbounds,
		Outbounds: outbounds,
		DNS: singbox.DNS{
			Servers:  servers,
			Rules:    dnsRules(cfg),
			Final:    "remote",
			Strategy: "prefer_ipv4",
			// A shared IP must not inherit another connection's VPN selection.
			ReverseMapping: len(cfg.VPN.Tunnels) == 0,
		},
		Route: singbox.Route{
			Rules:                 routeRules(cfg, socksPrefix),
			RuleSets:              ruleSets,
			Final:                 "vpn",
			AutoDetectInterface:   true,
			DefaultDomainResolver: "direct",
		},
		Experimental: singbox.Experimental{ClashAPI: singbox.ClashAPI{
			ExternalController: cfg.ClashAPI,
			Secret:             secrets.ClashSecret,
		}},
	}

	data, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sing-box config: %w", err)
	}
	return append(data, '\n'), nil
}

func vpnDNS(raw, tag, detour string, includePort bool) (singbox.DNSServer, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return singbox.DNSServer{}, errors.New("parse VPN DNS URL")
	}
	server := singbox.DNSServer{Type: "https", Tag: tag, Server: u.Hostname(), Detour: detour}
	if path := u.EscapedPath(); path != "/dns-query" {
		server.Path = path
	}
	if text := u.Port(); includePort && text != "" {
		port, err := strconv.ParseUint(text, 10, 16)
		if err != nil || port == 0 {
			return singbox.DNSServer{}, errors.New("invalid VPN DNS port")
		}
		server.ServerPort = uint16(port)
	}
	return server, nil
}

// dnsRules resolves gateway domains through the gateway DNS first; everything
// unmatched falls through to the remote resolver over the vpn.
func dnsRules(cfg config.Config) []singbox.DNSRule {
	rules := []singbox.DNSRule{{DomainSuffix: cfg.Gateway.Domains, Server: "gateway"}}
	if len(cfg.VPN.Tunnels) == 0 && cfg.VPN.ForceProviderDomains {
		rules = append(rules, singbox.DNSRule{RuleSet: providerRuleSets, Server: "remote"})
	}
	// A rule without conditions matches everything in sing-box, so the optional
	// local_domains rule exists only when the list is non-empty.
	if len(cfg.Direct.LocalDomains) > 0 {
		rules = append(rules, singbox.DNSRule{DomainSuffix: cfg.Direct.LocalDomains, Server: "local"})
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if len(tunnel.ProcessPathRegex) > 0 {
			rules = append(rules, singbox.DNSRule{ProcessPathRegex: tunnel.ProcessPathRegex, Server: tunnel.Tag() + "-dns"})
		}
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if len(tunnel.Domains) > 0 {
			rules = append(rules, singbox.DNSRule{DomainSuffix: tunnel.Domains, Server: tunnel.Tag() + "-dns"})
		}
	}
	if len(cfg.VPN.Tunnels) != 0 && cfg.VPN.ForceProviderDomains {
		rules = append(rules, singbox.DNSRule{RuleSet: providerRuleSets, Server: "remote"})
	}
	if len(cfg.VPN.ProcessPathRegex) != 0 {
		rules = append(rules, singbox.DNSRule{ProcessPathRegex: cfg.VPN.ProcessPathRegex, Server: "remote"})
	}
	return append(rules,
		singbox.DNSRule{DomainSuffix: directSuffixes, Server: "direct"},
		singbox.DNSRule{RuleSet: []string{"geosite-category-ru"}, Server: "direct"},
	)
}

// LoopbackListeners returns the optional TCP listeners checked during deployment.
func LoopbackListeners(cfg config.Config) []singbox.LoopbackListener {
	var listeners []singbox.LoopbackListener
	if cfg.VPNProxy != 0 {
		listeners = append(listeners, singbox.LoopbackListener{Port: cfg.VPNProxy, Tag: singbox.VPNProxyTag, Field: "vpn_proxy_port"})
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if tunnel.Xray != nil {
			listeners = append(listeners, singbox.LoopbackListener{Port: tunnel.Xray.Bridge, Tag: xray.BridgeTag(tunnel), Field: "vpn.tunnels." + tunnel.Name + ".xray.bridge_port"})
		}
	}
	return listeners
}

// RouteRules returns the route rules Render writes, in order, so front ends can
// show the routing that sing-box actually runs. The final outbound is vpn.
func RouteRules(cfg config.Config, gatewaySocks netip.AddrPort) ([]singbox.RouteRule, error) {
	socks, err := gatewayEndpoint(cfg, gatewaySocks)
	if err != nil {
		return nil, err
	}
	return routeRules(cfg, hostPrefix(socks.Addr())), nil
}

// routeRules keeps the gateway rules ahead of ip_is_private: gateway hosts in
// RFC1918 ranges would otherwise go direct. Unmatched traffic goes to the vpn.
func routeRules(cfg config.Config, socksPrefix string) []singbox.RouteRule {
	// Start with the dedicated listener when configured; it must win over
	// split-routing, including the DNS hijack on the TUN.
	rules := make([]singbox.RouteRule, 0, 10)
	if cfg.VPNProxy != 0 {
		rules = append(rules, singbox.RouteRule{Inbound: []string{singbox.VPNProxyTag}, Outbound: "vpn"})
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if tunnel.Xray != nil {
			rules = append(rules, singbox.RouteRule{Inbound: []string{xray.BridgeTag(tunnel)}, Outbound: "direct"})
		}
	}
	rules = append(rules,
		singbox.RouteRule{Action: "sniff"},
		singbox.RouteRule{Protocol: "dns", Action: "hijack-dns"},
		singbox.RouteRule{IPCIDR: []string{socksPrefix}, Outbound: "direct"},
		singbox.RouteRule{DomainSuffix: cfg.Gateway.Domains, Outbound: "gateway"},
		singbox.RouteRule{RuleSet: []string{"gateway-ip"}, Outbound: "gateway"},
		singbox.RouteRule{IPIsPrivate: true, Outbound: "direct"},
	)
	local := singbox.RouteRule{DomainSuffix: cfg.Direct.LocalDomains, Outbound: "direct"}
	if len(cfg.VPN.Tunnels) != 0 && len(cfg.Direct.LocalDomains) != 0 {
		rules = append(rules, local)
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if len(tunnel.ProcessPathRegex) > 0 {
			rules = append(rules, singbox.RouteRule{ProcessPathRegex: tunnel.ProcessPathRegex, Outbound: tunnel.Tag()})
		}
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		tag := tunnel.Tag()
		if len(tunnel.Domains) > 0 {
			rules = append(rules, singbox.RouteRule{DomainSuffix: tunnel.Domains, Outbound: tag})
		}
		if len(tunnel.CIDRs) > 0 {
			rules = append(rules, singbox.RouteRule{IPCIDR: tunnel.CIDRs, Outbound: tag})
		}
	}
	if cfg.VPN.ForceProviderDomains {
		rules = append(rules, singbox.RouteRule{RuleSet: providerRuleSets, Outbound: "vpn"})
	}
	if len(cfg.VPN.CIDRs) != 0 {
		rules = append(rules, singbox.RouteRule{IPCIDR: cfg.VPN.CIDRs, Outbound: "vpn"})
	}
	if len(cfg.VPN.Tunnels) == 0 && len(cfg.Direct.LocalDomains) != 0 {
		rules = append(rules, local)
	}
	if len(cfg.VPN.ProcessPathRegex) != 0 {
		rules = append(rules, singbox.RouteRule{ProcessPathRegex: cfg.VPN.ProcessPathRegex, Outbound: "vpn"})
	}
	return append(rules,
		singbox.RouteRule{DomainSuffix: directSuffixes, Outbound: "direct"},
		singbox.RouteRule{RuleSet: []string{"geoip-ru", "geosite-category-ru"}, Outbound: "direct"},
	)
}

// WriteConfig atomically replaces a sing-box config with owner-only permissions.
func WriteConfig(path string, configJSON []byte) error {
	if err := writeAtomic(path, configJSON, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

func renderInbound(opts Options) (singbox.Inbound, error) {
	switch opts.Inbound {
	case InboundTUN:
		return singbox.Inbound{
			Type: "tun", Tag: "tun-in",
			Address:   []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			AutoRoute: true,
		}, nil
	case InboundMixed:
		if opts.MixedPort == 0 {
			return singbox.Inbound{}, errors.New("mixed inbound requires a non-zero port")
		}
		return singbox.Inbound{
			Type: "mixed", Tag: "mixed-in", Listen: "127.0.0.1", ListenPort: opts.MixedPort,
		}, nil
	default:
		return singbox.Inbound{}, fmt.Errorf("unsupported inbound %q: want tun or mixed", opts.Inbound)
	}
}

// gatewayEndpoint returns the resolved endpoint, or parses gateway.socks
// when the caller did not resolve it (IP literals only).
func gatewayEndpoint(cfg config.Config, resolved netip.AddrPort) (netip.AddrPort, error) {
	if resolved.IsValid() {
		return netip.AddrPortFrom(resolved.Addr().Unmap(), resolved.Port()), nil
	}
	host, portText, err := net.SplitHostPort(cfg.Gateway.Socks)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse gateway SOCKS address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("parse gateway SOCKS address: invalid port")
	}
	addressIP, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, errors.New("gateway SOCKS host must be an IP address or resolved first")
	}
	return netip.AddrPortFrom(addressIP.Unmap(), uint16(port)), nil
}

// hostPrefix is the single-address prefix of addr (/32 or /128).
func hostPrefix(addr netip.Addr) string {
	return netip.PrefixFrom(addr, addr.BitLen()).String()
}

var providerRuleSets = []string{"geosite-google", "geosite-anthropic"}

func routeRuleSets(paths config.Paths, forceProviders bool) ([]singbox.RuleSet, error) {
	tags := []string{"geoip-ru", "geosite-category-ru"}
	if forceProviders {
		tags = append(tags, providerRuleSets...)
	}
	sets := make([]singbox.RuleSet, 1, 1+len(tags))
	sets[0] = singbox.RuleSet{Type: "local", Tag: "gateway-ip", Format: "source", Path: RuleSetPath(paths.RulesDir())}
	for _, tag := range tags {
		path := filepath.Join(paths.GeoDir(), tag+".srs")
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("geo rule-set %q is unavailable: %w; run: sudo twarp geo update", path, err)
		}
		sets = append(sets, singbox.RuleSet{Type: "local", Tag: tag, Format: "binary", Path: path})
	}
	return sets, nil
}
