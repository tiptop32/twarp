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
	"slices"
	"strconv"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/uri"
)

const (
	// InboundTUN selects the production TUN inbound.
	InboundTUN = "tun"
	// InboundMixed selects the local mixed inbound used by tests and diagnostics.
	InboundMixed = "mixed"
)

var directSuffixes = []string{"ru", "su", "xn--p1ai"}

// Options controls filesystem paths and testable sing-box endpoints.
type Options struct {
	Paths     config.Paths
	Inbound   string
	MixedPort uint16
	Outbounds map[string]singbox.Outbound
}

// Render returns a complete sing-box configuration as indented JSON.
func Render(cfg config.Config, secrets config.Secrets, prefixes []netip.Prefix, opts Options) ([]byte, error) {
	if _, err := RenderRuleSet(prefixes); err != nil {
		return nil, err
	}
	if err := checkGeoRuleSets(opts.Paths); err != nil {
		return nil, err
	}
	inbound, err := renderInbound(opts)
	if err != nil {
		return nil, err
	}
	host, port, socksPrefix, err := parseCorpSOCKS(cfg.Corp.Socks)
	if err != nil {
		return nil, err
	}
	vpn, err := uri.Parse(secrets.VPNURI)
	if err != nil {
		return nil, fmt.Errorf("parse VPN URI: %w", err)
	}
	remoteDNS, err := url.Parse(cfg.VPN.DNS)
	if err != nil || remoteDNS.Hostname() == "" {
		return nil, errors.New("parse VPN DNS URL")
	}
	remotePath := remoteDNS.EscapedPath()
	if remotePath == "/dns-query" {
		remotePath = ""
	}

	outbounds := []singbox.Outbound{
		{Type: "direct", Tag: "direct"},
		{Type: "socks", Tag: "corp", Server: host, ServerPort: port, Version: "5"},
		vpn,
	}
	for i := range outbounds {
		if override, ok := opts.Outbounds[outbounds[i].Tag]; ok {
			outbounds[i] = override
		}
	}

	generated := singbox.Config{
		Log:       singbox.Log{Level: cfg.LogLevel},
		Inbounds:  []singbox.Inbound{inbound},
		Outbounds: outbounds,
		DNS: singbox.DNS{
			Servers: []singbox.DNSServer{
				{Type: "tcp", Tag: "corp", Server: cfg.Corp.DNS, Detour: "corp"},
				{Type: "udp", Tag: "direct", Server: cfg.Direct.DNS},
				{Type: "local", Tag: "local"},
				{Type: "https", Tag: "remote", Server: remoteDNS.Hostname(), Path: remotePath, Detour: "vpn"},
			},
			Rules: []singbox.DNSRule{
				{DomainSuffix: cfg.Corp.Domains, Server: "corp"},
				{DomainSuffix: directSuffixes, Server: "direct"},
				{RuleSet: []string{"geosite-category-ru"}, Server: "direct"},
			},
			Final:          "remote",
			Strategy:       "prefer_ipv4",
			ReverseMapping: true,
		},
		Route: singbox.Route{
			Rules: []singbox.RouteRule{
				{Action: "sniff"},
				{Protocol: "dns", Action: "hijack-dns"},
				{IPCIDR: []string{socksPrefix}, Outbound: "direct"},
				{DomainSuffix: cfg.Corp.Domains, Outbound: "corp"},
				{RuleSet: []string{"corp-ip"}, Outbound: "corp"},
				{IPIsPrivate: true, Outbound: "direct"},
				{DomainSuffix: directSuffixes, Outbound: "direct"},
				{RuleSet: []string{"geoip-ru", "geosite-category-ru"}, Outbound: "direct"},
			},
			RuleSets: []singbox.RuleSet{
				{Type: "local", Tag: "corp-ip", Format: "source", Path: filepath.Join(opts.Paths.RulesDir(), "corp-ip.json")},
				{Type: "local", Tag: "geoip-ru", Format: "binary", Path: filepath.Join(opts.Paths.GeoDir(), "geoip-ru.srs")},
				{Type: "local", Tag: "geosite-category-ru", Format: "binary", Path: filepath.Join(opts.Paths.GeoDir(), "geosite-category-ru.srs")},
			},
			Final:                 "vpn",
			AutoDetectInterface:   true,
			DefaultDomainResolver: "direct",
		},
		Experimental: singbox.Experimental{ClashAPI: singbox.ClashAPI{
			ExternalController: cfg.ClashAPI,
			Secret:             secrets.ClashSecret,
		}},
	}

	// A rule without conditions matches everything in sing-box, so the optional
	// local_domains rules exist only when the list is non-empty.
	if len(cfg.Direct.LocalDomains) > 0 {
		generated.DNS.Rules = slices.Insert(generated.DNS.Rules, 1,
			singbox.DNSRule{DomainSuffix: cfg.Direct.LocalDomains, Server: "local"})
		generated.Route.Rules = slices.Insert(generated.Route.Rules, 6,
			singbox.RouteRule{DomainSuffix: cfg.Direct.LocalDomains, Outbound: "direct"})
	}

	data, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sing-box config: %w", err)
	}
	return append(data, '\n'), nil
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

func parseCorpSOCKS(address string) (string, uint16, string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse corporate SOCKS address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, "", errors.New("parse corporate SOCKS address: invalid port")
	}
	addressIP, err := netip.ParseAddr(host)
	if err != nil {
		return "", 0, "", errors.New("corporate SOCKS host must be an IP address")
	}
	addressIP = addressIP.Unmap()
	bits := 128
	if addressIP.Is4() {
		bits = 32
	}
	return host, uint16(port), netip.PrefixFrom(addressIP, bits).String(), nil
}

func checkGeoRuleSets(paths config.Paths) error {
	for _, name := range []string{"geoip-ru.srs", "geosite-category-ru.srs"} {
		path := filepath.Join(paths.GeoDir(), name)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("geo rule-set %q is unavailable: %w; run: sudo twarp geo update", path, err)
		}
	}
	return nil
}
