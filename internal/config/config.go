// Package config loads and validates twarp configuration and resolves its paths.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/idna"

	"github.com/tiptop32/twarp/internal/fsutil"
)

const (
	defaultDirectDNS = "77.88.8.8"
	defaultVPNDNS    = "https://1.1.1.1/dns-query"
	defaultClashAPI  = "127.0.0.1:9090"
	defaultLogLevel  = "warn"
)

var validLogLevels = map[string]struct{}{
	"trace": {},
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

// Config is the validated contents of twarp.yaml.
type Config struct {
	Gateway  GatewayConfig
	Direct   DirectConfig
	VPN      VPNConfig
	ClashAPI string
	LogLevel string
	VPNProxy uint16

	VPNProxyTLSCert string
	VPNProxyTLSKey  string
}

// GatewayConfig configures access to gateway resources.
type GatewayConfig struct {
	Socks         string
	Domains       []string
	DNS           string
	AllowedRanges []netip.Prefix
}

// DirectConfig configures traffic that bypasses the VPN.
type DirectConfig struct {
	DNS          string
	LocalDomains []string
}

// VPNConfig configures the primary resolver and ordered additional tunnels.
type VPNConfig struct {
	DNS                  string
	ForceProviderDomains bool
	CIDRs                []string
	ProcessPathRegex     []string
	Tunnels              []Tunnel
}

// Tunnel is a validated additional VPN and its traffic selectors.
type Tunnel struct {
	Name             string
	DNS              string
	DNSExplicit      bool
	Domains          []string
	CIDRs            []string
	ProcessPathRegex []string
	Xray             *XrayPorts
}

// Tag returns the sing-box outbound tag for this tunnel.
func (t Tunnel) Tag() string { return "vpn-" + t.Name }

// XrayPorts enables a separate Xray client for one additional tunnel.
// Both listeners bind IPv4 loopback. The bridge carries only the upstream
// VLESS connection, so sing-box can bind it to the current network interface.
type XrayPorts struct {
	Listen uint16 `yaml:"listen_port"`
	Bridge uint16 `yaml:"bridge_port"`
}

type rawTunnel struct {
	Name             string     `yaml:"name"`
	DNS              string     `yaml:"dns"`
	Domains          []string   `yaml:"domains"`
	CIDRs            []string   `yaml:"cidrs"`
	ProcessPathRegex []string   `yaml:"process_path_regex"`
	Xray             *XrayPorts `yaml:"xray"`
}

var tunnelName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// ValidTunnelName reports whether name can identify an additional VPN.
func ValidTunnelName(name string) bool { return tunnelName.MatchString(name) }

// ValidXrayTunnelName excludes case aliases of login agent files on APFS.
func ValidXrayTunnelName(name string) bool {
	return ValidTunnelName(name) && name == strings.ToLower(name)
}

// Secrets is the contents of secrets.yaml.
type Secrets struct {
	VPNURI      string            `yaml:"vpn_uri"`
	VPNURIs     map[string]string `yaml:"vpn_uris,omitempty"`
	ClashSecret string            `yaml:"clash_secret"`
	// GatewaySocksUser and GatewaySocksPassword are the optional SOCKS5
	// username/password (RFC 1929) of the gateway; set together or not at all.
	GatewaySocksUser     string `yaml:"gateway_socks_user,omitempty"`
	GatewaySocksPassword string `yaml:"gateway_socks_password,omitempty"`
}

// HasGatewayAuth reports whether gateway SOCKS credentials are configured.
func (secrets Secrets) HasGatewayAuth() bool {
	return secrets.GatewaySocksUser != ""
}

// ValidateGatewayAuth checks the gateway SOCKS credentials: both or neither,
// each 1 to 255 bytes (the RFC 1929 limit).
func ValidateGatewayAuth(user, password string) error {
	if user == "" && password == "" {
		return nil
	}
	if user == "" || password == "" {
		return errors.New("gateway_socks_user and gateway_socks_password must be set together")
	}
	if len(user) > 255 || len(password) > 255 {
		return errors.New("gateway SOCKS username and password must be at most 255 bytes")
	}
	return nil
}

type rawConfig struct {
	Gateway struct {
		Socks         string   `yaml:"socks"`
		Domains       []string `yaml:"domains"`
		DNS           string   `yaml:"dns"`
		AllowedRanges []string `yaml:"allowed_ranges"`
	} `yaml:"gateway"`
	Direct struct {
		DNS          string   `yaml:"dns"`
		LocalDomains []string `yaml:"local_domains"`
	} `yaml:"direct"`
	VPN struct {
		DNS                  string      `yaml:"dns"`
		Tunnels              []rawTunnel `yaml:"tunnels"`
		ForceProviderDomains bool        `yaml:"force_provider_domains"`
		CIDRs                []string    `yaml:"cidrs"`
		ProcessPathRegex     []string    `yaml:"process_path_regex"`
	} `yaml:"vpn"`
	ClashAPI string    `yaml:"clash_api"`
	LogLevel string    `yaml:"log_level"`
	VPNProxy yaml.Node `yaml:"vpn_proxy_port"`

	VPNProxyTLSCert string `yaml:"vpn_proxy_tls_cert"`
	VPNProxyTLSKey  string `yaml:"vpn_proxy_tls_key"`
}

// Load reads, defaults, normalizes, and validates twarp.yaml.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	raw := defaultRawConfig()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	config, err := validateConfig(raw)
	if err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return config, nil
}

// LoadSecrets reads secrets.yaml after checking that no group or other bits are set.
func LoadSecrets(path string) (Secrets, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Secrets{}, fmt.Errorf("stat secrets %q: %w", path, err)
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return Secrets{}, fmt.Errorf("secrets file %q has permissions %04o; want 0600 or stricter", path, permissions)
	}

	file, err := os.Open(path)
	if err != nil {
		return Secrets{}, fmt.Errorf("open secrets %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	var secrets Secrets
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&secrets); err != nil {
		// YAML errors can include mapping keys and scalar values verbatim.
		return Secrets{}, fmt.Errorf("decode secrets %q: invalid YAML or unknown fields", path)
	}
	if err := ValidateGatewayAuth(secrets.GatewaySocksUser, secrets.GatewaySocksPassword); err != nil {
		return Secrets{}, fmt.Errorf("secrets %q: %w", path, err)
	}
	return secrets, nil
}

// SaveSecrets atomically writes secrets.yaml with owner-only permissions.
func SaveSecrets(path string, secrets Secrets) error {
	data, err := yaml.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("encode secrets for %q: %w", path, err)
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write secrets %q: %w", path, err)
	}
	return nil
}

// UpdateSecrets serializes read-modify-write operations across CLI processes.
// Readers need no lock: SaveSecrets publishes a complete file by rename.
func UpdateSecrets(path string, update func(*Secrets) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	release, err := fsutil.LockExclusive(path + ".lock")
	if err != nil {
		return err
	}
	defer release()
	secrets, err := LoadSecrets(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := update(&secrets); err != nil {
		return err
	}
	return SaveSecrets(path, secrets)
}

// validateGatewayHost accepts an IP literal or a DNS host name (RFC 1123
// labels, e.g. proxyhost.local). Names are resolved at apply time and again
// by twarpd on network changes; literals are used as is. Loopback stays
// allowed for local test gateways.
func validateGatewayHost(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsUnspecified() || addr.IsMulticast() {
			return errors.New("gateway.socks host must not be an unspecified or multicast address")
		}
		return nil
	}
	if !validHostName(host) {
		return errors.New("gateway.socks host must be an IP address or a host name such as proxyhost.local")
	}
	return nil
}

func validHostName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	allNumeric := true
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= '0' && r <= '9':
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-':
				allNumeric = false
			default:
				return false
			}
		}
	}
	// "192.168.1" is a mistyped address, not a name
	return !allNumeric
}

func defaultRawConfig() rawConfig {
	var raw rawConfig
	raw.Gateway.AllowedRanges = []string{"100.64.0.0/10"}
	raw.Direct.DNS = defaultDirectDNS
	raw.Direct.LocalDomains = []string{"home.arpa"}
	raw.VPN.DNS = defaultVPNDNS
	raw.ClashAPI = defaultClashAPI
	raw.LogLevel = defaultLogLevel
	return raw
}

func validateConfig(raw rawConfig) (Config, error) {
	if raw.Gateway.Socks == "" {
		return Config{}, errors.New("gateway.socks is required")
	}
	if !validHostPort(raw.Gateway.Socks) {
		return Config{}, errors.New("gateway.socks must be host:port with a port from 1 to 65535")
	}
	gatewaySocksHost, _, _ := net.SplitHostPort(raw.Gateway.Socks)
	if err := validateGatewayHost(gatewaySocksHost); err != nil {
		return Config{}, err
	}
	if len(raw.Gateway.Domains) == 0 {
		return Config{}, errors.New("gateway.domains is required and must not be empty")
	}
	gatewayDomains, err := normalizeDomains("gateway.domains", raw.Gateway.Domains)
	if err != nil {
		return Config{}, err
	}
	if raw.Gateway.DNS == "" {
		return Config{}, errors.New("gateway.dns is required")
	}
	if _, err := netip.ParseAddr(raw.Gateway.DNS); err != nil {
		return Config{}, errors.New("gateway.dns must be an IP address")
	}
	allowedRanges, err := parseAllowedRanges(raw.Gateway.AllowedRanges)
	if err != nil {
		return Config{}, err
	}
	localDomains, err := normalizeDomains("direct.local_domains", raw.Direct.LocalDomains)
	if err != nil {
		return Config{}, err
	}
	if _, err := netip.ParseAddr(raw.Direct.DNS); err != nil {
		return Config{}, errors.New("direct.dns must be an IP address")
	}
	if vpnDNS, err := url.Parse(raw.VPN.DNS); err != nil || vpnDNS.Scheme != "https" || vpnDNS.Host == "" {
		return Config{}, errors.New("vpn.dns must be an https:// URL with a host")
	}
	if err := validateVPNSelectors("vpn", raw.VPN.CIDRs, raw.VPN.ProcessPathRegex); err != nil {
		return Config{}, err
	}
	tunnels, err := validateTunnels(raw.VPN.Tunnels, raw.VPN.DNS)
	if err != nil {
		return Config{}, err
	}
	if !validHostPort(raw.ClashAPI) {
		return Config{}, errors.New("clash_api must be host:port with a port from 1 to 65535")
	}
	if _, ok := validLogLevels[raw.LogLevel]; !ok {
		return Config{}, errors.New("log_level must be one of trace, debug, info, warn, error")
	}
	var vpnProxyPort uint16
	if raw.VPNProxy.Kind != 0 {
		if raw.VPNProxy.Kind != yaml.ScalarNode || raw.VPNProxy.ShortTag() != "!!int" || raw.VPNProxy.Decode(&vpnProxyPort) != nil {
			return Config{}, errors.New("vpn_proxy_port must be an integer from 0 to 65535")
		}
	}
	if vpnProxyPort != 0 {
		_, clashPort, _ := net.SplitHostPort(raw.ClashAPI)
		if port, _ := strconv.ParseUint(clashPort, 10, 16); uint16(port) == vpnProxyPort {
			return Config{}, errors.New("vpn_proxy_port must differ from the clash_api port")
		}
	}
	if err := validateXrayPorts(tunnels, vpnProxyPort, raw.ClashAPI, raw.Gateway.Socks); err != nil {
		return Config{}, err
	}
	if (raw.VPNProxyTLSCert == "") != (raw.VPNProxyTLSKey == "") {
		return Config{}, errors.New("vpn_proxy_tls_cert and vpn_proxy_tls_key must be set together")
	}
	if raw.VPNProxyTLSCert != "" {
		if vpnProxyPort == 0 {
			return Config{}, errors.New("VPN proxy TLS requires vpn_proxy_port")
		}
		if !filepath.IsAbs(raw.VPNProxyTLSCert) || !filepath.IsAbs(raw.VPNProxyTLSKey) {
			return Config{}, errors.New("vpn_proxy_tls_cert and vpn_proxy_tls_key must be absolute paths")
		}
	}

	return Config{
		Gateway: GatewayConfig{
			Socks:         raw.Gateway.Socks,
			Domains:       gatewayDomains,
			DNS:           raw.Gateway.DNS,
			AllowedRanges: allowedRanges,
		},
		Direct: DirectConfig{DNS: raw.Direct.DNS, LocalDomains: localDomains},
		VPN: VPNConfig{
			DNS: raw.VPN.DNS, ForceProviderDomains: raw.VPN.ForceProviderDomains,
			CIDRs: raw.VPN.CIDRs, ProcessPathRegex: raw.VPN.ProcessPathRegex, Tunnels: tunnels,
		},
		ClashAPI: raw.ClashAPI,
		LogLevel: raw.LogLevel,
		VPNProxy: vpnProxyPort,

		VPNProxyTLSCert: raw.VPNProxyTLSCert,
		VPNProxyTLSKey:  raw.VPNProxyTLSKey,
	}, nil
}

func validateTunnels(raw []rawTunnel, defaultDNS string) ([]Tunnel, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	tunnels := make([]Tunnel, 0, len(raw))
	names := make(map[string]struct{}, len(raw))
	for i, t := range raw {
		if !ValidTunnelName(t.Name) {
			return nil, fmt.Errorf("vpn.tunnels[%d].name must contain only ASCII letters, digits or hyphens", i)
		}
		field := "vpn.tunnels." + t.Name
		if _, exists := names[t.Name]; exists {
			return nil, fmt.Errorf("%s: duplicate tunnel name", field)
		}
		names[t.Name] = struct{}{}
		if len(t.Domains)+len(t.CIDRs)+len(t.ProcessPathRegex) == 0 {
			return nil, fmt.Errorf("%s must have at least one traffic selector", field)
		}
		explicitDNS := t.DNS != ""
		if t.DNS == "" {
			t.DNS = defaultDNS
		}
		dns, err := url.Parse(t.DNS)
		if err != nil || dns.Scheme != "https" || dns.Hostname() == "" || (explicitDNS && (dns.User != nil || dns.RawQuery != "" || dns.Fragment != "" || (dns.Port() != "" && !validHostPort(dns.Host)))) {
			return nil, fmt.Errorf("%s.dns must be an https:// URL with a host and optional port and path", field)
		}
		domains, err := normalizeDomains(field+".domains", t.Domains)
		if err != nil {
			return nil, err
		}
		if err := validateVPNSelectors(field, t.CIDRs, t.ProcessPathRegex); err != nil {
			return nil, err
		}
		tunnels = append(tunnels, Tunnel{Name: t.Name, DNS: t.DNS, DNSExplicit: explicitDNS, Domains: domains, CIDRs: t.CIDRs, ProcessPathRegex: t.ProcessPathRegex, Xray: t.Xray})
	}
	return tunnels, nil
}

func validateXrayPorts(tunnels []Tunnel, vpnProxy uint16, clash, gateway string) error {
	if len(tunnels) == 0 {
		return nil
	}
	ports := map[uint16]string{vpnProxy: "vpn_proxy_port"}
	addEndpoint := func(endpoint, field string) {
		_, port, _ := net.SplitHostPort(endpoint)
		number, _ := strconv.ParseUint(port, 10, 16)
		ports[uint16(number)] = field
	}
	addEndpoint(clash, "clash_api")
	host, _, _ := net.SplitHostPort(gateway)
	if addr, err := netip.ParseAddr(host); err == nil && addr.Unmap() == netip.MustParseAddr("127.0.0.1") {
		addEndpoint(gateway, "gateway.socks")
	}
	for _, tunnel := range tunnels {
		if tunnel.Xray == nil {
			continue
		}
		if !ValidXrayTunnelName(tunnel.Name) {
			return fmt.Errorf("vpn.tunnels.%s.xray requires a lowercase tunnel name", tunnel.Name)
		}
		for _, spec := range []struct {
			name string
			port uint16
		}{{"listen_port", tunnel.Xray.Listen}, {"bridge_port", tunnel.Xray.Bridge}} {
			field := "vpn.tunnels." + tunnel.Name + ".xray." + spec.name
			if spec.port == 0 {
				return fmt.Errorf("%s must be a port from 1 to 65535", field)
			}
			if previous, conflict := ports[spec.port]; conflict {
				return fmt.Errorf("%s conflicts with %s", field, previous)
			}
			ports[spec.port] = field
		}
	}
	return nil
}

func validateVPNSelectors(field string, cidrs, expressions []string) error {
	for i, value := range cidrs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return fmt.Errorf("%s.cidrs contains invalid or default prefix %q", field, value)
		}
		cidrs[i] = prefix.Masked().String()
	}
	for i, expression := range expressions {
		if _, err := regexp.Compile(expression); strings.TrimSpace(expression) == "" || err != nil {
			return fmt.Errorf("%s.process_path_regex[%d] must be a non-empty regular expression", field, i)
		}
	}
	return nil
}

func validHostPort(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0
}

func normalizeDomains(field string, domains []string) ([]string, error) {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimLeft(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" {
			return nil, fmt.Errorf("%s contains an empty domain", field)
		}
		ascii, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid domain %q: %w", field, domain, err)
		}
		normalized = append(normalized, strings.ToLower(ascii))
	}
	return normalized, nil
}

func parseAllowedRanges(values []string) ([]netip.Prefix, error) {
	ranges := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("gateway.allowed_ranges contains invalid prefix %q: %w", value, err)
		}
		if prefix.Bits() < 8 {
			return nil, fmt.Errorf("gateway.allowed_ranges prefix %q must not be wider than /8", value)
		}
		ranges = append(ranges, prefix.Masked())
	}
	return ranges, nil
}
