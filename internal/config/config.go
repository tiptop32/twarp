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

// VPNConfig configures the VPN DNS resolver.
type VPNConfig struct {
	DNS string
}

// Secrets is the contents of secrets.yaml.
type Secrets struct {
	VPNURI      string `yaml:"vpn_uri"`
	ClashSecret string `yaml:"clash_secret"`
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
		DNS string `yaml:"dns"`
	} `yaml:"vpn"`
	ClashAPI string `yaml:"clash_api"`
	LogLevel string `yaml:"log_level"`
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
		return Secrets{}, fmt.Errorf("decode secrets %q: %w", path, err)
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
	if _, err := netip.ParseAddr(gatewaySocksHost); err != nil {
		return Config{}, errors.New("gateway.socks host must be an IP address")
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
	if !validHostPort(raw.ClashAPI) {
		return Config{}, errors.New("clash_api must be host:port with a port from 1 to 65535")
	}
	if _, ok := validLogLevels[raw.LogLevel]; !ok {
		return Config{}, errors.New("log_level must be one of trace, debug, info, warn, error")
	}

	return Config{
		Gateway: GatewayConfig{
			Socks:         raw.Gateway.Socks,
			Domains:       gatewayDomains,
			DNS:           raw.Gateway.DNS,
			AllowedRanges: allowedRanges,
		},
		Direct:   DirectConfig{DNS: raw.Direct.DNS, LocalDomains: localDomains},
		VPN:      VPNConfig{DNS: raw.VPN.DNS},
		ClashAPI: raw.ClashAPI,
		LogLevel: raw.LogLevel,
	}, nil
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
