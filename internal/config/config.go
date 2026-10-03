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
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/idna"
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
	Corp     CorpConfig
	Direct   DirectConfig
	VPN      VPNConfig
	ClashAPI string
	LogLevel string
}

// CorpConfig configures access to corporate resources.
type CorpConfig struct {
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
	Corp struct {
		Socks         string   `yaml:"socks"`
		Domains       []string `yaml:"domains"`
		DNS           string   `yaml:"dns"`
		AllowedRanges []string `yaml:"allowed_ranges"`
	} `yaml:"corp"`
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
func SaveSecrets(path string, secrets Secrets) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary secrets file for %q: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) && returnErr == nil {
			returnErr = fmt.Errorf("remove temporary secrets file for %q: %w", path, err)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary secrets permissions for %q: %w", path, err)
	}
	if err := yaml.NewEncoder(temporary).Encode(secrets); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode secrets for %q: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary secrets file for %q: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary secrets file for %q: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace secrets file %q: %w", path, err)
	}
	return nil
}

func defaultRawConfig() rawConfig {
	var raw rawConfig
	raw.Corp.AllowedRanges = []string{"100.64.0.0/10"}
	raw.Direct.DNS = defaultDirectDNS
	raw.Direct.LocalDomains = []string{"home.arpa"}
	raw.VPN.DNS = defaultVPNDNS
	raw.ClashAPI = defaultClashAPI
	raw.LogLevel = defaultLogLevel
	return raw
}

func validateConfig(raw rawConfig) (Config, error) {
	if raw.Corp.Socks == "" {
		return Config{}, errors.New("corp.socks is required")
	}
	if !validHostPort(raw.Corp.Socks) {
		return Config{}, errors.New("corp.socks must be host:port with a port from 1 to 65535")
	}
	if len(raw.Corp.Domains) == 0 {
		return Config{}, errors.New("corp.domains is required and must not be empty")
	}
	corpDomains, err := normalizeDomains("corp.domains", raw.Corp.Domains)
	if err != nil {
		return Config{}, err
	}
	if raw.Corp.DNS == "" {
		return Config{}, errors.New("corp.dns is required")
	}
	if _, err := netip.ParseAddr(raw.Corp.DNS); err != nil {
		return Config{}, errors.New("corp.dns must be an IP address")
	}
	allowedRanges, err := parseAllowedRanges(raw.Corp.AllowedRanges)
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
		Corp: CorpConfig{
			Socks:         raw.Corp.Socks,
			Domains:       corpDomains,
			DNS:           raw.Corp.DNS,
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
			return nil, fmt.Errorf("corp.allowed_ranges contains invalid prefix %q: %w", value, err)
		}
		if prefix.Bits() < 8 {
			return nil, fmt.Errorf("corp.allowed_ranges prefix %q must not be wider than /8", value)
		}
		ranges = append(ranges, prefix.Masked())
	}
	return ranges, nil
}
