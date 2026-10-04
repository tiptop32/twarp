package config_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
)

func TestLoadAppliesDefaultsAndNormalizesDomains(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "twarp.yaml", 0o600, `
gateway:
  socks: 192.168.1.10:1080
  domains: [.INTRA.EXAMPLE, ПРИМЕР.РФ]
  dns: 100.64.0.53
`)

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	wantRanges := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	if got.Direct.DNS != "77.88.8.8" {
		t.Errorf("Direct.DNS = %q, want %q", got.Direct.DNS, "77.88.8.8")
	}
	if !reflect.DeepEqual(got.Direct.LocalDomains, []string{"home.arpa"}) {
		t.Errorf("Direct.LocalDomains = %#v, want [home.arpa]", got.Direct.LocalDomains)
	}
	if got.VPN.DNS != "https://1.1.1.1/dns-query" {
		t.Errorf("VPN.DNS = %q, want default DoH URL", got.VPN.DNS)
	}
	if got.ClashAPI != "127.0.0.1:9090" {
		t.Errorf("ClashAPI = %q, want default API address", got.ClashAPI)
	}
	if got.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", got.LogLevel)
	}
	if !reflect.DeepEqual(got.Gateway.AllowedRanges, wantRanges) {
		t.Errorf("Gateway.AllowedRanges = %#v, want %#v", got.Gateway.AllowedRanges, wantRanges)
	}
	if !reflect.DeepEqual(got.Gateway.Domains, []string{"intra.example", "xn--e1afmkfd.xn--p1ai"}) {
		t.Errorf("Gateway.Domains = %#v, want normalized ASCII domains", got.Gateway.Domains)
	}
}

func TestLoadReadsExplicitValuesAndCanonicalizesPrefixes(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "twarp.yaml", 0o600, `
gateway:
  socks: "[2001:db8::10]:1080"
  domains: [Gateway.Example]
  dns: 2001:db8::53
  allowed_ranges: [10.7.9.4/8, 2001:db8:1::1/32]
direct:
  dns: 9.9.9.9
  local_domains: [.LAN]
vpn:
  dns: https://dns.example/dns-query
clash_api: 127.0.0.2:9091
log_level: debug
`)

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	wantRanges := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got.Gateway.AllowedRanges, wantRanges) {
		t.Errorf("Gateway.AllowedRanges = %#v, want %#v", got.Gateway.AllowedRanges, wantRanges)
	}
	if !reflect.DeepEqual(got.Direct.LocalDomains, []string{"lan"}) {
		t.Errorf("Direct.LocalDomains = %#v, want [lan]", got.Direct.LocalDomains)
	}
	if got.Direct.DNS != "9.9.9.9" || got.VPN.DNS != "https://dns.example/dns-query" || got.LogLevel != "debug" {
		t.Errorf("explicit values were not preserved: %#v", got)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{name: "unknown field", yaml: validConfig() + "unknown: true\n", wantError: "field unknown not found"},
		{name: "empty domains", yaml: strings.Replace(validConfig(), "domains: [intra.example]", "domains: []", 1), wantError: "gateway.domains is required"},
		{name: "missing socks", yaml: strings.Replace(validConfig(), "  socks: 192.168.1.10:1080\n", "", 1), wantError: "gateway.socks is required"},
		{name: "socks without port", yaml: strings.Replace(validConfig(), "192.168.1.10:1080", "192.168.1.10", 1), wantError: "gateway.socks must be host:port"},
		{name: "socks invalid port", yaml: strings.Replace(validConfig(), "192.168.1.10:1080", "192.168.1.10:70000", 1), wantError: "gateway.socks must be host:port"},
		{name: "socks hostname", yaml: strings.Replace(validConfig(), "192.168.1.10:1080", "proxy.example.com:1080", 1), wantError: "gateway.socks host must be an IP address"},
		{name: "missing DNS", yaml: strings.Replace(validConfig(), "  dns: 100.64.0.53\n", "", 1), wantError: "gateway.dns is required"},
		{name: "non-IP DNS", yaml: strings.Replace(validConfig(), "100.64.0.53", "dns.example", 1), wantError: "gateway.dns must be an IP address"},
		{name: "invalid domain", yaml: strings.Replace(validConfig(), "intra.example", "-bad.example", 1), wantError: "gateway.domains"},
		{name: "invalid prefix", yaml: validConfig() + "  allowed_ranges: [not-a-prefix]\n", wantError: "gateway.allowed_ranges"},
		{name: "prefix wider than slash eight", yaml: validConfig() + "  allowed_ranges: [0.0.0.0/0]\n", wantError: "must not be wider than /8"},
		{name: "invalid log level", yaml: validConfig() + "log_level: verbose\n", wantError: "log_level must be one of"},
		{name: "non-IP direct DNS", yaml: validConfig() + "direct:\n  dns: dns.yandex\n", wantError: "direct.dns must be an IP address"},
		{name: "plain-text VPN DNS", yaml: validConfig() + "vpn:\n  dns: 1.1.1.1\n", wantError: "vpn.dns must be an https:// URL"},
		{name: "VPN DNS without host", yaml: validConfig() + "vpn:\n  dns: https:///dns-query\n", wantError: "vpn.dns must be an https:// URL"},
		{name: "clash API without host", yaml: validConfig() + "clash_api: \"9090\"\n", wantError: "clash_api must be host:port"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := writeFile(t, "twarp.yaml", 0o600, test.yaml)
			_, err := config.Load(path)
			if err == nil {
				t.Fatalf("Load() error = nil, want it to contain %q", test.wantError)
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Load() error = %q, want it to contain %q", err, test.wantError)
			}
		})
	}
}

func TestSecretsRejectLoosePermissionsAndRoundTripAt0600(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	loosePath := filepath.Join(dir, "loose.yaml")
	if err := os.WriteFile(loosePath, []byte("vpn_uri: secret-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := config.LoadSecrets(loosePath)
	if err == nil {
		t.Fatal("LoadSecrets() error = nil, want loose-permission error")
	}
	if !strings.Contains(err.Error(), loosePath) || !strings.Contains(err.Error(), "0644") {
		t.Fatalf("LoadSecrets() error = %q, want path and 0644", err)
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("LoadSecrets() error leaks a secret: %q", err)
	}

	want := config.Secrets{VPNURI: "vless://synthetic", ClashSecret: "synthetic-secret"}
	path := filepath.Join(dir, "secrets.yaml")
	if err := config.SaveSecrets(path, want); err != nil {
		t.Fatalf("SaveSecrets() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("saved mode = %04o, want 0600", got)
	}
	got, err := config.LoadSecrets(path)
	if err != nil {
		t.Fatalf("LoadSecrets(saved file) error = %v", err)
	}
	if got != want {
		t.Fatalf("LoadSecrets(saved file) = %#v, want %#v", got, want)
	}
}

func validConfig() string {
	return "gateway:\n" +
		"  socks: 192.168.1.10:1080\n" +
		"  domains: [intra.example]\n" +
		"  dns: 100.64.0.53\n"
}

func writeFile(t *testing.T, name string, mode os.FileMode, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
