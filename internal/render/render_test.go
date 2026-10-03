package render_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
)

var update = flag.Bool("update", false, "update golden files")

func TestRenderMatchesGolden(t *testing.T) {
	out := t.TempDir()
	createGeoPlaceholders(t, out)

	got, err := render.Render(testConfig(), testSecrets(t), testPrefixes(), render.Options{
		Paths:   config.Paths{Out: out},
		Inbound: "tun",
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	got = bytes.ReplaceAll(got, []byte(out), []byte("${OUT}"))
	assertGolden(t, filepath.Join("testdata", "golden", "config.json"), got)
}

func TestRenderConfigContract(t *testing.T) {
	out := t.TempDir()
	createGeoPlaceholders(t, out)
	got := renderFixture(t, out, render.Options{Inbound: render.InboundTUN})

	var configJSON singbox.Config
	if err := json.Unmarshal(got, &configJSON); err != nil {
		t.Fatalf("decode Render() output: %v", err)
	}
	wantInbound := singbox.Inbound{
		Type: "tun", Tag: "tun-in",
		Address:   []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		AutoRoute: true,
	}
	if len(configJSON.Inbounds) != 1 || !reflect.DeepEqual(configJSON.Inbounds[0], wantInbound) {
		t.Fatalf("inbounds = %#v, want %#v", configJSON.Inbounds, []singbox.Inbound{wantInbound})
	}
	wantRouteRules := []singbox.RouteRule{
		{Action: "sniff"},
		{Protocol: "dns", Action: "hijack-dns"},
		{IPCIDR: []string{"192.0.2.10/32"}, Outbound: "direct"},
		{DomainSuffix: []string{"corp.example", "internal.example"}, Outbound: "corp"},
		{RuleSet: []string{"corp-ip"}, Outbound: "corp"},
		{IPIsPrivate: true, Outbound: "direct"},
		{DomainSuffix: []string{"home.arpa", "lan"}, Outbound: "direct"},
		{DomainSuffix: []string{"ru", "su", "xn--p1ai"}, Outbound: "direct"},
		{RuleSet: []string{"geoip-ru", "geosite-category-ru"}, Outbound: "direct"},
	}
	if !reflect.DeepEqual(configJSON.Route.Rules, wantRouteRules) {
		t.Fatalf("route rules = %#v, want %#v", configJSON.Route.Rules, wantRouteRules)
	}
	if !configJSON.Route.AutoDetectInterface || configJSON.Route.DefaultDomainResolver != "direct" {
		t.Fatalf("route interface/resolver = %#v", configJSON.Route)
	}
	for _, forbidden := range [][]byte{[]byte(`"cache_file"`), []byte(`"strict_route"`)} {
		if bytes.Contains(got, forbidden) {
			t.Fatalf("Render() contains forbidden field %s", forbidden)
		}
	}

	wantDNSServers := []singbox.DNSServer{
		{Type: "tcp", Tag: "corp", Server: "100.64.70.28", Detour: "corp"},
		{Type: "udp", Tag: "direct", Server: "77.88.8.8"},
		{Type: "local", Tag: "local"},
		{Type: "https", Tag: "remote", Server: "1.1.1.1", Path: "/custom-query", Detour: "vpn"},
	}
	wantDNSRules := []singbox.DNSRule{
		{DomainSuffix: []string{"corp.example", "internal.example"}, Server: "corp"},
		{DomainSuffix: []string{"home.arpa", "lan"}, Server: "local"},
		{DomainSuffix: []string{"ru", "su", "xn--p1ai"}, Server: "direct"},
		{RuleSet: []string{"geosite-category-ru"}, Server: "direct"},
	}
	if !reflect.DeepEqual(configJSON.DNS.Servers, wantDNSServers) ||
		!reflect.DeepEqual(configJSON.DNS.Rules, wantDNSRules) ||
		configJSON.DNS.Final != "remote" || configJSON.DNS.Strategy != "prefer_ipv4" ||
		!configJSON.DNS.ReverseMapping {
		t.Fatalf("DNS config = %#v", configJSON.DNS)
	}
	if configJSON.DNS.Servers[1].Detour != "" {
		t.Fatalf("direct DNS detour = %q, want empty", configJSON.DNS.Servers[1].Detour)
	}
	vpn := outboundByTag(t, configJSON.Outbounds, "vpn")
	if vpn.DomainResolver != "direct" {
		t.Fatalf("vpn domain_resolver = %q, want direct", vpn.DomainResolver)
	}
	if got := configJSON.Experimental.ClashAPI; got.ExternalController != "127.0.0.1:9090" || got.Secret != "synthetic-clash-secret" {
		t.Fatalf("clash_api = %#v", got)
	}
}

func TestRenderMixedInboundAndOutboundOverrides(t *testing.T) {
	out := t.TempDir()
	createGeoPlaceholders(t, out)
	corpOverride := singbox.Outbound{Type: "direct", Tag: "corp"}
	vpnOverride := singbox.Outbound{Type: "direct", Tag: "vpn"}
	got := renderFixture(t, out, render.Options{
		Inbound:   render.InboundMixed,
		MixedPort: 2080,
		Outbounds: map[string]singbox.Outbound{"corp": corpOverride, "vpn": vpnOverride},
	})
	var configJSON singbox.Config
	if err := json.Unmarshal(got, &configJSON); err != nil {
		t.Fatalf("decode Render() output: %v", err)
	}
	wantInbound := singbox.Inbound{Type: "mixed", Tag: "mixed-in", Listen: "127.0.0.1", ListenPort: 2080}
	if len(configJSON.Inbounds) != 1 || !reflect.DeepEqual(configJSON.Inbounds[0], wantInbound) {
		t.Fatalf("inbounds = %#v, want %#v", configJSON.Inbounds, []singbox.Inbound{wantInbound})
	}
	if got := outboundByTag(t, configJSON.Outbounds, "corp"); !reflect.DeepEqual(got, corpOverride) {
		t.Fatalf("corp outbound = %#v, want override %#v", got, corpOverride)
	}
	if got := outboundByTag(t, configJSON.Outbounds, "vpn"); !reflect.DeepEqual(got, vpnOverride) {
		t.Fatalf("vpn outbound = %#v, want override %#v", got, vpnOverride)
	}
}

func TestRenderRejectsMissingGeoAndInvalidInbound(t *testing.T) {
	_, err := render.Render(testConfig(), testSecrets(t), testPrefixes(), render.Options{
		Paths: config.Paths{Out: t.TempDir()}, Inbound: render.InboundTUN,
	})
	if err == nil || !strings.Contains(err.Error(), "run: sudo twarp geo update") {
		t.Fatalf("Render() missing geo error = %v, want update hint", err)
	}

	out := t.TempDir()
	createGeoPlaceholders(t, out)
	_, err = render.Render(testConfig(), testSecrets(t), testPrefixes(), render.Options{
		Paths: config.Paths{Out: out}, Inbound: "http",
	})
	if err == nil || !strings.Contains(err.Error(), "want tun or mixed") {
		t.Fatalf("Render() invalid inbound error = %v", err)
	}
}

func TestRenderRuleSetMatchesGolden(t *testing.T) {
	got, err := render.RenderRuleSet(testPrefixes())
	if err != nil {
		t.Fatalf("RenderRuleSet() error = %v", err)
	}
	assertGolden(t, filepath.Join("testdata", "golden", "corp-ip.json"), got)
}

func TestRenderRuleSetEmptyAndSingBoxCompile(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []netip.Prefix
		want     string
	}{
		{name: "empty", prefixes: nil, want: "{\n  \"version\": 2,\n  \"rules\": []\n}\n"},
		{name: "populated", prefixes: testPrefixes()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := render.RenderRuleSet(test.prefixes)
			if err != nil {
				t.Fatalf("RenderRuleSet() error = %v", err)
			}
			if test.want != "" && string(got) != test.want {
				t.Fatalf("RenderRuleSet() = %s, want %s", got, test.want)
			}
			source := filepath.Join(t.TempDir(), "corp-ip.json")
			if err := os.WriteFile(source, got, 0o600); err != nil {
				t.Fatalf("write source rule-set: %v", err)
			}
			output := filepath.Join(t.TempDir(), "corp-ip.srs")
			command := exec.Command(singBox(t), "rule-set", "compile", "--output", output, source)
			if commandOutput, err := command.CombinedOutput(); err != nil {
				t.Fatalf("sing-box rule-set compile: %v\n%s", err, commandOutput)
			}
		})
	}
}

func TestRenderedConfigPassesSingBoxCheck(t *testing.T) {
	out := t.TempDir()
	createGeoRuleSets(t, out)
	configJSON := renderFixture(t, out, render.Options{Inbound: render.InboundTUN})
	if err := render.WriteRuleSet(filepath.Join(out, "rules"), testPrefixes()); err != nil {
		t.Fatalf("WriteRuleSet() error = %v", err)
	}
	configPath := filepath.Join(out, "config.json")
	if err := render.WriteConfig(configPath, configJSON); err != nil {
		t.Fatalf("WriteConfig() error = %v", err)
	}
	command := exec.Command(singBox(t), "check", "--config", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, output)
	}
}

func TestAtomicWritersModesAndOnChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nested", "config.json")
	if err := render.WriteConfig(configPath, []byte("first\n")); err != nil {
		t.Fatalf("WriteConfig() error = %v", err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatalf("relax config permissions before replacement: %v", err)
	}
	if err := render.WriteConfig(configPath, []byte("second\n")); err != nil {
		t.Fatalf("WriteConfig() replacement error = %v", err)
	}
	assertFile(t, configPath, "second\n", 0o600)

	rulesDir := filepath.Join(dir, "rules")
	if err := render.WriteRuleSet(rulesDir, nil); err != nil {
		t.Fatalf("WriteRuleSet() error = %v", err)
	}
	rulesPath := filepath.Join(rulesDir, "corp-ip.json")
	assertFile(t, rulesPath, "{\n  \"version\": 2,\n  \"rules\": []\n}\n", 0o644)
	if err := render.OnChangeWriter(rulesDir)(testPrefixes()); err != nil {
		t.Fatalf("OnChangeWriter() error = %v", err)
	}
	got, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read callback rule-set: %v", err)
	}
	if !bytes.Contains(got, []byte("100.66.84.182/32")) {
		t.Fatalf("callback rule-set = %s, want updated prefixes", got)
	}
	matches, err := filepath.Glob(filepath.Join(rulesDir, ".corp-ip.json.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary rule-set files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary rule-set files remain: %v", matches)
	}
}

func renderFixture(t *testing.T, out string, opts render.Options) []byte {
	t.Helper()
	opts.Paths = config.Paths{Out: out}
	got, err := render.Render(testConfig(), testSecrets(t), testPrefixes(), opts)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	return got
}

func outboundByTag(t *testing.T, outbounds []singbox.Outbound, tag string) singbox.Outbound {
	t.Helper()
	for _, outbound := range outbounds {
		if outbound.Tag == tag {
			return outbound
		}
	}
	t.Fatalf("outbound %q not found in %#v", tag, outbounds)
	return singbox.Outbound{}
}

func testConfig() config.Config {
	return config.Config{
		Corp: config.CorpConfig{
			Socks:   "192.0.2.10:1080",
			Domains: []string{"corp.example", "internal.example"},
			DNS:     "100.64.70.28",
		},
		Direct: config.DirectConfig{
			DNS:          "77.88.8.8",
			LocalDomains: []string{"home.arpa", "lan"},
		},
		VPN:      config.VPNConfig{DNS: "https://1.1.1.1/custom-query"},
		ClashAPI: "127.0.0.1:9090",
		LogLevel: "warn",
	}
}

func testSecrets(t *testing.T) config.Secrets {
	t.Helper()
	privateBytes := make([]byte, 32)
	for i := range privateBytes {
		privateBytes[i] = byte(i + 1)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("construct synthetic X25519 key: %v", err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	uuid := strings.Join([]string{"11111111", "2222", "4333", "8444", "555555555555"}, "-")
	query := url.Values{
		"security":   {"reality"},
		"encryption": {"none"},
		"type":       {"tcp"},
		"flow":       {"xtls-rprx-vision"},
		"sni":        {"example.com"},
		"fp":         {"edge"},
		"pbk":        {publicKey},
		"sid":        {"0123abcd"},
	}
	return config.Secrets{
		VPNURI:      fmt.Sprintf("%s://%s@vpn.example.com:443?%s", "vless", uuid, query.Encode()),
		ClashSecret: "synthetic-clash-secret",
	}
}

func testPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("100.66.84.182/32"),
		netip.MustParsePrefix("2001:db8:abcd::/48"),
	}
}

func createGeoRuleSets(t *testing.T, out string) {
	t.Helper()
	binary := singBox(t)
	geoDir := filepath.Join(out, "geo")
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatalf("create geo directory: %v", err)
	}
	sources := map[string]string{
		"geoip-ru":            `{"version":2,"rules":[{"ip_cidr":["198.51.100.0/24"]}]}`,
		"geosite-category-ru": `{"version":2,"rules":[{"domain_suffix":["example.ru"]}]}`,
	}
	for tag, source := range sources {
		sourcePath := filepath.Join(t.TempDir(), tag+".json")
		if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
			t.Fatalf("write %s source rule-set: %v", tag, err)
		}
		outputPath := filepath.Join(geoDir, tag+".srs")
		command := exec.Command(binary, "rule-set", "compile", "--output", outputPath, sourcePath)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compile %s rule-set: %v\n%s", tag, err, output)
		}
	}
}

func createGeoPlaceholders(t *testing.T, out string) {
	t.Helper()
	geoDir := filepath.Join(out, "geo")
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatalf("create geo directory: %v", err)
	}
	for _, name := range []string{"geoip-ru.srs", "geosite-category-ru.srs"} {
		if err := os.WriteFile(filepath.Join(geoDir, name), []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write %s placeholder: %v", name, err)
		}
	}
}

func singBox(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sing-box")
	if err != nil {
		t.Fatal("install sing-box: brew install sing-box")
	}
	return path
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden directory: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden %q: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %q: %v (run go test ./internal/render -update)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from %s; run go test ./internal/render -update", path)
	}
}

func assertFile(t *testing.T, path, wantContent string, wantMode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if string(got) != wantContent {
		t.Fatalf("%s content = %q, want %q", path, got, wantContent)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if gotMode := info.Mode().Perm(); gotMode != wantMode {
		t.Fatalf("%s mode = %04o, want %04o", path, gotMode, wantMode)
	}
}

// A sing-box rule without conditions matches every connection, so an empty
// list in twarp.yaml must drop the rule instead of routing everything direct.
func TestRenderNeverEmitsUnconditionalRules(t *testing.T) {
	out := t.TempDir()
	createGeoPlaceholders(t, out)
	cfg := testConfig()
	cfg.Direct.LocalDomains = nil

	data, err := render.Render(cfg, testSecrets(t), nil, render.Options{Paths: config.Paths{Out: out}, Inbound: render.InboundTUN})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	var generated singbox.Config
	if err := json.Unmarshal(data, &generated); err != nil {
		t.Fatalf("decode rendered config: %v", err)
	}
	for i, rule := range generated.Route.Rules {
		if rule.Action != "" {
			continue
		}
		if len(rule.IPCIDR) == 0 && len(rule.DomainSuffix) == 0 && len(rule.RuleSet) == 0 && !rule.IPIsPrivate && rule.Protocol == "" {
			t.Errorf("route.rules[%d] = %#v has no condition and would match all traffic", i, rule)
		}
	}
	for i, rule := range generated.DNS.Rules {
		if len(rule.DomainSuffix) == 0 && len(rule.RuleSet) == 0 {
			t.Errorf("dns.rules[%d] = %#v has no condition and would match all queries", i, rule)
		}
	}
}

// Before `sudo twarp install` the rules directory does not exist and its root-
// owned parent cannot be created by the user; install renders the rule-set.
func TestOnChangeWriterSkipsWhenNotInstalled(t *testing.T) {
	rulesDir := filepath.Join(t.TempDir(), "not-installed", "rules")
	if err := render.OnChangeWriter(rulesDir)(testPrefixes()); err != nil {
		t.Fatalf("OnChangeWriter() error = %v, want nil before install", err)
	}
	if _, err := os.Stat(rulesDir); !os.IsNotExist(err) {
		t.Fatalf("rules dir stat err = %v, want it not to be created", err)
	}
}
