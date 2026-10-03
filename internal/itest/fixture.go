//go:build integration

package itest

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
)

type renderedFixture struct {
	home        string
	out         string
	configPath  string
	mixedPort   int
	clashPort   int
	clashSecret string
	gateway     *socksServer
	vpn         *socksServer
}

func newRenderedFixture(t *testing.T) *renderedFixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(filepath.Join(out, "rules"), 0o755); err != nil {
		t.Fatalf("create output directories: %v", err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create twarp home: %v", err)
	}
	compileGeoRuleSets(t, out)
	if err := render.WriteRuleSet(filepath.Join(out, "rules"), nil); err != nil {
		t.Fatalf("write initial gateway rule-set: %v", err)
	}

	gateway := startSOCKSServer(t)
	vpn := startSOCKSServer(t)
	mixedPort := freePort(t)
	clashPort := freePort(t)
	const clashSecret = "twarp-flow-itest"
	cfg := config.Config{
		Gateway: config.GatewayConfig{
			Socks:         netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(gateway.Port())).String(),
			Domains:       []string{"intra.example"},
			DNS:           "127.0.0.1",
			AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		},
		Direct:   config.DirectConfig{DNS: "127.0.0.1"},
		VPN:      config.VPNConfig{DNS: "https://127.0.0.1/dns-query"},
		ClashAPI: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(clashPort)).String(),
		LogLevel: "debug",
	}
	secrets := syntheticSecrets(t, clashSecret)
	configJSON, err := render.Render(cfg, secrets, nil, render.Options{
		Paths:     config.Paths{Out: out},
		Inbound:   render.InboundMixed,
		MixedPort: uint16(mixedPort),
		Outbounds: map[string]singbox.Outbound{
			"gateway": socksOutbound("gateway", gateway.Port()),
			"vpn":     socksOutbound("vpn", vpn.Port()),
		},
	})
	if err != nil {
		t.Fatalf("render flow config: %v", err)
	}
	configPath := filepath.Join(out, "config.json")
	if err := render.WriteConfig(configPath, configJSON); err != nil {
		t.Fatalf("write flow config: %v", err)
	}

	configYAML := fmt.Sprintf(
		"gateway:\n  socks: 127.0.0.1:%d\n  domains: [intra.example]\n  dns: 127.0.0.1\n  allowed_ranges: [100.64.0.0/10]\ndirect:\n  dns: 127.0.0.1\nvpn:\n  dns: https://127.0.0.1/dns-query\nclash_api: 127.0.0.1:%d\nlog_level: debug\n",
		gateway.Port(), clashPort,
	)
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write twarp config: %v", err)
	}
	if err := config.SaveSecrets(filepath.Join(home, "secrets.yaml"), secrets); err != nil {
		t.Fatalf("write twarp secrets: %v", err)
	}

	return &renderedFixture{
		home: home, out: out, configPath: configPath,
		mixedPort: mixedPort, clashPort: clashPort, clashSecret: clashSecret,
		gateway: gateway, vpn: vpn,
	}
}

func (f *renderedFixture) start(t *testing.T) *singBoxProcess {
	t.Helper()
	return startSingBoxWithConfig(t, f.configPath, f.mixedPort, f.clashPort, f.clashSecret)
}

func (f *renderedFixture) buildTWARP(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "twarp")
	command := exec.Command("go", "build", "-o", binary, "./cmd/twarp")
	command.Dir = filepath.Join("..", "..")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build twarp: %v\n%s", err, output)
	}
	return binary
}

func (f *renderedFixture) runTWARP(t *testing.T, binary string, args ...string) string {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = append(os.Environ(),
		"TWARP_HOME="+f.home,
		"TWARP_OUT="+f.out,
		"TWARP_SINGBOX="+singBoxPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("twarp %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func socksOutbound(tag string, port int) singbox.Outbound {
	return singbox.Outbound{
		Type: "socks", Tag: tag, Server: "127.0.0.1", ServerPort: uint16(port), Version: "5",
	}
}

func syntheticSecrets(t *testing.T, clashSecret string) config.Secrets {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic X25519 key: %v", err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		t.Fatalf("generate synthetic UUID: %v", err)
	}
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	query := url.Values{
		"security": {"reality"}, "encryption": {"none"}, "type": {"tcp"},
		"flow": {"xtls-rprx-vision"}, "sni": {"example.com"}, "fp": {"chrome"},
		"pbk": {publicKey}, "sid": {"0123abcd"},
	}
	return config.Secrets{
		VPNURI:      fmt.Sprintf("%s://%s@vpn.example.com:443?%s", "vless", uuid, query.Encode()),
		ClashSecret: clashSecret,
	}
}

func compileGeoRuleSets(t *testing.T, out string) {
	t.Helper()
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
		command := exec.Command(singBoxPath, "rule-set", "compile", "--output", outputPath, sourcePath)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compile %s rule-set: %v\n%s", tag, err, output)
		}
	}
}
