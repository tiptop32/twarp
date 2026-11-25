package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
)

func TestRunImportWritesOwnerOnlySecretsWithoutLeakingURI(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	out := filepath.Join(base, "out")
	t.Setenv("TWARP_HOME", home)
	t.Setenv("TWARP_OUT", out)
	system := cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": out}}
	raw, uuid, publicKey := syntheticVPNURI(t)

	var stdout, stderr bytes.Buffer
	code := runWithDeps([]string{"import"}, &stdout, &stderr, cliDeps{
		Sys: system, Stdin: strings.NewReader(raw + "\n"), Random: bytes.NewReader(bytes.Repeat([]byte{0xa5}, 32)),
	})
	if code != 0 {
		t.Fatalf("run(import) = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for _, secret := range []string{raw, uuid, publicKey, "0123abcd"} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatalf("command output exposes a VPN credential: %q", stdout.String()+stderr.String())
		}
	}
	if want := "imported vpn outbound (VLESS Reality)"; !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}

	secretsPath := filepath.Join(home, "secrets.yaml")
	info, err := os.Stat(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("secrets permissions = %04o, want 0600", got)
	}
	secrets, err := config.LoadSecrets(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.VPNURI != raw {
		t.Error("stored VPN URI does not match stdin")
	}
	if secrets.ClashSecret != strings.Repeat("a5", 32) {
		t.Errorf("clash_secret = %q, want deterministic 32-byte hex", secrets.ClashSecret)
	}

	secondRaw, _, _ := syntheticVPNURI(t)
	stdout.Reset()
	stderr.Reset()
	code = runWithDeps([]string{"import"}, &stdout, &stderr, cliDeps{
		Sys: system, Stdin: strings.NewReader(secondRaw), Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32)),
	})
	if code != 0 {
		t.Fatalf("second run(import) = %d, stderr = %q", code, stderr.String())
	}
	secrets, err = config.LoadSecrets(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.VPNURI != secondRaw {
		t.Error("second import did not replace the VPN URI")
	}
	if secrets.ClashSecret != strings.Repeat("a5", 32) {
		t.Errorf("second import changed clash_secret to %q", secrets.ClashSecret)
	}
}

func TestRunImportReplacesOnlyNamedVPN(t *testing.T) {
	home := t.TempDir()
	system := cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(home, "out")}}
	path := filepath.Join(home, "secrets.yaml")
	before := config.Secrets{VPNURI: "existing primary", ClashSecret: "existing controller", GatewaySocksUser: "gateway", GatewaySocksPassword: "existing gateway", VPNURIs: map[string]string{"other": "existing other", "second": "old second"}}
	if err := config.SaveSecrets(path, before); err != nil {
		t.Fatal(err)
	}
	raw, id, publicKey := syntheticVPNURI(t)
	stdout, stderr, code := runCLIForTest([]string{"import", "--name", "second"}, cliDeps{Sys: system, Stdin: strings.NewReader(raw)})
	if code != 0 || stderr != "" || !strings.Contains(stdout, "vpn-second") || strings.Contains(stdout, id) || strings.Contains(stdout, publicKey) {
		t.Fatalf("named import failed or exposed credentials, exit %d", code)
	}
	got, err := config.LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.VPNURI != before.VPNURI || got.ClashSecret != before.ClashSecret || got.GatewaySocksUser != before.GatewaySocksUser || got.GatewaySocksPassword != before.GatewaySocksPassword || got.VPNURIs["other"] != before.VPNURIs["other"] || got.VPNURIs["second"] != raw {
		t.Fatal("named import did not replace only the selected URI")
	}
}

func TestRunImportXHTTPRequiresConfiguredXrayBeforePersistence(t *testing.T) {
	for _, test := range []struct {
		name      string
		target    string
		xray      bool
		noConfig  bool
		wantError bool
	}{
		{name: "primary", xray: true, wantError: true},
		{name: "sing-box tunnel", target: "second", wantError: true},
		{name: "unknown tunnel", target: "unknown", xray: true, wantError: true},
		{name: "missing config", target: "second", noConfig: true, wantError: true},
		{name: "Xray tunnel", target: "second", xray: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			system := cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(home, "out")}}
			if !test.noConfig {
				text := "gateway:\n  socks: 192.0.2.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\nvpn:\n  tunnels:\n    - name: second\n      domains: [selected.example]\n"
				if test.xray {
					text += "      xray: {listen_port: 19080, bridge_port: 19081}\n"
				}
				if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(home, "secrets.yaml")
			before := config.Secrets{VPNURI: "existing primary", ClashSecret: "existing controller", GatewaySocksUser: "gateway", GatewaySocksPassword: "existing gateway", VPNURIs: map[string]string{"other": "existing other", "second": "old second"}}
			if err := config.SaveSecrets(path, before); err != nil {
				t.Fatal(err)
			}
			query := url.Values{"security": {"tls"}, "type": {"xhttp"}, "sni": {"tls.example.com"}, "extra": {`{"noGRPCHeader":true}`}}
			raw := "vless://" + "11111111-1111-4111-8111-111111111111" + "@vpn.example.com:443?" + query.Encode()
			args := []string{"import"}
			if test.target != "" {
				args = append(args, "--name", test.target)
			}
			stdout, stderr, code := runCLIForTest(args, cliDeps{Sys: system, Stdin: strings.NewReader(raw)})
			if test.wantError {
				if code != 1 || !strings.Contains(stderr, "XHTTP requires") || stdout != "" {
					t.Fatalf("unsupported XHTTP import = (%d, %q, %q)", code, stdout, stderr)
				}
			} else if code != 0 || stderr != "" {
				t.Fatalf("configured XHTTP import = (%d, %q)", code, stderr)
			}
			if strings.Contains(stdout+stderr, raw) || strings.Contains(stdout+stderr, "11111111-1111-4111-8111-111111111111") {
				t.Fatal("import output exposed the VPN profile")
			}
			got, err := config.LoadSecrets(path)
			if err != nil {
				t.Fatal(err)
			}
			if !test.wantError {
				before.VPNURIs["second"] = raw
			}
			if !reflect.DeepEqual(got, before) {
				t.Fatal("XHTTP import changed credentials outside the supported selected profile")
			}
		})
	}
}

func TestConcurrentNamedImportsDoNotDropCredentials(t *testing.T) {
	home := t.TempDir()
	system := cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(home, "out")}}
	raw, _, _ := syntheticVPNURI(t)
	const count = 12
	start := make(chan struct{})
	results := make(chan int, count)
	for i := range count {
		go func() {
			<-start
			_, _, code := runCLIForTest([]string{"import", "--name", fmt.Sprint(i)}, cliDeps{Sys: system, Stdin: strings.NewReader(raw), Random: bytes.NewReader(make([]byte, 32))})
			results <- code
		}()
	}
	close(start)
	for range count {
		if code := <-results; code != 0 {
			t.Errorf("import exited %d", code)
		}
	}
	secrets, err := config.LoadSecrets(filepath.Join(home, "secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets.VPNURIs) != count {
		t.Fatalf("stored %d of %d named VPNs", len(secrets.VPNURIs), count)
	}
}

func TestRunImportRejectsArgumentsEmptyInputAndRoot(t *testing.T) {
	base := t.TempDir()
	system := cliTestSys{euid: 501, env: map[string]string{
		"TWARP_HOME": filepath.Join(base, "home"),
		"TWARP_OUT":  filepath.Join(base, "out"),
	}}
	tests := []struct {
		name     string
		args     []string
		stdin    string
		system   cliTestSys
		wantCode int
		wantErr  string
	}{
		{name: "argument", args: []string{"import", "secret"}, system: system, wantCode: 2, wantErr: "the URI is read from stdin only"},
		{name: "secret as name", args: []string{"import", "--name", "vless://synthetic"}, system: system, wantCode: 2, wantErr: "the URI is read from stdin only"},
		{name: "empty stdin", args: []string{"import"}, stdin: " \n", system: system, wantCode: 1, wantErr: "paste the VPN URI on stdin: twarp import < key.txt"},
		{name: "root", args: []string{"import"}, stdin: "secret", system: cliTestSys{euid: 0}, wantCode: 1, wantErr: "do not run import with sudo"},
		{name: "named root", args: []string{"import", "--name", "second"}, system: cliTestSys{euid: 0}, wantCode: 1, wantErr: "do not run import with sudo"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithDeps(test.args, &stdout, &stderr, cliDeps{
				Sys: test.system, Stdin: strings.NewReader(test.stdin), Random: bytes.NewReader(make([]byte, 32)),
			})
			if code != test.wantCode {
				t.Fatalf("run(%q) = %d, want %d", test.args, code, test.wantCode)
			}
			if !strings.Contains(stderr.String(), test.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), test.wantErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func syntheticVPNURI(t *testing.T) (raw, uuid, publicKey string) {
	t.Helper()

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("generate UUID: %v", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(id)
	uuid = fmt.Sprintf("%s-%s-%s-%s-%s", hexID[:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:])
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	publicKey = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	query := url.Values{
		"security": {"reality"}, "encryption": {"none"}, "headerType": {"none"},
		"fp": {"edge"}, "type": {"tcp"}, "flow": {"xtls-rprx-vision"},
		"sni": {"example.com"}, "sid": {"0123abcd"}, "pbk": {publicKey},
	}
	return fmt.Sprintf("%s://%s@vpn.example.com:443?%s#ignored-name", "vless", uuid, query.Encode()), uuid, publicKey
}
