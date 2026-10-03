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
	if want := "imported vpn outbound: vpn.example.com:443 (reality, sni example.com)"; !strings.Contains(stdout.String(), want) {
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
		{name: "empty stdin", args: []string{"import"}, stdin: " \n", system: system, wantCode: 1, wantErr: "paste the VPN URI on stdin: twarp import < key.txt"},
		{name: "root", args: []string{"import"}, stdin: "secret", system: cliTestSys{euid: 0}, wantCode: 1, wantErr: "do not run import with sudo"},
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
