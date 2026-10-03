package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
)

func TestRunRenderPrintsMaskedJSONWithoutRoot(t *testing.T) {
	for _, euid := range []int{501, 0} {
		t.Run(map[int]string{501: "user", 0: "root"}[euid], func(t *testing.T) {
			fixture := newCLIRenderFixture(t, euid)
			stdout, stderr, code := runCLIForTest([]string{"render"}, fixture.deps)
			if code != 0 || stderr != "" {
				t.Fatalf("render = (%d, %q, %q), want success", code, stdout, stderr)
			}
			var rendered map[string]any
			if err := json.Unmarshal([]byte(stdout), &rendered); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
			}
			for _, secret := range []string{fixture.uuid, fixture.publicKey, "0123abcd", fixture.clashSecret} {
				if strings.Contains(stdout, secret) {
					t.Fatalf("render output exposes credential %q", secret)
				}
			}
			if got := strings.Count(stdout, `"***"`); got != 4 {
				t.Fatalf("masked value count = %d, want 4\n%s", got, stdout)
			}
		})
	}
}

func TestRunRenderOutWritesFullCheckableSet(t *testing.T) {
	fixture := newCLIRenderFixture(t, 501)
	destination := filepath.Join(t.TempDir(), "rendered")
	stdout, stderr, code := runCLIForTest([]string{"render", "--out", destination}, fixture.deps)
	if code != 0 || stderr != "" {
		t.Fatalf("render --out = (%d, %q, %q), want success", code, stdout, stderr)
	}
	if !strings.Contains(stdout, filepath.Join(destination, "config.json")) {
		t.Fatalf("stdout = %q, want output path", stdout)
	}
	configPath := filepath.Join(destination, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{fixture.uuid, fixture.publicKey, "0123abcd", fixture.clashSecret} {
		if !strings.Contains(string(data), secret) {
			t.Errorf("full config does not contain credential %q", secret)
		}
	}
	if !strings.Contains(string(data), filepath.Join(destination, "rules", "corp-ip.json")) {
		t.Errorf("config does not point at rendered corp rule-set: %s", data)
	}
	if !strings.Contains(string(data), filepath.Join(fixture.out, "geo", "geoip-ru.srs")) {
		t.Errorf("config does not retain installed geo path: %s", data)
	}
	if info, err := os.Stat(configPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, error = %v, want 0600", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(filepath.Join(destination, "rules", "corp-ip.json")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("rule-set mode = %v, error = %v, want 0644", info.Mode().Perm(), err)
	}
}

type cliRenderFixture struct {
	deps            cliDeps
	home, out       string
	uuid, publicKey string
	clashSecret     string
}

func newCLIRenderFixture(t *testing.T, euid int) cliRenderFixture {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	out := filepath.Join(base, "out")
	if err := os.MkdirAll(filepath.Join(out, "geo"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geoip-ru.srs", "geosite-category-ru.srs"} {
		if err := os.WriteFile(filepath.Join(out, "geo", name), []byte("stub"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "corp:\n  socks: 192.168.0.105:8080\n  domains: [x5.ru]\n  dns: 100.64.70.28\n  allowed_ranges: [100.64.0.0/10]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, uuid, publicKey := syntheticVPNURI(t)
	clashSecret := strings.Repeat("a5", 32)
	if err := config.SaveSecrets(filepath.Join(home, "secrets.yaml"), config.Secrets{
		VPNURI: raw, ClashSecret: clashSecret,
	}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"TWARP_HOME": home, "TWARP_OUT": out, "TWARP_SINGBOX": "/test/sing-box",
		"TWARP_LOG_DIR": filepath.Join(base, "log"),
	}
	if euid == 0 {
		env["SUDO_USER"] = "alice"
		env["SUDO_UID"] = "501"
		env["SUDO_GID"] = "20"
	}
	return cliRenderFixture{
		deps: cliDeps{Sys: cliTestSys{euid: euid, env: env}},
		home: home, out: out, uuid: uuid, publicKey: publicKey, clashSecret: clashSecret,
	}
}
