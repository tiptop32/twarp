package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
)

const syntheticGatewayPassword = "synthetic gateway pass"

func gatewayAuthDeps(t *testing.T, euid int, stdin string) (cliDeps, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	system := cliTestSys{euid: euid, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(home, "out")}}
	return cliDeps{Sys: system, Stdin: strings.NewReader(stdin)}, home
}

func TestRunGatewayAuthStoresCredentialsFromStdin(t *testing.T) {
	deps, home := gatewayAuthDeps(t, 501, "proxy\r\n"+syntheticGatewayPassword+"\n")
	secretsPath := filepath.Join(home, "secrets.yaml")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveSecrets(secretsPath, config.Secrets{VPNURI: "kept", ClashSecret: "kept-secret"}); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIForTest([]string{"gateway", "auth"}, deps)
	if code != 0 || stderr != "" {
		t.Fatalf("gateway auth = (%d, %q, %q), want success", code, stdout, stderr)
	}
	if strings.Contains(stdout, syntheticGatewayPassword) || !strings.Contains(stdout, "for user proxy") {
		t.Errorf("stdout = %q, want the user and no password", stdout)
	}
	secrets, err := config.LoadSecrets(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Secrets{VPNURI: "kept", ClashSecret: "kept-secret", GatewaySocksUser: "proxy", GatewaySocksPassword: syntheticGatewayPassword}
	if secrets != want {
		t.Errorf("secrets = %+v, want %+v", secrets, want)
	}
	if info, err := os.Stat(secretsPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("secrets mode = %v, %v; want 0600", info, err)
	}

	deps.Stdin = strings.NewReader("")
	if _, stderr, code := runCLIForTest([]string{"gateway", "auth", "--clear"}, deps); code != 0 {
		t.Fatalf("gateway auth --clear = (%d, %q)", code, stderr)
	}
	secrets, err = config.LoadSecrets(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.HasGatewayAuth() || secrets.VPNURI != "kept" {
		t.Errorf("after --clear secrets = %+v, want credentials removed and the rest kept", secrets)
	}
}

func TestRunGatewayAuthRejectsBadInput(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		euid  int
		code  int
		want  string
	}{
		{"password as argument", []string{"gateway", "auth", "proxy"}, "", 501, 2, "stdin only"},
		{"one line", []string{"gateway", "auth"}, "proxy\n", 501, 1, "first line"},
		{"empty password", []string{"gateway", "auth"}, "proxy\n\n", 501, 1, "first line"},
		{"too long", []string{"gateway", "auth"}, "proxy\n" + strings.Repeat("x", 256) + "\n", 501, 1, "at most 255 bytes"},
		{"sudo", []string{"gateway", "auth"}, "proxy\npass\n", 0, 1, "do not run gateway with sudo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, home := gatewayAuthDeps(t, tt.euid, tt.stdin)
			_, stderr, code := runCLIForTest(tt.args, deps)
			if code != tt.code || !strings.Contains(stderr, tt.want) {
				t.Fatalf("gateway auth = (%d, %q), want (%d, %q)", code, stderr, tt.code, tt.want)
			}
			if _, err := os.Stat(filepath.Join(home, "secrets.yaml")); err == nil {
				t.Error("rejected input must not write secrets.yaml")
			}
		})
	}
}
