package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGatewayMutatesStateAndRuleSet(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	out := filepath.Join(base, "out")
	t.Setenv("TWARP_HOME", home)
	t.Setenv("TWARP_OUT", out)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// `sudo twarp install` creates the user-owned rules directory.
	if err := os.MkdirAll(filepath.Join(out, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 192.168.1.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	system := cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": out}}
	deps := cliDeps{Sys: system}

	stdout, stderr, code := runCLIForTest([]string{"gateway", "add", "100.64.10.10", "--comment", "vm"}, deps)
	if code != 0 {
		t.Fatalf("gateway add = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "added 100.64.10.10/32") {
		t.Errorf("stdout = %q, want added prefix", stdout)
	}
	if !strings.Contains(stderr, "warning: sing-box is not running") {
		t.Errorf("stderr = %q, want stopped sing-box warning", stderr)
	}
	stateData, err := os.ReadFile(filepath.Join(home, "gateway-ips.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stateData, []byte("100.64.10.10/32")) || !bytes.Contains(stateData, []byte(`"comment":"vm"`)) {
		t.Errorf("state = %s, want CIDR and comment", stateData)
	}
	rulesData, err := os.ReadFile(filepath.Join(out, "rules", "gateway-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rulesData, []byte("100.64.10.10/32")) {
		t.Errorf("rule-set = %s, want added CIDR", rulesData)
	}

	stdout, stderr, code = runCLIForTest([]string{"gateway", "add", "10.1.2.3"}, deps)
	if code != 1 || !strings.Contains(stderr, "outside allowed ranges") {
		t.Fatalf("unforced outside add = (%d, %q, %q), want validation failure", code, stdout, stderr)
	}
	stdout, stderr, code = runCLIForTest([]string{"gateway", "add", "10.1.2.3", "--force", "--comment=external"}, deps)
	if code != 0 || !strings.Contains(stdout, "added 10.1.2.3/32") {
		t.Fatalf("forced outside add = (%d, %q, %q), want success", code, stdout, stderr)
	}

	stdout, stderr, code = runCLIForTest([]string{"gateway", "ls"}, deps)
	for _, want := range []string{"CIDR", "ADDED_BY", "ADDED_AT", "COMMENT", "100.64.10.10/32", "cli", "vm", "10.1.2.3/32", "external"} {
		if code != 0 || !strings.Contains(stdout, want) {
			t.Fatalf("gateway ls = (%d, %q, %q), want %q", code, stdout, stderr, want)
		}
	}

	stdout, stderr, code = runCLIForTest([]string{"gateway", "rm", "100.64.10.10"}, deps)
	if code != 0 || !strings.Contains(stdout, "removed 100.64.10.10/32") {
		t.Fatalf("gateway rm = (%d, %q, %q), want success", code, stdout, stderr)
	}
	rulesData, err = os.ReadFile(filepath.Join(out, "rules", "gateway-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rulesData, []byte("100.64.10.10/32")) {
		t.Errorf("rule-set still contains removed CIDR: %s", rulesData)
	}
}

func TestRunGatewayListEmptyAndRejectsRoot(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 192.168.1.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIForTest([]string{"gateway", "ls"}, cliDeps{Sys: cliTestSys{
		euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(base, "out")},
	}})
	if code != 0 || strings.TrimSpace(stdout) != "no gateway CIDRs" || stderr != "" {
		t.Fatalf("empty gateway ls = (%d, %q, %q)", code, stdout, stderr)
	}

	stdout, stderr, code = runCLIForTest([]string{"gateway", "add", "100.64.11.1"}, cliDeps{Sys: cliTestSys{euid: 0}})
	if code != 1 || stdout != "" || !strings.Contains(stderr, "do not run gateway with sudo") {
		t.Fatalf("root gateway = (%d, %q, %q), want refusal", code, stdout, stderr)
	}
}

func runCLIForTest(args []string, deps cliDeps) (stdout, stderr string, code int) {
	var stdoutBuffer, stderrBuffer bytes.Buffer
	code = runWithDeps(args, &stdoutBuffer, &stderrBuffer, deps)
	return stdoutBuffer.String(), stderrBuffer.String(), code
}

func TestRunGatewayAddBeforeInstallWarnsAndSucceeds(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	out := filepath.Join(base, "not-installed")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 192.168.1.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := cliDeps{Sys: cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": out}}}

	stdout, stderr, code := runCLIForTest([]string{"gateway", "add", "100.64.10.10"}, deps)
	if code != 0 {
		t.Fatalf("gateway add before install = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "added 100.64.10.10/32") {
		t.Errorf("stdout = %q, want added prefix", stdout)
	}
	if !strings.Contains(stderr, "warning: twarp is not installed yet") {
		t.Errorf("stderr = %q, want not-installed warning", stderr)
	}
}
