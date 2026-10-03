package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
)

func TestRunMigrateUsesHomeAndForce(t *testing.T) {
	temp := t.TempDir()
	userHome := filepath.Join(temp, "user")
	twarpHome := filepath.Join(temp, "twarp")
	if err := os.MkdirAll(userHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "internal", "migrate", "testdata", "warp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userHome, ".warp.yaml"), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(twarpHome, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{Home: twarpHome}
	if err := os.WriteFile(paths.ConfigFile(), []byte("old config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.CorpIPsFile(), []byte("old state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	t.Setenv("TWARP_HOME", twarpHome)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"migrate", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(migrate) = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for _, want := range []string{
		paths.ConfigFile(),
		paths.CorpIPsFile(),
		"8 CIDRs",
		"warning: host bits masked: 100.66.65.149/24 → 100.66.65.0/24",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
		}
	}
	if _, err := config.Load(paths.ConfigFile()); err != nil {
		t.Fatalf("Load(migrated config) error = %v", err)
	}
	stateText, err := os.ReadFile(paths.CorpIPsFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateText), "old state") {
		t.Fatalf("--force did not replace state: %q", stateText)
	}
}
