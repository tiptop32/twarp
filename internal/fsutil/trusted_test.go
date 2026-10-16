package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustedPath(t *testing.T) {
	// the temp root may itself be writable by others without the sticky bit
	// on some hosts; build a private tree below a trusted parent instead
	base, err := os.MkdirTemp("", "twarp-trusted")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if _, err := TrustedPath(base, os.Getuid()); err != nil {
		t.Skipf("temp directory is not trusted on this host: %v", err)
	}

	binary := filepath.Join(base, "bin", "twarp")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := TrustedPath(link, os.Getuid())
	if err != nil {
		t.Fatalf("TrustedPath() = %v", err)
	}
	if want, _ := filepath.EvalSymlinks(binary); resolved != want {
		t.Fatalf("TrustedPath() = %q, want the resolved %q", resolved, want)
	}

	if err := os.Chmod(filepath.Dir(binary), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustedPath(binary, os.Getuid()); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("TrustedPath(world-writable dir) = %v, want refusal", err)
	}
	if err := os.Chmod(filepath.Dir(binary), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustedPath(binary, os.Getuid()); err != nil {
		t.Fatalf("TrustedPath(sticky dir) = %v, want allowed", err)
	}
}
