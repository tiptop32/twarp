package render_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tiptop32/twarp/internal/render"
)

func TestAtomicWritersPreserveDestinationWhenDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	tests := []struct {
		name   string
		target string
		write  func(string) error
	}{
		{
			name:   "config",
			target: "config.json",
			write: func(path string) error {
				return render.WriteConfig(path, []byte("replacement config\n"))
			},
		},
		{
			name:   "rule set",
			target: "gateway-ip.json",
			write: func(path string) error {
				return render.WriteRuleSet(filepath.Dir(path), testPrefixes())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, test.target)
			original := []byte("original bytes\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatalf("seed destination: %v", err)
			}
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatalf("make destination directory read-only: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(dir, 0o700); err != nil {
					t.Errorf("restore destination directory permissions: %v", err)
				}
			})

			if err := test.write(path); err == nil {
				t.Fatal("atomic writer error = nil, want read-only directory failure")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read destination after failed write: %v", err)
			}
			if !bytes.Equal(got, original) {
				t.Fatalf("destination after failed write = %q, want %q", got, original)
			}
			matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
			if err != nil {
				t.Fatalf("glob temporary files: %v", err)
			}
			if len(matches) != 0 {
				t.Fatalf("temporary files remain after failed write: %v", matches)
			}
		})
	}
}

func TestWriteRuleSetOwnedGivesOwnerBeforeRename(t *testing.T) {
	dir := t.TempDir()

	if err := render.WriteRuleSetOwned(dir, testPrefixes(), os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("WriteRuleSetOwned() error = %v", err)
	}
	path := filepath.Join(dir, "gateway-ip.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rule-set: %v", err)
	}
	if !strings.Contains(string(data), "100.64.") {
		t.Fatalf("rule-set = %q, want rendered prefixes", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat rule-set: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("rule-set mode = %04o, want 0644", mode)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if got := int(stat.Uid); got != os.Getuid() {
			t.Fatalf("rule-set owner uid = %d, want %d", got, os.Getuid())
		}
	}
}

// The MCP write stays unprivileged: it renders world-readable data without
// touching ownership, exactly like before the owned writer was introduced.
func TestWriteRuleSetStaysUnprivileged(t *testing.T) {
	dir := t.TempDir()

	if err := render.WriteRuleSet(dir, testPrefixes()); err != nil {
		t.Fatalf("WriteRuleSet() error = %v", err)
	}
	path := filepath.Join(dir, "gateway-ip.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat rule-set: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("rule-set mode = %04o, want 0644", mode)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		t.Fatalf("rule-set owner uid = %d, want the writing user %d", stat.Uid, os.Getuid())
	}
}

func TestWriteConfigReportsParentPathWhenParentIsAFile(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("regular file\n"), 0o600); err != nil {
		t.Fatalf("create parent file: %v", err)
	}
	path := filepath.Join(parent, "config.json")

	err := render.WriteConfig(path, []byte("config\n"))
	if err == nil {
		t.Fatal("WriteConfig() error = nil, want parent-is-file failure")
	}
	if !strings.Contains(err.Error(), parent) {
		t.Fatalf("WriteConfig() error = %q, want parent path %q", err, parent)
	}
}
