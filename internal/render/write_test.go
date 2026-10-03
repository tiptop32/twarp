package render_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
