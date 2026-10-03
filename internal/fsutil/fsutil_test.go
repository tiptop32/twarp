package fsutil_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tiptop32/twarp/internal/fsutil"
)

func TestWriteFileAtomicReplacesContentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	if err := fsutil.WriteFileAtomic(path, []byte("new\n"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(got, []byte("new\n")) {
		t.Fatalf("destination = %q, want %q", got, "new\n")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("destination mode = %04o, want 0600", mode)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestWriteFileAtomicFailsWhenDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.json")
	if err := fsutil.WriteFileAtomic(path, []byte("data\n"), 0o600); err == nil {
		t.Fatal("WriteFileAtomic() error = nil, want missing directory failure")
	}
}

func TestAppendJSONLineAppendsOwnerOnlyRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, op := range []string{"first", "second"} {
		if err := fsutil.AppendJSONLine(path, map[string]string{"op": op}); err != nil {
			t.Fatalf("AppendJSONLine(%s) error = %v", op, err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	want := "{\"op\":\"first\"}\n{\"op\":\"second\"}\n"
	if string(got) != want {
		t.Fatalf("audit = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("audit mode = %04o, want 0600", mode)
	}
}
