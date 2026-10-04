package fsutil_test

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
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

func TestWriteFileAtomicOwnedSetsOwnerBeforeRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-ip.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	if err := fsutil.WriteFileAtomicOwned(path, []byte("new\n"), 0o644, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("WriteFileAtomicOwned() error = %v", err)
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
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("destination mode = %04o, want 0644", mode)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if got := int(stat.Uid); got != os.Getuid() {
			t.Fatalf("destination owner uid = %d, want %d", got, os.Getuid())
		}
		if got := int(stat.Gid); got != os.Getgid() {
			t.Fatalf("destination owner gid = %d, want %d", got, os.Getgid())
		}
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

// The ownership change must happen on the open temporary descriptor before
// the rename. A path-based chown after the rename would either fail and leave
// the new contents unowned or follow a symlink swapped into the destination.
func TestWriteFileAtomicOwnedKeepsDestinationWhenOwnerFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can give any owner to any file")
	}
	path := filepath.Join(t.TempDir(), "gateway-ip.json")
	original := []byte("old\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	err := fsutil.WriteFileAtomicOwned(path, []byte("new\n"), 0o644, os.Getuid()+1337, os.Getgid())
	if err == nil {
		t.Fatal("WriteFileAtomicOwned() error = nil, want unprivileged owner failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("destination after failed write = %q, want %q", got, original)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after failed write: %v", matches)
	}
}

// A privileged writer must replace a symlinked destination instead of
// following it: the rename swaps the link itself, and no chown ever touches
// the path, so the victim file keeps its contents and owner.
func TestWriteFileAtomicOwnedReplacesSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	path := filepath.Join(dir, "gateway-ip.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatalf("create symlink destination: %v", err)
	}

	if err := fsutil.WriteFileAtomicOwned(path, []byte("new\n"), 0o644, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("WriteFileAtomicOwned() error = %v", err)
	}
	victimData, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if !bytes.Equal(victimData, []byte("victim\n")) {
		t.Fatalf("victim = %q, want %q", victimData, "victim\n")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat destination: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("destination is still a symlink, want a regular file")
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
