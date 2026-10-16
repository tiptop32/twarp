package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenUserFileGuard(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "twarp.yaml")
	if err := os.WriteFile(regular, []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.yaml")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without the guard every path opens like os.Open, symlinks included.
	if data, err := ReadUserFile(link, 1024); err != nil || string(data) != "gateway: {}\n" {
		t.Fatalf("unguarded read = (%q, %v)", data, err)
	}

	GuardUserFiles(os.Getuid())
	t.Cleanup(func() { GuardUserFiles(-1) })
	if data, err := ReadUserFile(regular, 1024); err != nil || string(data) != "gateway: {}\n" {
		t.Fatalf("guarded read of own file = (%q, %v)", data, err)
	}
	for path, want := range map[string]string{
		link: "is a symlink",
		fifo: "not a regular file",
	} {
		if _, err := OpenUserFile(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("OpenUserFile(%s) error = %v, want %q", filepath.Base(path), err, want)
		}
	}
	if _, err := OpenUserFile(filepath.Join(directory, "missing")); !os.IsNotExist(err) {
		t.Errorf("missing file error = %v, want not exist", err)
	}
	if _, err := ReadUserFile(regular, 4); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized read error = %v", err)
	}

	GuardUserFiles(os.Getuid() + 1)
	if _, err := OpenUserFile(regular); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("file of another owner error = %v", err)
	}
}

func TestLockExclusiveSerializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".apply.lock")
	release, err := LockExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		second, err := LockExclusive(path)
		if err != nil {
			t.Error(err)
			close(acquired)
			return
		}
		acquired <- second
	}()
	select {
	case <-acquired:
		t.Fatal("second lock acquired while the first is held")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case second := <-acquired:
		second()
	case <-time.After(2 * time.Second):
		t.Fatal("second lock never acquired")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file = (%v, %v), want mode 0600", info, err)
	}
}

func TestTrustedExecutable(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "twarp")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustedExecutable(binary, os.Getuid()); err != nil {
		t.Fatalf("own binary refused: %v", err)
	}
	if err := os.Chmod(binary, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustedExecutable(binary, os.Getuid()); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("group-writable binary error = %v", err)
	}
}
