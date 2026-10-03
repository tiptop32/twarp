package state

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadPrefixesWithoutLockDoesNotCreateFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stateFile := filepath.Join(dir, "gateway-ips.json")
	lockFile := filepath.Join(dir, "gateway-ips.lock")
	prefixes, err := ReadPrefixes(stateFile, lockFile)
	if err != nil {
		t.Fatalf("ReadPrefixes() error = %v", err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("ReadPrefixes() = %v, want empty", prefixes)
	}
	if _, err := os.Stat(lockFile); !os.IsNotExist(err) {
		t.Fatalf("lock file stat error = %v, want not exist", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("directory entries = %v, error = %v, want empty", entries, err)
	}
}

func TestReadPrefixesValidatesState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stateFile := filepath.Join(dir, "gateway-ips.json")
	if err := os.WriteFile(stateFile, []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadPrefixes(stateFile, filepath.Join(dir, "gateway-ips.lock"))
	if err == nil || !strings.Contains(err.Error(), "decode state") {
		t.Fatalf("ReadPrefixes() error = %v, want decode state error", err)
	}
}

func TestReadPrefixesWaitsForStoreExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	locked := make(chan struct{})
	release := make(chan struct{})
	opts.OnChange = func([]netip.Prefix) error {
		close(locked)
		<-release
		return nil
	}
	addDone := make(chan error, 1)
	go func() {
		_, err := New(opts).Add(context.Background(), "cli", "100.64.11.1", "", false)
		addDone <- err
	}()
	<-locked

	readDone := make(chan error, 1)
	go func() {
		_, err := ReadPrefixes(opts.File, opts.LockFile)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		t.Fatalf("ReadPrefixes() completed while LOCK_EX was held: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-addDone; err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("ReadPrefixes() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPrefixes() remained blocked after LOCK_EX was released")
	}
}

func TestLockSharedDoesNotCreateMissingLockFile(t *testing.T) {
	lockFile := filepath.Join(t.TempDir(), "gateway-ips.lock")
	release, err := LockShared(lockFile)
	if err != nil {
		t.Fatalf("LockShared() error = %v", err)
	}
	release()
	if _, err := os.Stat(lockFile); !os.IsNotExist(err) {
		t.Fatalf("lock file stat err = %v, want it not to be created", err)
	}
}
