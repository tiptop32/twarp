package state

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStorePersistsStateWhenAuditCannotBeOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	stateDir := t.TempDir()
	auditDir := t.TempDir()
	opts := testOptions(stateDir, nil, nil, nil)
	opts.AuditFile = filepath.Join(auditDir, "audit.jsonl")
	if err := os.Chmod(auditDir, 0o500); err != nil {
		t.Fatalf("make audit directory read-only: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(auditDir, 0o700); err != nil {
			t.Errorf("restore audit directory permissions: %v", err)
		}
	})

	result, err := New(opts).Add(context.Background(), "cli", "100.64.11.1", "", false)
	if err == nil || !strings.Contains(err.Error(), "append audit") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Add() error = %v, want joined audit permission error", err)
	}
	if result.Status != AddStatusAdded {
		t.Fatalf("Add() result = %#v, want added state despite audit failure", result)
	}
	entries, listErr := New(opts).List()
	if listErr != nil {
		t.Fatalf("List() after audit failure error = %v", listErr)
	}
	if len(entries) != 1 || entries[0].CIDR != netip.MustParsePrefix("100.64.11.1/32") {
		t.Fatalf("entries after audit failure = %#v, want persisted prefix", entries)
	}
}

func TestStoreWriteFailurePreservesStateAndSkipsOnChange(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	if _, err := New(opts).Add(context.Background(), "cli", "100.64.11.1", "seed", false); err != nil {
		t.Fatalf("seed Add() error = %v", err)
	}
	original := mustReadFile(t, opts.File)
	var onChangeCalls atomic.Int32
	opts.OnChange = func([]netip.Prefix) error {
		onChangeCalls.Add(1)
		return nil
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make state directory read-only: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore state directory permissions: %v", err)
		}
	})

	_, err := New(opts).Add(context.Background(), "cli", "100.64.11.2", "new", false)
	if err == nil || !strings.Contains(err.Error(), "write state") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Add() error = %v, want temporary state permission error", err)
	}
	if got := mustReadFile(t, opts.File); !bytes.Equal(got, original) {
		t.Fatalf("state after failed write = %q, want original %q", got, original)
	}
	if got := onChangeCalls.Load(); got != 0 {
		t.Fatalf("OnChange calls = %d, want 0 after failed state write", got)
	}
	matches, globErr := filepath.Glob(filepath.Join(dir, ".gateway-ips.json.tmp-*"))
	if globErr != nil {
		t.Fatalf("glob temporary state files: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary state files remain after failed write: %v", matches)
	}
}

func TestStoreReportsOpenLockWhenParentDirectoryIsMissing(t *testing.T) {
	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	opts.LockFile = filepath.Join(dir, "missing", "gateway-ips.lock")

	_, err := New(opts).Add(context.Background(), "cli", "100.64.11.1", "", false)
	if err == nil || !strings.Contains(err.Error(), "open lock") || !strings.Contains(err.Error(), opts.LockFile) {
		t.Fatalf("Add() error = %v, want open lock error with path %q", err, opts.LockFile)
	}
}
