package state

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestStoreAddRemoveList(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 17, 40, 0, 0, time.UTC)
	var changes [][]netip.Prefix
	store := New(testOptions(dir, func(cidrs []netip.Prefix) error {
		changes = append(changes, append([]netip.Prefix(nil), cidrs...))
		return nil
	}, func() bool { return true }, func() time.Time { return now }))

	added, err := store.Add(context.Background(), "cli", "100.66.84.182", "new VM", false)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if added.Status != AddStatusAdded || added.CIDR != netip.MustParsePrefix("100.66.84.182/32") || !added.SingBoxRunning {
		t.Fatalf("Add() = %#v", added)
	}

	duplicate, err := store.Add(context.Background(), "mcp", "100.66.84.182/32", "ignored", false)
	if err != nil {
		t.Fatalf("duplicate Add() error = %v", err)
	}
	if duplicate.Status != AddStatusAlreadyPresent || duplicate.CIDR != added.CIDR {
		t.Fatalf("duplicate Add() = %#v", duplicate)
	}

	wide, err := store.Add(context.Background(), "cli", "100.66.85.149/24", "team subnet", false)
	if err != nil {
		t.Fatalf("wide Add() error = %v", err)
	}
	if wide.Status != AddStatusAdded || wide.CIDR != netip.MustParsePrefix("100.66.85.0/24") {
		t.Fatalf("wide Add() = %#v", wide)
	}
	if want := []string{"host bits masked: 100.66.85.149/24 → 100.66.85.0/24"}; !reflect.DeepEqual(wide.Warnings, want) {
		t.Fatalf("wide Add() warnings = %q, want %q", wide.Warnings, want)
	}

	covered, err := store.Add(context.Background(), "mcp", "100.66.85.12", "covered host", false)
	if err != nil {
		t.Fatalf("covered Add() error = %v", err)
	}
	if covered.Status != AddStatusCoveredBy || covered.CoveredBy != wide.CIDR {
		t.Fatalf("covered Add() = %#v", covered)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	wantEntries := []Entry{
		{CIDR: netip.MustParsePrefix("100.66.84.182/32"), Comment: "new VM", AddedBy: "cli", AddedAt: now},
		{CIDR: netip.MustParsePrefix("100.66.85.0/24"), Comment: "team subnet", AddedBy: "cli", AddedAt: now},
	}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Fatalf("List() = %#v, want %#v", entries, wantEntries)
	}

	removed, err := store.Remove(context.Background(), "cli", "100.66.85.149/24")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if removed.Status != RemoveStatusRemoved || removed.CIDR != wide.CIDR || !removed.SingBoxRunning {
		t.Fatalf("Remove() = %#v", removed)
	}
	if want := []string{"host bits masked: 100.66.85.149/24 → 100.66.85.0/24"}; !reflect.DeepEqual(removed.Warnings, want) {
		t.Fatalf("Remove() warnings = %q, want %q", removed.Warnings, want)
	}

	missing, err := store.Remove(context.Background(), "mcp", "100.66.85.0/24")
	if err != nil {
		t.Fatalf("missing Remove() error = %v", err)
	}
	if missing.Status != RemoveStatusNotFound {
		t.Fatalf("missing Remove() = %#v", missing)
	}

	if len(changes) != 3 {
		t.Fatalf("OnChange calls = %d, want 3", len(changes))
	}
	if got := prefixStrings(changes[2]); !reflect.DeepEqual(got, []string{"100.66.84.182/32"}) {
		t.Fatalf("last OnChange prefixes = %v", got)
	}

	audit := readAudit(t, filepath.Join(dir, "audit.jsonl"))
	wantResults := []string{"added", "already_present", "added", "covered_by", "removed", "not_found"}
	if len(audit) != len(wantResults) {
		t.Fatalf("audit records = %d, want %d", len(audit), len(wantResults))
	}
	for i, want := range wantResults {
		if audit[i].Result != want {
			t.Errorf("audit[%d].result = %q, want %q", i, audit[i].Result, want)
		}
		if audit[i].TS != now {
			t.Errorf("audit[%d].ts = %s, want %s", i, audit[i].TS, now)
		}
	}
}

func TestStoreListSortsByAddressThenPrefixLength(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(testOptions(dir, nil, nil, nil))
	for _, input := range []string{"100.66.2.1", "100.66.1.0", "100.66.1.0/24"} {
		if _, err := store.Add(context.Background(), "cli", input, "", false); err != nil {
			t.Fatalf("Add(%q) error = %v", input, err)
		}
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	got := make([]string, len(entries))
	for i, entry := range entries {
		got[i] = entry.CIDR.String()
	}
	want := []string{"100.66.1.0/24", "100.66.1.0/32", "100.66.2.1/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %v, want %v", got, want)
	}
}

func TestStoreExactMatchWinsOverCoveringEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(testOptions(dir, nil, nil, nil))
	for _, input := range []string{"100.66.1.0/32", "100.66.1.0/24"} {
		if _, err := store.Add(context.Background(), "cli", input, "", false); err != nil {
			t.Fatalf("Add(%q) error = %v", input, err)
		}
	}
	result, err := store.Add(context.Background(), "cli", "100.66.1.0/32", "", false)
	if err != nil {
		t.Fatalf("duplicate Add() error = %v", err)
	}
	if result.Status != AddStatusAlreadyPresent {
		t.Fatalf("duplicate Add() status = %q, want %q", result.Status, AddStatusAlreadyPresent)
	}
}

func TestStoreRejectsEntryBeyondLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	entries := make([]Entry, 255)
	for i := range entries {
		entries[i] = Entry{
			CIDR:    netip.MustParsePrefix(fmt.Sprintf("100.66.%d.%d/32", i/256, i%256)),
			AddedBy: "cli",
			AddedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC),
		}
	}
	writeStateFixture(t, opts.File, diskState{Version: 1, CIDRs: entries})
	result, err := New(opts).Add(context.Background(), "mcp", "100.66.0.255/32", "256th", false)
	if err != nil {
		t.Fatalf("256th Add() error = %v", err)
	}
	if result.Status != AddStatusAdded {
		t.Fatalf("256th Add() status = %q, want %q", result.Status, AddStatusAdded)
	}
	original := mustReadFile(t, opts.File)

	_, err = New(opts).Add(context.Background(), "mcp", "100.66.1.0/32", "257th", false)
	if err == nil || !strings.Contains(err.Error(), "maximum 256 entries") {
		t.Fatalf("257th Add() error = %v, want maximum 256 entries", err)
	}
	if got := mustReadFile(t, opts.File); !reflect.DeepEqual(got, original) {
		t.Fatal("257th Add() changed state file")
	}
}

func TestStoreDoesNotOverwriteUnreadableState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "invalid JSON", data: []byte("{definitely-not-json\n")},
		{name: "unknown version", data: []byte(`{"version":2,"cidrs":[]}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			opts := testOptions(dir, nil, nil, nil)
			if err := os.WriteFile(opts.File, tt.data, 0o600); err != nil {
				t.Fatalf("write corrupt state: %v", err)
			}
			var onChangeCalls atomic.Int32
			opts.OnChange = func([]netip.Prefix) error {
				onChangeCalls.Add(1)
				return nil
			}

			_, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false)
			if err == nil || !strings.Contains(err.Error(), opts.File) {
				t.Fatalf("Add() error = %v, want path %q", err, opts.File)
			}
			if got := mustReadFile(t, opts.File); !reflect.DeepEqual(got, tt.data) {
				t.Fatalf("state changed: got %q, want %q", got, tt.data)
			}
			if got := onChangeCalls.Load(); got != 0 {
				t.Fatalf("OnChange calls = %d, want 0", got)
			}
		})
	}
}

func TestStoreRejectsUnsafePersistedEntryWithoutChangingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	original := []byte(`{"version":1,"cidrs":[{"comment":"missing CIDR","added_by":"cli","added_at":"2026-10-03T00:00:00Z"}]}`)
	if err := os.WriteFile(opts.File, original, 0o600); err != nil {
		t.Fatalf("write unsafe state: %v", err)
	}
	_, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false)
	if err == nil || !strings.Contains(err.Error(), opts.File) {
		t.Fatalf("Add() error = %v, want path %q", err, opts.File)
	}
	if got := mustReadFile(t, opts.File); !reflect.DeepEqual(got, original) {
		t.Fatalf("state changed: got %q, want %q", got, original)
	}
}

func TestStorePersistsStateBeforeOnChangeError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, func([]netip.Prefix) error { return errors.New("render failed") }, func() bool { return true }, nil)
	result, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false)
	if err == nil || !strings.Contains(err.Error(), "state saved but OnChange failed: render failed") {
		t.Fatalf("Add() error = %v", err)
	}
	if result.Status != AddStatusAdded {
		t.Fatalf("Add() result = %#v", result)
	}

	opts.OnChange = nil
	entries, err := New(opts).List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 || entries[0].CIDR.String() != "100.66.1.1/32" {
		t.Fatalf("persisted entries = %#v", entries)
	}
	audit := readAudit(t, opts.AuditFile)
	if len(audit) != 1 || audit[0].Result != "added" {
		t.Fatalf("audit after OnChange error = %#v", audit)
	}
}

func TestStoreAuditsRemoveAfterOnChangeError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, nil, func() bool { return true }, nil)
	if _, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false); err != nil {
		t.Fatalf("seed Add() error = %v", err)
	}
	opts.OnChange = func([]netip.Prefix) error { return errors.New("render failed") }
	result, err := New(opts).Remove(context.Background(), "cli", "100.66.1.1")
	if err == nil || !strings.Contains(err.Error(), "state saved but OnChange failed: render failed") {
		t.Fatalf("Remove() error = %v", err)
	}
	if result.Status != RemoveStatusRemoved || !result.SingBoxRunning {
		t.Fatalf("Remove() result = %#v", result)
	}

	opts.OnChange = nil
	entries, err := New(opts).List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("persisted entries = %#v, want empty", entries)
	}
	audit := readAudit(t, opts.AuditFile)
	if len(audit) != 2 || audit[1].Result != "removed" {
		t.Fatalf("audit after OnChange error = %#v", audit)
	}
}

func TestStoreWarnsWhenSingBoxIsNotRunning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result, err := New(testOptions(dir, nil, func() bool { return false }, nil)).Add(
		context.Background(), "cli", "100.66.1.1", "", false,
	)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if result.SingBoxRunning {
		t.Fatal("SingBoxRunning = true, want false")
	}
	if want := []string{"sing-box is not running"}; !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("warnings = %q, want %q", result.Warnings, want)
	}
}

func TestStoreRunsHealthCheckAfterUnlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	probeOpts := opts
	probeOpts.Running = func() bool { return true }
	probe := New(probeOpts)
	opts.Running = func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := probe.Add(ctx, "cli", "100.66.1.2", "health probe", false)
		return err == nil
	}

	result, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if !result.SingBoxRunning {
		t.Fatal("SingBoxRunning = false, health callback could not mutate through a separate Store")
	}
}

func TestStoreLockWaitHonorsContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, nil)
	lockFile, err := os.OpenFile(opts.LockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock: %v", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer func() {
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
			t.Errorf("unlock: %v", err)
		}
		if err := lockFile.Close(); err != nil {
			t.Errorf("close lock: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = New(opts).Add(ctx, "mcp", "100.66.1.1", "", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Add() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Add() returned after %s, want prompt context cancellation", elapsed)
	}
}

func TestStoreConcurrentAddsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	const workers = 20
	const perWorker = 5

	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			store := New(testOptions(dir, nil, nil, nil))
			<-start
			for offset := 0; offset < perWorker; offset++ {
				lastOctet := worker*perWorker + offset
				input := fmt.Sprintf("100.66.0.%d", lastOctet)
				if _, err := store.Add(context.Background(), "mcp", input, "concurrent", false); err != nil {
					errorsByWorker <- fmt.Errorf("Add(%s): %w", input, err)
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	opts := testOptions(dir, nil, nil, nil)
	entries, err := New(opts).List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != workers*perWorker {
		t.Fatalf("entries = %d, want %d", len(entries), workers*perWorker)
	}
	var state diskState
	if err := json.Unmarshal(mustReadFile(t, opts.File), &state); err != nil {
		t.Fatalf("final state is invalid JSON: %v", err)
	}
	if len(state.CIDRs) != workers*perWorker {
		t.Fatalf("state CIDRs = %d, want %d", len(state.CIDRs), workers*perWorker)
	}
	if audit := readAudit(t, opts.AuditFile); len(audit) != workers*perWorker {
		t.Fatalf("audit records = %d, want %d", len(audit), workers*perWorker)
	}
	for _, path := range []string{opts.File, opts.LockFile, opts.AuditFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", filepath.Base(path), got)
		}
	}
}

func testOptions(dir string, onChange func([]netip.Prefix) error, running func() bool, now func() time.Time) Options {
	return Options{
		File:          filepath.Join(dir, "corp-ips.json"),
		LockFile:      filepath.Join(dir, "corp-ips.lock"),
		AuditFile:     filepath.Join(dir, "audit.jsonl"),
		AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		CorpSocks:     netip.MustParseAddr("100.64.70.28"),
		OnChange:      onChange,
		Running:       running,
		Now:           now,
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		result[i] = prefix.String()
	}
	return result
}

func readAudit(t *testing.T, path string) []auditRecord {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close audit: %v", err)
		}
	}()

	var records []auditRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit: %v", err)
	}
	return records
}

func writeStateFixture(t *testing.T, path string, state diskState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write state fixture: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestStoreAuditsRejectedAdd(t *testing.T) {
	dir := t.TempDir()
	opts := testOptions(dir, nil, nil, func() time.Time { return time.Unix(0, 0) })
	store := New(opts)

	if _, err := store.Add(context.Background(), "mcp", "8.8.0.0/16", "agent attempt", false); err == nil {
		t.Fatal("Add(8.8.0.0/16) error = nil, want outside allowed ranges")
	}

	audit := readAudit(t, opts.AuditFile)
	if len(audit) != 1 {
		t.Fatalf("audit records = %d, want 1 rejected attempt", len(audit))
	}
	got := audit[0]
	if got.Actor != "mcp" || got.Op != "add" || got.Input != "8.8.0.0/16" || !strings.HasPrefix(got.Result, "rejected: ") {
		t.Fatalf("audit record = %#v, want rejected add by mcp", got)
	}
	if _, err := os.Stat(opts.File); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after rejected add: err = %v, want not exist", err)
	}
}
