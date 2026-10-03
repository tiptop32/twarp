package main

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestRunApplyRequiresRoot(t *testing.T) {
	stdout, stderr, code := runCLIForTest([]string{"apply"}, cliDeps{Sys: cliTestSys{euid: 501}})
	if code != 1 || stdout != "" || !strings.Contains(stderr, "run with sudo") {
		t.Fatalf("apply = (%d, %q, %q), want sudo error", code, stdout, stderr)
	}
}

func TestRunApplyChecksAndReloadsRunningService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	filesystem := &cliFakeFS{}
	fixture.deps.Runner = runner
	fixture.deps.FS = filesystem

	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "applied and reloaded") {
		t.Fatalf("apply = (%d, %q, %q), want reload success", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if got, want := filesystem.chowns, []cliChown{{filepath.Join(fixture.out, "rules", "corp-ip.json"), 501, 20}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("chowns = %#v, want %#v", got, want)
	}
	if info, err := os.Stat(filepath.Join(fixture.out, "config.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, error = %v, want 0600", info.Mode().Perm(), err)
	}
	audit, err := os.ReadFile(filepath.Join(fixture.deps.Sys.Getenv("TWARP_LOG_DIR"), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"actor":"cli"`, `"op":"apply"`, `"result":"reloaded"`} {
		if !strings.Contains(string(audit), want) {
			t.Errorf("audit = %s, want %s", audit, want)
		}
	}
}

func TestRunApplyKickstartsStoppedService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = exited\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kickstart", "-k", "system/dev.twarp.singbox"}}},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "applied and kickstarted") {
		t.Fatalf("apply = (%d, %q, %q), want kickstart success", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunApplyRejectsUninstalledService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: errors.New("service not found")}},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "sing-box service is not installed; run: sudo twarp install") {
		t.Fatalf("apply = (%d, %q, %q), want not-installed error", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunApplyDoesNotCreateFilesInHome(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	before := treeNames(t, fixture.home)
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	_, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 0 {
		t.Fatalf("apply = %d, stderr = %q", code, stderr)
	}
	after := treeNames(t, fixture.home)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("files in TWARP_HOME changed: before %v, after %v", before, after)
	}
}

func TestRunApplyWaitsForStoreExclusiveLock(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	locked := make(chan struct{})
	release := make(chan struct{})
	store := state.New(state.Options{
		File: filepath.Join(fixture.home, "corp-ips.json"), LockFile: filepath.Join(fixture.home, "corp-ips.lock"),
		AuditFile: filepath.Join(fixture.home, "audit.jsonl"), AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		CorpSocks: netip.MustParseAddr("192.168.0.105"),
		OnChange:  func([]netip.Prefix) error { close(locked); <-release; return nil },
	})
	addDone := make(chan error, 1)
	go func() {
		_, err := store.Add(context.Background(), "cli", "100.66.1.1", "", false)
		addDone <- err
	}()
	<-locked

	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	applyDone := make(chan int, 1)
	go func() {
		_, _, code := runCLIForTest([]string{"apply"}, fixture.deps)
		applyDone <- code
	}()
	select {
	case code := <-applyDone:
		t.Fatalf("apply completed with code %d while LOCK_EX was held", code)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-addDone; err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	select {
	case code := <-applyDone:
		if code != 0 {
			t.Fatalf("apply code = %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("apply remained blocked after LOCK_EX was released")
	}
}

func treeNames(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			names = append(names, relative)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return names
}

type cliChown struct {
	path     string
	uid, gid int
}

type cliFakeFS struct {
	mu      sync.Mutex
	chowns  []cliChown
	writes  []string
	removes []string
	stats   map[string]error
}

func (filesystem *cliFakeFS) MkdirAll(string, fs.FileMode) error { return nil }
func (filesystem *cliFakeFS) Chown(path string, uid, gid int) error {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	filesystem.chowns = append(filesystem.chowns, cliChown{path, uid, gid})
	return nil
}
func (filesystem *cliFakeFS) WriteFile(path string, _ []byte, _ fs.FileMode) error {
	filesystem.writes = append(filesystem.writes, path)
	return nil
}
func (filesystem *cliFakeFS) Remove(path string) error {
	filesystem.removes = append(filesystem.removes, path)
	return nil
}
func (filesystem *cliFakeFS) Stat(path string) (os.FileInfo, error) {
	if err := filesystem.stats[path]; err != nil {
		return nil, err
	}
	return cliFileInfo{}, nil
}

type cliFileInfo struct{}

func (cliFileInfo) Name() string       { return "file" }
func (cliFileInfo) Size() int64        { return 0 }
func (cliFileInfo) Mode() fs.FileMode  { return 0o644 }
func (cliFileInfo) ModTime() time.Time { return time.Time{} }
func (cliFileInfo) IsDir() bool        { return false }
func (cliFileInfo) Sys() any           { return nil }

var _ launchd.FS = (*cliFakeFS)(nil)
var _ config.Sys = cliTestSys{}

// apply must keep the shared lock until the rule-set is written; otherwise an
// MCP add between read and write is overwritten by the stale list.
func TestRunApplyHoldsLockWhileWritingRuleSet(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	lockPath := filepath.Join(fixture.home, "corp-ips.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	var lockedDuringWrite bool
	filesystem := &lockProbeFS{cliFakeFS: &cliFakeFS{}, onChown: func() {
		probe, err := os.Open(lockPath)
		if err != nil {
			t.Errorf("open lock: %v", err)
			return
		}
		defer func() { _ = probe.Close() }()
		err = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		lockedDuringWrite = errors.Is(err, syscall.EWOULDBLOCK)
		if err == nil {
			_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
		}
	}}
	fixture.deps.Runner = runner
	fixture.deps.FS = filesystem

	if _, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps); code != 0 {
		t.Fatalf("apply = %d, stderr = %q", code, stderr)
	}
	if !lockedDuringWrite {
		t.Fatal("apply released the state lock before the rule-set was written and chowned")
	}
}

type lockProbeFS struct {
	*cliFakeFS
	onChown func()
}

func (filesystem *lockProbeFS) Chown(path string, uid, gid int) error {
	filesystem.onChown()
	return filesystem.cliFakeFS.Chown(path, uid, gid)
}
