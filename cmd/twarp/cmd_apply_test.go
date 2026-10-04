package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/tiptop32/twarp/internal/fsutil"
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
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
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
	if got := filesystem.chowns; len(got) != 0 {
		t.Fatalf("path-based chowns = %#v, want none", got)
	}
	ruleSetPath := filepath.Join(fixture.out, "rules", "gateway-ip.json")
	if got, want := filesystem.ownedWrites, []cliChown{{ruleSetPath, 501, 20}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("owned writes = %#v, want %#v", got, want)
	}
	if info, err := os.Stat(ruleSetPath); err != nil {
		t.Fatalf("stat rule-set: %v", err)
	} else if info.Mode().Perm() != 0o644 {
		t.Fatalf("rule-set mode = %v, want 0644", info.Mode().Perm())
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
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = exited\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kickstart", "-k", "system/dev.twarp.singbox"}}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
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

func TestRunApplyKeepsDisabledServiceStopped(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	disabledOutput, err := os.ReadFile(filepath.Join("testdata", "print-disabled-system.txt"))
	if err != nil {
		t.Fatal(err)
	}
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", sysexec.SystemTarget()}}, Response: sysexec.Response{Err: errors.New("service not loaded")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print-disabled", "system"}}, Response: sysexec.Response{Output: disabledOutput}},
	}}
	fixture.deps.Runner = &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "stays stopped") {
		t.Fatalf("apply = (%d, %q, %q), want stopped success", code, stdout, stderr)
	}
	if err := runnerFake.Verify(); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(filepath.Join(fixture.deps.Sys.Getenv("TWARP_LOG_DIR"), "audit.jsonl"))
	if err != nil || !strings.Contains(string(audit), `"result":"stopped"`) {
		t.Fatalf("audit = %q, error = %v, want stopped record", audit, err)
	}
}

func TestRunApplyRejectsUninstalledService(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	configPath := filepath.Join(fixture.out, "config.json")
	installed := []byte("working config\n")
	if err := os.WriteFile(configPath, installed, 0o600); err != nil {
		t.Fatal(err)
	}
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", configPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: errors.New("service not found")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print-disabled", "system"}}, Response: sysexec.Response{Output: []byte(`"dev.twarp.singbox" => false`)}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: configPath}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "sing-box service is not installed; run: sudo twarp install") {
		t.Fatalf("apply = (%d, %q, %q), want not-installed error", code, stdout, stderr)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil || !reflect.DeepEqual(got, installed) {
		t.Fatalf("config after rejected apply = %q, error = %v, want %q", got, err, installed)
	}
	leftovers, err := filepath.Glob(filepath.Join(fixture.out, ".config.json.tmp-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("candidate files after rejected apply = %v, error = %v", leftovers, err)
	}
	if _, err := os.Stat(filepath.Join(fixture.out, "rules", "gateway-ip.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new gateway rule-set after rejected apply: stat error = %v, want not-exist", err)
	}
}

func TestRunApplyRejectsDisabledLabelWithoutInstalledPlist(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", sysexec.SystemTarget()}}, Response: sysexec.Response{Err: errors.New("service not loaded")}},
	}}
	fixture.deps.Runner = &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
	fixture.deps.FS = &cliFakeFS{stats: map[string]error{launchd.SingBoxPlistPath: os.ErrNotExist}}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "not installed") {
		t.Fatalf("apply = (%d, %q, %q), want not installed", code, stdout, stderr)
	}
	if err := runnerFake.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunApplyFailedCheckPreservesInstalledConfig(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	installed := []byte("working config\n")
	configPath := filepath.Join(fixture.out, "config.json")
	if err := os.WriteFile(configPath, installed, 0o600); err != nil {
		t.Fatal(err)
	}
	ruleSetPath := filepath.Join(fixture.out, "rules", "gateway-ip.json")
	if err := os.MkdirAll(filepath.Dir(ruleSetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousRuleSet := []byte("working rule-set\n")
	if err := os.WriteFile(ruleSetPath, previousRuleSet, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &rejectCandidateRunner{singBox: "/test/sing-box", installedPath: configPath}
	fixture.deps.Runner = runner
	fixture.deps.FS = &cliFakeFS{}

	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "candidate is invalid") {
		t.Fatalf("apply = (%d, %q, %q), want candidate check failure", code, stdout, stderr)
	}
	if !runner.checkedCandidate {
		t.Fatal("apply did not check a candidate config separate from config.json")
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(installed) {
		t.Fatalf("config.json = %q, want byte-identical %q", got, installed)
	}
	gotRules, err := os.ReadFile(ruleSetPath)
	if err != nil || !reflect.DeepEqual(gotRules, previousRuleSet) {
		t.Fatalf("gateway rule-set after failed check = %q, error = %v, want %q", gotRules, err, previousRuleSet)
	}
	leftovers, err := filepath.Glob(filepath.Join(fixture.out, ".config.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("candidate config was not removed: %v", leftovers)
	}
	if runner.serviceCalls != 0 {
		t.Fatalf("service calls after failed check = %d, want 0", runner.serviceCalls)
	}
}

func TestRunApplyFailedReloadRestoresInstalledFiles(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	configPath := filepath.Join(fixture.out, "config.json")
	ruleSetPath := filepath.Join(fixture.out, "rules", "gateway-ip.json")
	if err := os.MkdirAll(filepath.Dir(ruleSetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousConfig := []byte("working config\n")
	previousRules := []byte("working rules\n")
	if err := os.WriteFile(configPath, previousConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruleSetPath, previousRules, 0o644); err != nil {
		t.Fatal(err)
	}
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", configPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", sysexec.SystemTarget()}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", sysexec.SystemTarget()}}, Response: sysexec.Response{Err: errors.New("reload failed")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", sysexec.SystemTarget()}}},
	}}
	fixture.deps.Runner = &applyCandidateRunner{Fake: runnerFake, configPath: configPath}
	fixture.deps.FS = &cliFakeFS{}
	stdout, stderr, code := runCLIForTest([]string{"apply"}, fixture.deps)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "reload failed") {
		t.Fatalf("apply = (%d, %q, %q), want reload failure", code, stdout, stderr)
	}
	if err := runnerFake.Verify(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{configPath: previousConfig, ruleSetPath: previousRules} {
		got, err := os.ReadFile(path)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s after failed reload = %q, error = %v, want %q", path, got, err, want)
		}
	}
}

type rejectCandidateRunner struct {
	singBox          string
	installedPath    string
	checkedCandidate bool
	serviceCalls     int
}

type applyCandidateRunner struct {
	*sysexec.Fake
	configPath string
}

func (runner *applyCandidateRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "/test/sing-box" && len(args) == 3 && args[0] == "check" && args[1] == "-c" {
		candidatePath := args[2]
		if candidatePath == runner.configPath || filepath.Dir(candidatePath) != filepath.Dir(runner.configPath) || !strings.HasPrefix(filepath.Base(candidatePath), ".config.json.tmp-") {
			return nil, fmt.Errorf("check path %q is not a config candidate", candidatePath)
		}
		return runner.Fake.Run(ctx, name, "check", "-c", runner.configPath)
	}
	return runner.Fake.Run(ctx, name, args...)
}

func (runner *rejectCandidateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == runner.singBox && len(args) == 3 && args[0] == "check" && args[1] == "-c" {
		runner.checkedCandidate = args[2] != runner.installedPath &&
			filepath.Dir(args[2]) == filepath.Dir(runner.installedPath) &&
			strings.HasPrefix(filepath.Base(args[2]), ".config.json.tmp-")
		return nil, errors.New("candidate is invalid")
	}
	runner.serviceCalls++
	return nil, errors.New("unexpected service call")
}

func TestRunApplyDoesNotCreateFilesInHome(t *testing.T) {
	fixture := newCLIRenderFixture(t, 0)
	before := treeNames(t, fixture.home)
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
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
		File: filepath.Join(fixture.home, "gateway-ips.json"), LockFile: filepath.Join(fixture.home, "gateway-ips.lock"),
		AuditFile: filepath.Join(fixture.home, "audit.jsonl"), AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		GatewaySocks: netip.MustParseAddr("192.168.1.10"),
		OnChange:     func([]netip.Prefix) error { close(locked); <-release; return nil },
	})
	addDone := make(chan error, 1)
	go func() {
		_, err := store.Add(context.Background(), "cli", "100.64.11.1", "", false)
		addDone <- err
	}()
	<-locked

	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
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
	mu          sync.Mutex
	chowns      []cliChown
	ownedWrites []cliChown
	writes      []string
	removes     []string
	stats       map[string]error
	onWrite     func(string)
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
	if filesystem.onWrite != nil {
		filesystem.onWrite(path)
	}
	return nil
}
func (filesystem *cliFakeFS) WriteFileOwned(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	filesystem.mu.Lock()
	filesystem.ownedWrites = append(filesystem.ownedWrites, cliChown{path, uid, gid})
	filesystem.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomicOwned(path, data, mode, os.Getuid(), os.Getgid())
}
func (filesystem *cliFakeFS) WriteFileCandidate(path string, _ []byte, _ fs.FileMode) (string, error) {
	filesystem.writes = append(filesystem.writes, path+".candidate")
	if filesystem.onWrite != nil {
		filesystem.onWrite(path)
	}
	return path + ".candidate", nil
}
func (filesystem *cliFakeFS) PromoteFile(candidatePath, path string) error {
	filesystem.writes = append(filesystem.writes, candidatePath+" -> "+path)
	return nil
}
func (filesystem *cliFakeFS) Remove(path string) error {
	filesystem.removes = append(filesystem.removes, path)
	return nil
}
func (filesystem *cliFakeFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
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
	lockPath := filepath.Join(fixture.home, "gateway-ips.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runnerFake := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "/test/sing-box", Args: []string{"check", "-c", filepath.Join(fixture.out, "config.json")}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Output: []byte("state = running\n")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"kill", "SIGHUP", "system/dev.twarp.singbox"}}},
	}}
	runner := &applyCandidateRunner{Fake: runnerFake, configPath: filepath.Join(fixture.out, "config.json")}
	var lockedDuringWrite bool
	filesystem := &lockProbeFS{cliFakeFS: &cliFakeFS{}, onWriteFileOwned: func() {
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
		t.Fatal("apply released the state lock before the owned rule-set write")
	}
}

type lockProbeFS struct {
	*cliFakeFS
	onWriteFileOwned func()
}

func (filesystem *lockProbeFS) WriteFileOwned(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	filesystem.onWriteFileOwned()
	return filesystem.cliFakeFS.WriteFileOwned(path, data, mode, uid, gid)
}
