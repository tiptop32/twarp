package launchd_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

const testSingBox = "/opt/homebrew/opt/sing-box/bin/sing-box"

func TestInstallPerformsSystemSetupInOrder(t *testing.T) {
	t.Parallel()

	paths := config.Paths{Home: "/Users/alice/.config/twarp", Out: "/usr/local/etc/twarp", SingBox: testSingBox}
	missing := &fs.PathError{Op: "stat", Path: filepath.Join(paths.GeoDir(), "geoip-ru.srs"), Err: os.ErrNotExist}
	operations := []fsOperation{}
	filesystem := &fakeFS{operations: &operations, statErrors: map[string]error{
		filepath.Join(paths.GeoDir(), "geoip-ru.srs"): missing,
	}}
	runner := &sysexec.Fake{Expect: successfulInstallCalls(t)}
	deps := launchd.Deps{
		Runner: runner,
		Sys: fakeSystem{euid: 0, env: map[string]string{
			"SUDO_UID": "501",
			"SUDO_GID": "20",
		}},
		FS: filesystem,
		Executable: func() (string, error) {
			return "/usr/local/bin/twarp", nil
		},
	}
	options := launchd.Options{
		Paths: paths,
		LockState: func() (func(), error) {
			operations = append(operations, fsOperation{kind: "lock-state"})
			return func() { operations = append(operations, fsOperation{kind: "unlock-state"}) }, nil
		},
		GeoUpdate: func(context.Context) error {
			operations = append(operations, fsOperation{kind: "geo-update"})
			return nil
		},
		RenderConfig: func() ([]byte, error) {
			operations = append(operations, fsOperation{kind: "render"})
			return []byte("generated config\n"), nil
		},
		WriteRuleSet: func(dir string, uid, gid int) error {
			operations = append(operations, fsOperation{kind: "write-rule-set", path: dir, uid: uid, gid: gid})
			return nil
		},
	}

	if err := launchd.Install(context.Background(), deps, options); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}

	want := []fsOperation{
		{kind: "mkdir", path: paths.RulesDir(), mode: 0o755},
		{kind: "mkdir", path: paths.GeoDir(), mode: 0o755},
		{kind: "mkdir", path: "/usr/local/var/log/twarp", mode: 0o755},
		{kind: "mkdir", path: "/usr/local/var/lib/twarp", mode: 0o755},
		{kind: "chown", path: paths.RulesDir(), uid: 501, gid: 20},
		{kind: "stat", path: filepath.Join(paths.GeoDir(), "geoip-ru.srs")},
		{kind: "geo-update"},
		{kind: "lock-state"},
		{kind: "read", path: filepath.Join(paths.RulesDir(), "gateway-ip.json")},
		{kind: "read", path: paths.OutConfig()},
		{kind: "render"},
		{kind: "stage", path: paths.OutConfig() + ".candidate", data: "generated config\n", mode: 0o600},
		{kind: "write-rule-set", path: paths.RulesDir(), uid: 501, gid: 20},
		{kind: "write", path: launchd.SingBoxPlistPath, data: string(fixture(t, "dev.twarp.singbox.plist")), mode: 0o644},
		{kind: "write", path: launchd.GeoPlistPath, data: string(fixture(t, "dev.twarp.geo.plist")), mode: 0o644},
		{kind: "write", path: launchd.NewsyslogPath, data: string(fixture(t, "twarp.newsyslog.conf")), mode: 0o644},
		{kind: "promote", path: paths.OutConfig(), data: paths.OutConfig() + ".candidate"},
		{kind: "unlock-state"},
	}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("filesystem operations = %#v\nwant %#v", operations, want)
	}
}

func TestInstallRefusesUnsafePreconditions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		system    fakeSystem
		expect    []sysexec.ExpectedCall
		wantError string
	}{
		{
			name:      "not root",
			system:    fakeSystem{euid: 501},
			wantError: "run with sudo",
		},
		{
			name:      "sudo owner missing",
			system:    fakeSystem{euid: 0},
			wantError: "run with sudo",
		},
		{
			name:   "sing-box too old",
			system: rootSystem(),
			expect: []sysexec.ExpectedCall{{
				Call:     sysexec.Call{Name: testSingBox, Args: []string{"version"}},
				Response: sysexec.Response{Output: []byte("sing-box version 1.13.9\n")},
			}},
			wantError: "too old",
		},
		{
			name:   "another VPN owns default route",
			system: rootSystem(),
			expect: []sysexec.ExpectedCall{
				{Call: sysexec.Call{Name: testSingBox, Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.0\n")}},
				{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: fixture(t, "route-utun-outline.txt")}},
				{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun7"}}, Response: sysexec.Response{Output: fixture(t, "ifconfig-utun-outline.txt")}},
			},
			wantError: "another VPN holds the default route; quit it first",
		},
		{
			name:   "brew service is loaded",
			system: rootSystem(),
			expect: []sysexec.ExpectedCall{
				{Call: sysexec.Call{Name: testSingBox, Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.0\n")}},
				{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: fixture(t, "route-en0.txt")}},
				{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/homebrew.mxcl.sing-box"}}},
			},
			wantError: "brew services sing-box is loaded; run: brew services stop sing-box",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			operations := []fsOperation{}
			runner := &sysexec.Fake{Expect: tt.expect}
			err := launchd.Install(context.Background(), launchd.Deps{
				Runner: runner,
				Sys:    tt.system,
				FS:     &fakeFS{operations: &operations},
				Executable: func() (string, error) {
					return "/usr/local/bin/twarp", nil
				},
			}, launchd.Options{Paths: installPaths()})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Install() error = %v, want containing %q", err, tt.wantError)
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
			if len(operations) != 0 {
				t.Fatalf("filesystem operations = %#v, want none", operations)
			}
		})
	}
}

func TestInstallFailedCheckPreservesInstalledConfigAndService(t *testing.T) {
	t.Parallel()

	paths := installPaths()
	installed := "working config\n"
	operations := []fsOperation{}
	filesystem := &fakeFS{
		operations: &operations,
		files: map[string]storedFile{
			paths.OutConfig(): {data: installed, mode: 0o600},
			filepath.Join(paths.RulesDir(), "gateway-ip.json"): {data: "working rule-set\n", mode: 0o644},
		},
	}
	notLoaded := errors.New("service not found")
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: testSingBox, Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.3\n")}},
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: fixture(t, "route-en0.txt")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "gui/501/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: testSingBox, Args: []string{"check", "-c", paths.OutConfig() + ".candidate"}}, Response: sysexec.Response{Err: errors.New("candidate is invalid")}},
	}}
	err := launchd.Install(context.Background(), launchd.Deps{
		Runner:     runner,
		Sys:        rootSystem(),
		FS:         filesystem,
		Executable: func() (string, error) { return "/usr/local/bin/twarp", nil },
	}, launchd.Options{
		Paths:        paths,
		LockState:    func() (func(), error) { return func() {}, nil },
		RenderConfig: func() ([]byte, error) { return []byte("invalid replacement\n"), nil },
		WriteRuleSet: func(dir string, uid, gid int) error {
			return filesystem.WriteFileOwned(filepath.Join(dir, "gateway-ip.json"), []byte("replacement rule-set\n"), 0o644, uid, gid)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "candidate is invalid") {
		t.Fatalf("Install() error = %v, want candidate check failure", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if got := filesystem.files[paths.OutConfig()]; got.data != installed || got.mode != 0o600 {
		t.Fatalf("config.json = %#v, want byte-identical installed config", got)
	}
	if got := filesystem.files[filepath.Join(paths.RulesDir(), "gateway-ip.json")]; got.data != "working rule-set\n" {
		t.Fatalf("gateway rule-set after failed check = %#v, want previous content", got)
	}
	if _, exists := filesystem.files[paths.OutConfig()+".candidate"]; exists {
		t.Fatal("candidate config was not removed after failed check")
	}
}

func TestInstallFileFailureKeepsRunningServiceAndConfig(t *testing.T) {
	t.Parallel()

	paths := installPaths()
	operations := []fsOperation{}
	installed := storedFile{data: "working config\n", mode: 0o600}
	filesystem := &fakeFS{
		operations:  &operations,
		writeErrors: map[string]error{launchd.GeoPlistPath: errors.New("disk full")},
		files:       map[string]storedFile{paths.OutConfig(): installed},
	}
	runner := &sysexec.Fake{Expect: successfulInstallCalls(t)[:5]}
	err := launchd.Install(context.Background(), launchd.Deps{
		Runner:     runner,
		Sys:        rootSystem(),
		FS:         filesystem,
		Executable: func() (string, error) { return "/usr/local/bin/twarp", nil },
	}, launchd.Options{
		Paths:        paths,
		LockState:    func() (func(), error) { return func() {}, nil },
		RenderConfig: func() ([]byte, error) { return []byte("replacement\n"), nil },
		WriteRuleSet: func(string, int, int) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "write geo plist: disk full") {
		t.Fatalf("Install() error = %v, want geo plist write failure", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if got := filesystem.files[paths.OutConfig()]; got != installed {
		t.Fatalf("config after failed install = %#v, want %#v", got, installed)
	}
	if _, exists := filesystem.files[paths.OutConfig()+".candidate"]; exists {
		t.Fatal("candidate config was not removed")
	}
}

func TestInstallGeoServiceFailureKeepsSingBoxRunning(t *testing.T) {
	t.Parallel()

	paths := installPaths()
	ruleSetPath := filepath.Join(paths.RulesDir(), "gateway-ip.json")
	operations := []fsOperation{}
	installedConfig := storedFile{data: "working config\n", mode: 0o600}
	installedRules := storedFile{data: "working rules\n", mode: 0o644}
	filesystem := &fakeFS{operations: &operations, files: map[string]storedFile{
		paths.OutConfig(): installedConfig, ruleSetPath: installedRules,
	}}
	calls := successfulInstallCalls(t)[:7]
	calls[6].Err = errors.New("geo bootstrap failed")
	runner := &sysexec.Fake{Expect: calls}
	err := launchd.Install(context.Background(), launchd.Deps{
		Runner:     runner,
		Sys:        rootSystem(),
		FS:         filesystem,
		Executable: func() (string, error) { return "/usr/local/bin/twarp", nil },
	}, launchd.Options{
		Paths:        paths,
		LockState:    func() (func(), error) { return func() {}, nil },
		RenderConfig: func() ([]byte, error) { return []byte("valid config\n"), nil },
		WriteRuleSet: func(string, int, int) error {
			return filesystem.WriteFileOwned(ruleSetPath, []byte("replacement rules\n"), 0o644, 501, 20)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "load geo service: geo bootstrap failed") {
		t.Fatalf("Install() error = %v, want geo bootstrap failure", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if got := filesystem.files[paths.OutConfig()]; got != installedConfig {
		t.Errorf("config after geo failure = %#v, want %#v", got, installedConfig)
	}
	if got := filesystem.files[ruleSetPath]; got != installedRules {
		t.Errorf("rule-set after geo failure = %#v, want %#v", got, installedRules)
	}
}

func TestInstallPromoteFailureRestoresInstalledFiles(t *testing.T) {
	t.Parallel()

	paths := installPaths()
	ruleSetPath := filepath.Join(paths.RulesDir(), "gateway-ip.json")
	operations := []fsOperation{}
	installedConfig := storedFile{data: "working config\n", mode: 0o600}
	installedRules := storedFile{data: "working rules\n", mode: 0o644}
	filesystem := &fakeFS{
		operations: &operations,
		promoteErr: errors.New("directory sync failed"),
		files:      map[string]storedFile{paths.OutConfig(): installedConfig, ruleSetPath: installedRules},
	}
	runner := &sysexec.Fake{Expect: successfulInstallCalls(t)[:5]}
	err := launchd.Install(context.Background(), launchd.Deps{
		Runner:     runner,
		Sys:        rootSystem(),
		FS:         filesystem,
		Executable: func() (string, error) { return "/usr/local/bin/twarp", nil },
	}, launchd.Options{
		Paths:        paths,
		LockState:    func() (func(), error) { return func() {}, nil },
		RenderConfig: func() ([]byte, error) { return []byte("replacement config\n"), nil },
		WriteRuleSet: func(string, int, int) error {
			return filesystem.WriteFileOwned(ruleSetPath, []byte("replacement rules\n"), 0o644, 501, 20)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "directory sync failed") {
		t.Fatalf("Install() error = %v, want promote failure", err)
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	if got := filesystem.files[paths.OutConfig()]; got != installedConfig {
		t.Errorf("config after failed promotion = %#v, want %#v", got, installedConfig)
	}
	if got := filesystem.files[ruleSetPath]; got != installedRules {
		t.Errorf("rule-set after failed promotion = %#v, want %#v", got, installedRules)
	}
}

func TestUninstallIsIdempotent(t *testing.T) {
	t.Parallel()

	absent := errors.New("launchctl bootout: No such process")
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
	}}
	operations := []fsOperation{}
	filesystem := &fakeFS{operations: &operations, removeOnce: true, removed: map[string]bool{}}
	deps := launchd.Deps{Runner: runner, Sys: rootSystem(), FS: filesystem}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := launchd.Uninstall(context.Background(), deps); err != nil {
			t.Fatalf("Uninstall() attempt %d error = %v", attempt, err)
		}
	}
	if err := runner.Verify(); err != nil {
		t.Fatal(err)
	}
	want := []fsOperation{
		{kind: "remove", path: launchd.SingBoxPlistPath},
		{kind: "remove", path: launchd.GeoPlistPath},
		{kind: "remove", path: launchd.NewsyslogPath},
		{kind: "remove", path: launchd.SingBoxPlistPath},
		{kind: "remove", path: launchd.GeoPlistPath},
		{kind: "remove", path: launchd.NewsyslogPath},
	}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("filesystem operations = %#v, want %#v", operations, want)
	}
}

func successfulInstallCalls(t *testing.T) []sysexec.ExpectedCall {
	t.Helper()
	absent := errors.New("launchctl: No such process")
	notLoaded := errors.New("launchctl print: service not found")
	return []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: testSingBox, Args: []string{"version"}}, Response: sysexec.Response{Output: []byte("sing-box version 1.14.3\n")}},
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: fixture(t, "route-en0.txt")}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "system/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"print", "gui/501/homebrew.mxcl.sing-box"}}, Response: sysexec.Response{Err: notLoaded}},
		{Call: sysexec.Call{Name: testSingBox, Args: []string{"check", "-c", "/usr/local/etc/twarp/config.json.candidate"}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.GeoPlistPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"enable", sysexec.SystemTarget()}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}},
	}
}

func installPaths() config.Paths {
	return config.Paths{Home: "/Users/alice/.config/twarp", Out: "/usr/local/etc/twarp", SingBox: testSingBox}
}

func rootSystem() fakeSystem {
	return fakeSystem{euid: 0, env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}}
}

type fakeSystem struct {
	euid int
	env  map[string]string
}

func (system fakeSystem) Geteuid() int                   { return system.euid }
func (system fakeSystem) Getenv(name string) string      { return system.env[name] }
func (fakeSystem) LookupUser(string) (*user.User, error) { return nil, user.UnknownUserError("unused") }
func (fakeSystem) Stat(string) (os.FileInfo, error)      { return nil, os.ErrNotExist }

type fsOperation struct {
	kind string
	path string
	data string
	mode fs.FileMode
	uid  int
	gid  int
}

type fakeFS struct {
	operations  *([]fsOperation)
	statErrors  map[string]error
	writeErrors map[string]error
	promoteErr  error
	removeOnce  bool
	removed     map[string]bool
	files       map[string]storedFile
}

type storedFile struct {
	data string
	mode fs.FileMode
}

func (filesystem *fakeFS) MkdirAll(path string, mode fs.FileMode) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "mkdir", path: path, mode: mode})
	return nil
}

func (filesystem *fakeFS) Chown(path string, uid, gid int) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "chown", path: path, uid: uid, gid: gid})
	return nil
}

func (filesystem *fakeFS) WriteFile(path string, data []byte, mode fs.FileMode) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "write", path: path, data: string(data), mode: mode})
	if err := filesystem.writeErrors[path]; err != nil {
		return err
	}
	if filesystem.files != nil {
		filesystem.files[path] = storedFile{data: string(data), mode: mode}
	}
	return nil
}

func (filesystem *fakeFS) WriteFileOwned(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "write", path: path, data: string(data), mode: mode, uid: uid, gid: gid})
	if filesystem.files != nil {
		filesystem.files[path] = storedFile{data: string(data), mode: mode}
	}
	return nil
}

func (filesystem *fakeFS) ReadFile(path string) ([]byte, error) {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "read", path: path})
	file, ok := filesystem.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(file.data), nil
}

func (filesystem *fakeFS) WriteFileCandidate(path string, data []byte, mode fs.FileMode) (string, error) {
	candidatePath := path + ".candidate"
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "stage", path: candidatePath, data: string(data), mode: mode})
	if filesystem.files != nil {
		filesystem.files[candidatePath] = storedFile{data: string(data), mode: mode}
	}
	return candidatePath, nil
}

func (filesystem *fakeFS) PromoteFile(candidatePath, path string) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "promote", path: path, data: candidatePath})
	if filesystem.files != nil {
		filesystem.files[path] = filesystem.files[candidatePath]
		delete(filesystem.files, candidatePath)
	}
	return filesystem.promoteErr
}

func (filesystem *fakeFS) Remove(path string) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "remove", path: path})
	delete(filesystem.files, path)
	if filesystem.removeOnce && filesystem.removed[path] {
		return os.ErrNotExist
	}
	if filesystem.removeOnce {
		filesystem.removed[path] = true
	}
	return nil
}

func (filesystem *fakeFS) Stat(path string) (os.FileInfo, error) {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "stat", path: path})
	if err := filesystem.statErrors[path]; err != nil {
		return nil, err
	}
	return fileInfo{name: filepath.Base(path)}, nil
}

type fileInfo struct{ name string }

func (info fileInfo) Name() string  { return info.name }
func (fileInfo) Size() int64        { return 1 }
func (fileInfo) Mode() fs.FileMode  { return 0o644 }
func (fileInfo) ModTime() time.Time { return time.Time{} }
func (fileInfo) IsDir() bool        { return false }
func (fileInfo) Sys() any           { return nil }

var _ config.Sys = fakeSystem{}
var _ launchd.FS = (*fakeFS)(nil)

// os.WriteFile keeps the mode of an existing file, which would leave a
// previously world-readable config.json (VLESS keys, Clash secret) readable.
func TestOSFSWriteFileEnforcesModeOnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (launchd.OSFS{}).WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
	if data, _ := os.ReadFile(path); string(data) != "new" {
		t.Fatalf("content = %q, want new", data)
	}
}

func TestOSFSCandidatePromotionKeepsInstalledConfigUntilPromote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	installed := []byte("working config\n")
	if err := os.WriteFile(path, installed, 0o644); err != nil {
		t.Fatal(err)
	}
	filesystem := launchd.OSFS{}
	candidatePath, err := filesystem.WriteFileCandidate(path, []byte("checked config\n"), 0o600)
	if err != nil {
		t.Fatalf("WriteFileCandidate() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(candidatePath) })

	if data, err := os.ReadFile(path); err != nil || string(data) != string(installed) {
		t.Fatalf("config before promotion = %q, error = %v, want %q", data, err, installed)
	}
	if info, err := os.Stat(candidatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("candidate mode = %v, error = %v, want 0600", info.Mode().Perm(), err)
	}
	if err := filesystem.PromoteFile(candidatePath, path); err != nil {
		t.Fatalf("PromoteFile() error = %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "checked config\n" {
		t.Fatalf("promoted config = %q, error = %v, want checked config", data, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("promoted mode = %v, error = %v, want 0600", info.Mode().Perm(), err)
	}
}
