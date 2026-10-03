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
		GeoUpdate: func(context.Context) error {
			operations = append(operations, fsOperation{kind: "geo-update"})
			return nil
		},
		RenderConfig: func() ([]byte, error) {
			operations = append(operations, fsOperation{kind: "render"})
			return []byte("generated config\n"), nil
		},
		WriteRuleSet: func(dir string) error {
			operations = append(operations, fsOperation{kind: "write-rule-set", path: dir})
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
		{kind: "render"},
		{kind: "write", path: paths.OutConfig(), data: "generated config\n", mode: 0o600},
		{kind: "write-rule-set", path: paths.RulesDir()},
		{kind: "chown", path: filepath.Join(paths.RulesDir(), "gateway-ip.json"), uid: 501, gid: 20},
		{kind: "write", path: launchd.SingBoxPlistPath, data: string(fixture(t, "dev.twarp.singbox.plist")), mode: 0o644},
		{kind: "write", path: launchd.GeoPlistPath, data: string(fixture(t, "dev.twarp.geo.plist")), mode: 0o644},
		{kind: "write", path: launchd.NewsyslogPath, data: string(fixture(t, "twarp.newsyslog.conf")), mode: 0o644},
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
		{Call: sysexec.Call{Name: testSingBox, Args: []string{"check", "-c", "/usr/local/etc/twarp/config.json"}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.singbox"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.SingBoxPlistPath}}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootout", "system/dev.twarp.geo"}}, Response: sysexec.Response{Err: absent}},
		{Call: sysexec.Call{Name: "launchctl", Args: []string{"bootstrap", "system", launchd.GeoPlistPath}}},
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
	operations *([]fsOperation)
	statErrors map[string]error
	removeOnce bool
	removed    map[string]bool
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
	return nil
}

func (filesystem *fakeFS) Remove(path string) error {
	*filesystem.operations = append(*filesystem.operations, fsOperation{kind: "remove", path: path})
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
