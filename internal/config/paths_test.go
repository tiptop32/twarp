package config_test

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/config"
)

const (
	armSingBox   = "/opt/homebrew/opt/sing-box/bin/sing-box"
	intelSingBox = "/usr/local/opt/sing-box/bin/sing-box"
)

func TestResolveUsesEnvironmentOverrides(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	out := t.TempDir()
	singBox := filepath.Join(t.TempDir(), "sing-box")
	system := fakeSys{
		euid: 501,
		env: map[string]string{
			"TWARP_HOME":    home,
			"TWARP_OUT":     out,
			"TWARP_SINGBOX": singBox,
		},
	}

	got, err := config.Resolve(system)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	want := config.Paths{Home: home, Out: out, SingBox: singBox}
	if got != want {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestResolveBuildsDefaultPathsForRegularUser(t *testing.T) {
	t.Parallel()

	system := fakeSys{
		euid:     501,
		env:      map[string]string{"HOME": "/Users/alice"},
		existing: map[string]bool{intelSingBox: true},
	}

	got, err := config.Resolve(system)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Home != "/Users/alice/.config/twarp" {
		t.Errorf("Home = %q, want regular user's config directory", got.Home)
	}
	if got.Out != "/usr/local/etc/twarp" {
		t.Errorf("Out = %q, want default output directory", got.Out)
	}
	if got.SingBox != intelSingBox {
		t.Errorf("SingBox = %q, want second existing candidate", got.SingBox)
	}
}

func TestResolveUsesSudoUsersHomeForRoot(t *testing.T) {
	t.Parallel()

	system := fakeSys{
		euid:  0,
		env:   map[string]string{"HOME": "/var/root", "SUDO_USER": "alice"},
		users: map[string]*user.User{"alice": {Username: "alice", HomeDir: "/Users/alice"}},
	}

	got, err := config.Resolve(system)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Home != "/Users/alice/.config/twarp" {
		t.Fatalf("Home = %q, want sudo user's config directory", got.Home)
	}
}

func TestResolveRejectsRootWithoutSudoUser(t *testing.T) {
	t.Parallel()

	for _, env := range []map[string]string{
		{"HOME": "/var/root"},
		{"HOME": "/var/root", "TWARP_HOME": "/tmp/twarp-test-home"},
	} {
		_, err := config.Resolve(fakeSys{euid: 0, env: env})
		if err == nil {
			t.Fatalf("Resolve() with env %v error = nil, want SUDO_USER error", env)
		}
		const want = "run via sudo from your user account; SUDO_USER is empty"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Resolve() error = %q, want it to contain %q", err, want)
		}
	}
}

func TestResolvePrefersFirstSingBoxCandidateAndAllowsMissingBinary(t *testing.T) {
	t.Parallel()

	base := fakeSys{euid: 501, env: map[string]string{"HOME": "/Users/alice"}}
	withBoth := base
	withBoth.existing = map[string]bool{armSingBox: true, intelSingBox: true}

	got, err := config.Resolve(withBoth)
	if err != nil {
		t.Fatalf("Resolve() with candidates error = %v", err)
	}
	if got.SingBox != armSingBox {
		t.Fatalf("SingBox = %q, want first candidate %q", got.SingBox, armSingBox)
	}

	got, err = config.Resolve(base)
	if err != nil {
		t.Fatalf("Resolve() without candidates error = %v", err)
	}
	if got.SingBox != "" {
		t.Fatalf("SingBox = %q, want empty when no candidate exists", got.SingBox)
	}
}

func TestPathsHelpers(t *testing.T) {
	t.Parallel()

	paths := config.Paths{Home: "/home", Out: "/out"}
	got := []string{
		paths.ConfigFile(), paths.SecretsFile(), paths.CorpIPsFile(), paths.LockFile(), paths.AuditFile(),
		paths.OutConfig(), paths.RulesDir(), paths.GeoDir(),
	}
	want := []string{
		"/home/twarp.yaml", "/home/secrets.yaml", "/home/corp-ips.json", "/home/corp-ips.lock", "/home/audit.jsonl",
		"/out/config.json", "/out/rules", "/out/geo",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path helpers = %#v, want %#v", got, want)
	}
}

func TestSudoOwner(t *testing.T) {
	t.Parallel()

	uid, gid, ok := config.SudoOwner(fakeSys{env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}})
	if !ok || uid != 501 || gid != 20 {
		t.Fatalf("SudoOwner(valid) = (%d, %d, %t), want (501, 20, true)", uid, gid, ok)
	}
	for _, env := range []map[string]string{
		{},
		{"SUDO_UID": "bad", "SUDO_GID": "20"},
		{"SUDO_UID": "501", "SUDO_GID": "-1"},
	} {
		if _, _, ok := config.SudoOwner(fakeSys{env: env}); ok {
			t.Fatalf("SudoOwner(%v) ok = true, want false", env)
		}
	}
}

type fakeSys struct {
	euid     int
	env      map[string]string
	users    map[string]*user.User
	existing map[string]bool
}

func (system fakeSys) Geteuid() int { return system.euid }

func (system fakeSys) Getenv(name string) string { return system.env[name] }

func (system fakeSys) LookupUser(name string) (*user.User, error) {
	account, ok := system.users[name]
	if !ok {
		return nil, user.UnknownUserError(name)
	}
	return account, nil
}

func (system fakeSys) Stat(path string) (os.FileInfo, error) {
	if system.existing[path] {
		return fakeFileInfo{name: filepath.Base(path)}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
}

type fakeFileInfo struct{ name string }

func (info fakeFileInfo) Name() string  { return info.name }
func (fakeFileInfo) Size() int64        { return 1 }
func (fakeFileInfo) Mode() os.FileMode  { return 0o755 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }

var _ config.Sys = fakeSys{}
var _ os.FileInfo = fakeFileInfo{}
