package launchd_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/launchd"
)

var update = flag.Bool("update", false, "update golden files")

func TestSingBoxPlistGolden(t *testing.T) {
	t.Parallel()

	got, err := launchd.SingBoxPlist(config.Paths{
		Out:     "/usr/local/etc/twarp",
		SingBox: "/opt/homebrew/opt/sing-box/bin/sing-box",
	})
	if err != nil {
		t.Fatalf("SingBoxPlist() error = %v", err)
	}
	assertGolden(t, "dev.twarp.singbox.plist", got)
}

func TestGeoPlistGolden(t *testing.T) {
	t.Parallel()

	got, err := launchd.GeoPlist("/usr/local/bin/twarp", "/usr/local/etc/twarp")
	if err != nil {
		t.Fatalf("GeoPlist() error = %v", err)
	}
	assertGolden(t, "dev.twarp.geo.plist", got)
}

func TestDaemonPlistGolden(t *testing.T) {
	t.Parallel()

	got, err := launchd.DaemonPlist("/usr/local/bin/twarp", "/usr/local/etc/twarp", launchd.Owner{UID: 501, GID: 20, User: "alice"})
	if err != nil {
		t.Fatalf("DaemonPlist() error = %v", err)
	}
	assertGolden(t, "dev.twarp.daemon.plist", got)
}

func TestDaemonPlistRejectsBadInput(t *testing.T) {
	t.Parallel()

	for name, call := range map[string]func() ([]byte, error){
		"relative executable": func() ([]byte, error) {
			return launchd.DaemonPlist("twarp", "/usr/local/etc/twarp", launchd.Owner{UID: 501, GID: 20, User: "alice"})
		},
		"root owner": func() ([]byte, error) {
			return launchd.DaemonPlist("/usr/local/bin/twarp", "/usr/local/etc/twarp", launchd.Owner{UID: 0, GID: 0, User: "root"})
		},
		"no owner name": func() ([]byte, error) {
			return launchd.DaemonPlist("/usr/local/bin/twarp", "/usr/local/etc/twarp", launchd.Owner{UID: 501, GID: 20})
		},
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s: DaemonPlist() error = nil", name)
		}
	}
}

func TestGeoPlistPassesCustomOutputDirectory(t *testing.T) {
	t.Parallel()
	got, err := launchd.GeoPlist("/usr/local/bin/twarp", "/tmp/twarp-custom")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("<key>TWARP_OUT</key>\n    <string>/tmp/twarp-custom</string>")) {
		t.Fatalf("geo plist does not pass custom output directory: %s", got)
	}
}

func TestNewsyslogConfigGolden(t *testing.T) {
	t.Parallel()

	assertGolden(t, "twarp.newsyslog.conf", launchd.NewsyslogConfig())
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden %q: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %q: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("generated %s:\n%s\nwant:\n%s", name, got, want)
	}
}
