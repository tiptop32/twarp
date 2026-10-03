package launchd_test

import (
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

	got, err := launchd.GeoPlist("/usr/local/bin/twarp")
	if err != nil {
		t.Fatalf("GeoPlist() error = %v", err)
	}
	assertGolden(t, "dev.twarp.geo.plist", got)
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
