package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/geo"
)

func TestRunGeoRejectsNonRoot(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := runGeo([]string{"update"}, &stdout, &stderr, geoDeps{Sys: geoFakeSys{euid: 501}})
	if code != 1 {
		t.Fatalf("runGeo(update) = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "run with sudo: geo/ is owned by root") {
		t.Errorf("stderr = %q, want root ownership guidance", stderr.String())
	}
}

func TestRunGeoUpdateAsRootDownloadsFilesAndWritesAudit(t *testing.T) {
	t.Parallel()

	bodies := map[string]string{
		"/geoip":   "SRS-geoip",
		"/geosite": "SRS-geosite",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, ok := bodies[request.URL.Path]
		if !ok {
			http.NotFound(w, request)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	base := t.TempDir()
	out := filepath.Join(base, "out")
	logDir := filepath.Join(base, "log")
	system := geoFakeSys{
		euid: 0,
		env: map[string]string{
			"SUDO_USER":     "alice",
			"TWARP_HOME":    filepath.Join(base, "home"),
			"TWARP_OUT":     out,
			"TWARP_LOG_DIR": logDir,
		},
	}
	options := geo.Options{
		Sources: []geo.Source{
			{Name: "geoip-ru.srs", URL: server.URL + "/geoip"},
			{Name: "geosite-category-ru.srs", URL: server.URL + "/geosite"},
		},
		Client: server.Client(),
		Now:    func() time.Time { return time.Date(2026, time.October, 3, 12, 0, 0, 0, time.UTC) },
	}

	var stdout, stderr bytes.Buffer
	code := runGeo([]string{"update"}, &stdout, &stderr, geoDeps{Sys: system, Options: options})
	if code != 0 {
		t.Fatalf("runGeo(update) = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for path, body := range bodies {
		name := map[string]string{"/geoip": "geoip-ru.srs", "/geosite": "geosite-category-ru.srs"}[path]
		stored, err := os.ReadFile(filepath.Join(out, "geo", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(stored) != body {
			t.Errorf("%s contents = %q, want %q", name, stored, body)
		}
		wantOutput := fmt.Sprintf("updated %s: %d bytes, mtime ", name, len(body))
		if !strings.Contains(stdout.String(), wantOutput) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), wantOutput)
		}
	}
	audit, err := os.ReadFile(filepath.Join(logDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"op":"geo_update"`) || !strings.Contains(string(audit), `"result":"ok"`) {
		t.Errorf("audit = %q, want successful geo_update", audit)
	}
}

func TestRunGeoPrintsSuccessfulReportWhenAnotherSourceFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/good" {
			_, _ = w.Write([]byte("SRS-good"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	base := t.TempDir()
	system := geoFakeSys{
		euid: 0,
		env: map[string]string{
			"SUDO_USER":     "alice",
			"TWARP_HOME":    filepath.Join(base, "home"),
			"TWARP_OUT":     filepath.Join(base, "out"),
			"TWARP_LOG_DIR": filepath.Join(base, "log"),
		},
	}
	options := geo.Options{
		Sources: []geo.Source{
			{Name: "good.srs", URL: server.URL + "/good"},
			{Name: "bad.srs", URL: server.URL + "/bad"},
		},
		Client: server.Client(),
	}

	var stdout, stderr bytes.Buffer
	code := runGeo([]string{"update"}, &stdout, &stderr, geoDeps{Sys: system, Options: options})
	if code != 1 {
		t.Fatalf("runGeo(update) = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "updated good.srs: 8 bytes, mtime ") {
		t.Errorf("stdout = %q, want successful file report", stdout.String())
	}
	if !strings.Contains(stderr.String(), "HTTP status 500") {
		t.Errorf("stderr = %q, want failed source error", stderr.String())
	}
}

type geoFakeSys struct {
	euid int
	env  map[string]string
}

func (system geoFakeSys) Geteuid() int { return system.euid }

func (system geoFakeSys) Getenv(name string) string { return system.env[name] }

func (geoFakeSys) LookupUser(name string) (*user.User, error) {
	return nil, user.UnknownUserError(name)
}

func (geoFakeSys) Stat(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
