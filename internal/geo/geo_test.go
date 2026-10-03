package geo_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/geo"
)

func TestUpdateReplacesRuleSetAndReportsStoredMetadata(t *testing.T) {
	t.Parallel()

	want := []byte("SRS\x01new-rule-set")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(want)
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "geo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "geoip-ru.srs")
	if err := os.WriteFile(path, []byte("SRS-old"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := geo.Update(context.Background(), geo.Options{
		Dir:     dir,
		Sources: []geo.Source{{Name: "geoip-ru.srs", URL: server.URL}},
		Client:  server.Client(),
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("stored rule-set = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("stored mode = %04o, want 0644", info.Mode().Perm())
	}
	if len(report.Files) != 1 {
		t.Fatalf("report files = %#v, want one file", report.Files)
	}
	file := report.Files[0]
	if file.Name != "geoip-ru.srs" || file.Path != path {
		t.Errorf("report file identity = %#v, want name and path for stored rule-set", file)
	}
	if file.Size != int64(len(want)) {
		t.Errorf("report size = %d, want %d", file.Size, len(want))
	}
	if !file.ModTime.Equal(info.ModTime()) {
		t.Errorf("report mtime = %v, want stored mtime %v", file.ModTime, info.ModTime())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "geoip-ru.srs" {
		t.Fatalf("geo directory entries = %v, want only final rule-set", entries)
	}
}

func TestUpdateRejectsInvalidDownloadsWithoutTouchingExistingFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
		},
		{
			name: "500",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "abrupt response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("Hijack() error = %v", err)
					return
				}
				defer func() { _ = connection.Close() }()
				_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nSRS")
			},
		},
		{
			name:    "empty response",
			handler: func(http.ResponseWriter, *http.Request) {},
		},
		{
			name: "missing SRS magic",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "not-a-rule-set")
			},
		},
		{
			name: "larger than 32 MiB",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "SRS")
				_, _ = io.CopyN(w, zeroReader{}, 32<<20-2)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(test.handler)
			t.Cleanup(server.Close)
			dir := t.TempDir()
			path := filepath.Join(dir, "geoip-ru.srs")
			oldContents := []byte("SRS-old-rule-set")
			if err := os.WriteFile(path, oldContents, 0o644); err != nil {
				t.Fatal(err)
			}
			oldTime := time.Unix(1_700_000_000, 0)
			if err := os.Chtimes(path, oldTime, oldTime); err != nil {
				t.Fatal(err)
			}

			report, err := geo.Update(context.Background(), geo.Options{
				Dir:     dir,
				Sources: []geo.Source{{Name: "geoip-ru.srs", URL: server.URL}},
				Client:  server.Client(),
			})
			if err == nil {
				t.Fatal("Update() error = nil, want download rejection")
			}
			if len(report.Files) != 0 {
				t.Fatalf("report files = %#v, want no successful files", report.Files)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != string(oldContents) {
				t.Errorf("existing contents = %q, want %q", got, oldContents)
			}
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if !info.ModTime().Equal(oldTime) {
				t.Errorf("existing mtime = %v, want %v", info.ModTime(), oldTime)
			}
			entries, readDirErr := os.ReadDir(dir)
			if readDirErr != nil {
				t.Fatal(readDirErr)
			}
			if len(entries) != 1 || entries[0].Name() != "geoip-ru.srs" {
				t.Fatalf("geo directory entries = %v, want only existing rule-set", entries)
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestUpdateAppendsRootAuditResult(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2026, time.October, 3, 12, 34, 56, 0, time.UTC)
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantError  bool
		wantResult string
		wantFiles  []auditFile
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "SRS-valid")
			},
			wantResult: "ok",
			wantFiles:  []auditFile{{Name: "geoip-ru.srs", Size: 9}},
		},
		{
			name: "error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantError:  true,
			wantResult: "error: ",
			wantFiles:  []auditFile{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(test.handler)
			t.Cleanup(server.Close)
			base := t.TempDir()
			auditPath := filepath.Join(base, "log", "audit.jsonl")
			_, err := geo.Update(context.Background(), geo.Options{
				Dir:       filepath.Join(base, "geo"),
				Sources:   []geo.Source{{Name: "geoip-ru.srs", URL: server.URL}},
				Client:    server.Client(),
				AuditFile: auditPath,
				Now:       func() time.Time { return fixedTime },
			})
			if (err != nil) != test.wantError {
				t.Fatalf("Update() error = %v, wantError %t", err, test.wantError)
			}

			line, readErr := os.ReadFile(auditPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(line) == 0 || line[len(line)-1] != '\n' || strings.Count(string(line), "\n") != 1 {
				t.Fatalf("audit contents = %q, want one JSON line", line)
			}
			var entry auditEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatalf("decode audit line %q: %v", line, err)
			}
			if !entry.TS.Equal(fixedTime) || entry.Actor != "cli" || entry.Op != "geo_update" {
				t.Errorf("audit identity = %#v, want fixed time, cli, geo_update", entry)
			}
			if test.wantError {
				if !strings.HasPrefix(entry.Result, test.wantResult) || !strings.Contains(entry.Result, "HTTP status 500") {
					t.Errorf("audit result = %q, want error with HTTP status", entry.Result)
				}
			} else if entry.Result != test.wantResult {
				t.Errorf("audit result = %q, want %q", entry.Result, test.wantResult)
			}
			if len(entry.Files) != len(test.wantFiles) {
				t.Fatalf("audit files = %#v, want %#v", entry.Files, test.wantFiles)
			}
			for index := range test.wantFiles {
				if entry.Files[index] != test.wantFiles[index] {
					t.Errorf("audit file %d = %#v, want %#v", index, entry.Files[index], test.wantFiles[index])
				}
			}
			info, statErr := os.Stat(auditPath)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("audit mode = %04o, want 0600", info.Mode().Perm())
			}
			logInfo, statErr := os.Stat(filepath.Dir(auditPath))
			if statErr != nil {
				t.Fatal(statErr)
			}
			if logInfo.Mode().Perm() != 0o755 {
				t.Errorf("audit directory mode = %04o, want 0755", logInfo.Mode().Perm())
			}
		})
	}
}

func TestUpdateAuditsGeoDirectoryCreationFailure(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	dir := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(dir, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(base, "log", "audit.jsonl")
	_, err := geo.Update(context.Background(), geo.Options{
		Dir:       dir,
		Sources:   []geo.Source{},
		AuditFile: auditPath,
	})
	if err == nil {
		t.Fatal("Update() error = nil, want geo directory creation error")
	}
	line, readErr := os.ReadFile(auditPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var entry auditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("decode audit line %q: %v", line, err)
	}
	if !strings.HasPrefix(entry.Result, "error: ") || !strings.Contains(entry.Result, "create geo directory") {
		t.Fatalf("audit result = %q, want geo directory creation error", entry.Result)
	}
}

func TestUpdateReturnsSuccessfulFilesWhenAnotherSourceFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/good":
			_, _ = io.WriteString(w, "SRS-new-good")
		case "/bad":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.srs")
	if err := os.WriteFile(badPath, []byte("SRS-old-bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := geo.Update(context.Background(), geo.Options{
		Dir: dir,
		Sources: []geo.Source{
			{Name: "good.srs", URL: server.URL + "/good"},
			{Name: "bad.srs", URL: server.URL + "/bad"},
		},
		Client: server.Client(),
	})
	if err == nil {
		t.Fatal("Update() error = nil, want error for failed source")
	}
	if len(report.Files) != 1 || report.Files[0].Name != "good.srs" {
		t.Fatalf("report files = %#v, want only good.srs", report.Files)
	}
	good, readErr := os.ReadFile(filepath.Join(dir, "good.srs"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(good) != "SRS-new-good" {
		t.Errorf("good rule-set = %q, want updated contents", good)
	}
	bad, readErr := os.ReadFile(badPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(bad) != "SRS-old-bad" {
		t.Errorf("bad rule-set = %q, want old contents", bad)
	}
}

func TestUpdateTimeoutLeavesExistingFileUntouched(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip-ru.srs")
	if err := os.WriteFile(path, []byte("SRS-old"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := geo.Update(context.Background(), geo.Options{
		Dir:     dir,
		Sources: []geo.Source{{Name: "geoip-ru.srs", URL: server.URL}},
		Client:  server.Client(),
		Timeout: 25 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Update() error = nil, want timeout")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "SRS-old" {
		t.Fatalf("existing rule-set = %q, want untouched contents", got)
	}
}

func TestUpdateAcceptsRuleSetCompiledBySingBox(t *testing.T) {
	t.Parallel()

	binary, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box is not installed")
	}
	compileDir := t.TempDir()
	sourcePath := filepath.Join(compileDir, "rule-set.json")
	compiledPath := filepath.Join(compileDir, "rule-set.srs")
	const source = `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "rule-set", "compile", "--output", compiledPath, sourcePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sing-box rule-set compile: %v: %s", err, output)
	}
	compiled, err := os.ReadFile(compiledPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(compiled)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	report, err := geo.Update(context.Background(), geo.Options{
		Dir:     dir,
		Sources: []geo.Source{{Name: "compiled.srs", URL: server.URL}},
		Client:  server.Client(),
	})
	if err != nil {
		t.Fatalf("Update(compiled rule-set) error = %v", err)
	}
	if len(report.Files) != 1 || report.Files[0].Size != int64(len(compiled)) {
		t.Fatalf("report files = %#v, want compiled rule-set size %d", report.Files, len(compiled))
	}
}

type auditEntry struct {
	TS     time.Time   `json:"ts"`
	Actor  string      `json:"actor"`
	Op     string      `json:"op"`
	Result string      `json:"result"`
	Files  []auditFile `json:"files"`
}

type auditFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
