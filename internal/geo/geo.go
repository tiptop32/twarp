// Package geo downloads and atomically stores sing-box geo rule-sets.
package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultTimeout = 60 * time.Second
	maxRuleSetSize = 32 << 20
)

var ruleSetMagic = []byte("SRS")

// Source identifies a rule-set download and its destination file name.
type Source struct {
	Name string
	URL  string
}

// DefaultSources are the Russian geo rule-sets used by twarp.
var DefaultSources = []Source{
	{Name: "geoip-ru.srs", URL: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"},
	{Name: "geosite-category-ru.srs", URL: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs"},
}

// Options configures an Update.
type Options struct {
	Dir       string
	Sources   []Source
	Client    *http.Client
	Timeout   time.Duration
	AuditFile string
	Now       func() time.Time
}

// FileReport describes one successfully stored rule-set.
type FileReport struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
}

// Report lists the rule-sets successfully stored by Update.
type Report struct {
	Files []FileReport
}

// Update downloads rule-sets and atomically replaces each destination file.
func Update(ctx context.Context, options Options) (Report, error) {
	sources := options.Sources
	if sources == nil {
		sources = DefaultSources
	}
	report := Report{Files: make([]FileReport, 0, len(sources))}
	if err := os.MkdirAll(options.Dir, 0o755); err != nil {
		return finishUpdate(options, report, fmt.Errorf("create geo directory %q: %w", options.Dir, err))
	}

	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	var updateErrors []error
	for _, source := range sources {
		file, err := updateOne(ctx, options.Dir, source, client, timeout)
		if err != nil {
			updateErrors = append(updateErrors, err)
			continue
		}
		report.Files = append(report.Files, file)
	}
	return finishUpdate(options, report, errors.Join(updateErrors...))
}

func finishUpdate(options Options, report Report, updateErr error) (Report, error) {
	if err := appendAudit(options.AuditFile, options.Now, report, updateErr); err != nil {
		return report, errors.Join(updateErr, err)
	}
	return report, updateErr
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

func appendAudit(path string, now func() time.Time, report Report, updateErr error) (returnErr error) {
	if path == "" {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit directory for %q: %w", path, err)
	}

	files := make([]auditFile, 0, len(report.Files))
	for _, file := range report.Files {
		files = append(files, auditFile{Name: file.Name, Size: file.Size})
	}
	result := "ok"
	if updateErr != nil {
		result = "error: " + updateErr.Error()
	}
	line, err := json.Marshal(auditEntry{
		TS:     now(),
		Actor:  "cli",
		Op:     "geo_update",
		Result: result,
		Files:  files,
	})
	if err != nil {
		return fmt.Errorf("encode geo audit entry: %w", err)
	}
	line = append(line, '\n')

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open geo audit file %q: %w", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close geo audit file %q: %w", path, err)
		}
	}()
	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("append geo audit file %q: %w", path, err)
	}
	return nil
}

func updateOne(ctx context.Context, dir string, source Source, client *http.Client, timeout time.Duration) (result FileReport, returnErr error) {
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, source.URL, nil)
	if err != nil {
		return FileReport{}, fmt.Errorf("create request for %q: %w", source.Name, err)
	}
	response, err := client.Do(request)
	if err != nil {
		return FileReport{}, fmt.Errorf("download %q: %w", source.Name, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return FileReport{}, fmt.Errorf("download %q: HTTP status %s", source.Name, response.Status)
	}

	magic := make([]byte, len(ruleSetMagic))
	if _, err := io.ReadFull(response.Body, magic); err != nil {
		return FileReport{}, fmt.Errorf("read rule-set magic for %q: %w", source.Name, err)
	}
	if string(magic) != string(ruleSetMagic) {
		return FileReport{}, fmt.Errorf("download %q: missing SRS magic header", source.Name)
	}

	temporary, err := os.CreateTemp(dir, "."+source.Name+".tmp-*")
	if err != nil {
		return FileReport{}, fmt.Errorf("create temporary file for %q: %w", source.Name, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !os.IsNotExist(err) && returnErr == nil {
			returnErr = fmt.Errorf("remove temporary file for %q: %w", source.Name, err)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("set temporary file permissions for %q: %w", source.Name, err)
	}
	if _, err := temporary.Write(magic); err != nil {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("write rule-set magic for %q: %w", source.Name, err)
	}
	remainingLimit := int64(maxRuleSetSize - len(ruleSetMagic) + 1)
	written, err := io.Copy(temporary, io.LimitReader(response.Body, remainingLimit))
	if err != nil {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("write temporary file for %q: %w", source.Name, err)
	}
	if written == remainingLimit {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("download %q exceeds 32 MiB limit", source.Name)
	}
	if err := response.Body.Close(); err != nil {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("close download body for %q: %w", source.Name, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return FileReport{}, fmt.Errorf("sync temporary file for %q: %w", source.Name, err)
	}
	if err := temporary.Close(); err != nil {
		return FileReport{}, fmt.Errorf("close temporary file for %q: %w", source.Name, err)
	}

	path := filepath.Join(dir, source.Name)
	if err := os.Rename(temporaryPath, path); err != nil {
		return FileReport{}, fmt.Errorf("replace rule-set %q: %w", source.Name, err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return FileReport{}, fmt.Errorf("open geo directory %q: %w", dir, err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return FileReport{}, fmt.Errorf("sync geo directory %q: %w", dir, err)
	}
	if err := directory.Close(); err != nil {
		return FileReport{}, fmt.Errorf("close geo directory %q: %w", dir, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return FileReport{}, fmt.Errorf("stat stored rule-set %q: %w", source.Name, err)
	}
	return FileReport{Name: source.Name, Path: path, Size: info.Size(), ModTime: info.ModTime()}, nil
}
