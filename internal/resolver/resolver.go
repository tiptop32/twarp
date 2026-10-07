// Package resolver keeps macOS per-domain resolver files for gateway domains.
//
// macOS sends DNS for a domain listed in /etc/resolver to that file's
// nameserver. Without such a file, the system resolver may reach a DNS server
// on the local subnet directly: the connected route is more specific than the
// TUN routes, so the query bypasses sing-box and gateway names fail to resolve.
// Each file written here points at the TUN DNS address, where sing-box hijacks
// the query and resolves it through the gateway DNS.
package resolver

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tiptop32/twarp/internal/fsutil"
)

// DefaultDir is the macOS per-domain resolver directory.
const DefaultDir = "/etc/resolver"

// marker is the first line of every file twarp owns. Files without it belong
// to someone else, for example a previous VPN client, and are never changed.
const marker = "# Managed by twarp; do not edit. Removed by: sudo twarp stop / uninstall"

// Result reports what Sync changed.
type Result struct {
	// Changed is true when a file was written or removed.
	Changed bool
	// Foreign lists domains whose resolver file twarp does not own.
	Foreign []string
}

// Sync writes a managed resolver file pointing at nameserver for every domain
// and removes managed files for domains no longer listed. Foreign files are
// left as they are and reported.
func Sync(dir string, domains []string, nameserver string) (Result, error) {
	var result Result
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return result, fmt.Errorf("create resolver directory: %w", err)
	}
	content := []byte(marker + "\nnameserver " + nameserver + "\n")
	wanted := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		name, err := fileName(domain)
		if err != nil {
			return result, err
		}
		if _, seen := wanted[name]; seen {
			continue
		}
		wanted[name] = struct{}{}
		path := filepath.Join(dir, name)
		current, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return result, fmt.Errorf("read resolver file %q: %w", path, err)
		case !managed(current):
			result.Foreign = append(result.Foreign, name)
			continue
		case bytes.Equal(current, content):
			continue
		}
		if err := fsutil.WriteFileAtomic(path, content, 0o644); err != nil {
			return result, fmt.Errorf("write resolver file %q: %w", path, err)
		}
		result.Changed = true
	}
	removed, err := removeManaged(dir, func(name string) bool {
		_, keep := wanted[name]
		return !keep
	})
	result.Changed = result.Changed || removed
	slices.Sort(result.Foreign)
	return result, err
}

// RemoveAll removes every managed resolver file and reports whether any was
// removed. A missing directory is not an error.
func RemoveAll(dir string) (bool, error) {
	return removeManaged(dir, func(string) bool { return true })
}

func removeManaged(dir string, remove func(name string) bool) (bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("list resolver directory: %w", err)
	}
	removed := false
	var errs []error
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !remove(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("read resolver file %q: %w", path, err))
			continue
		}
		if !managed(data) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove resolver file %q: %w", path, err))
			continue
		}
		removed = true
	}
	return removed, errors.Join(errs...)
}

func managed(data []byte) bool {
	line, _, _ := bufio.NewReader(bytes.NewReader(data)).ReadLine()
	return string(line) == marker
}

// fileName returns the resolver file name for a normalized domain. Config
// validation already rejects these cases; the check keeps a bad name from
// ever escaping the resolver directory.
func fileName(domain string) (string, error) {
	name := strings.TrimSuffix(domain, ".")
	if name == "" || strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid resolver domain %q", domain)
	}
	return name, nil
}
