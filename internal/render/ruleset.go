package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/singbox"
)

// RenderRuleSet returns a sing-box source-format rule-set.
//
//nolint:revive // The task's public API is explicitly named RenderRuleSet.
func RenderRuleSet(prefixes []netip.Prefix) ([]byte, error) {
	rules := make([]singbox.SourceRuleSetRule, 0, 1)
	if len(prefixes) > 0 {
		cidrs := make([]string, len(prefixes))
		for i, prefix := range prefixes {
			if !prefix.IsValid() {
				return nil, fmt.Errorf("render rule-set: prefix %d is invalid", i)
			}
			cidrs[i] = prefix.Masked().String()
		}
		rules = append(rules, singbox.SourceRuleSetRule{IPCIDR: cidrs})
	}
	data, err := json.MarshalIndent(singbox.SourceRuleSet{Version: 2, Rules: rules}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode rule-set: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteRuleSet atomically replaces rules/corp-ip.json with world-readable data.
func WriteRuleSet(dir string, prefixes []netip.Prefix) error {
	data, err := RenderRuleSet(prefixes)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "corp-ip.json")
	if err := writeAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write rule-set %q: %w", path, err)
	}
	return nil
}

// OnChangeWriter adapts WriteRuleSet to state.Options.OnChange.
func OnChangeWriter(rulesDir string) func([]netip.Prefix) error {
	return func(prefixes []netip.Prefix) error {
		return WriteRuleSet(rulesDir, prefixes)
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) (returnErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary file: %w", err))
		}
	}()

	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open destination directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync destination directory: %w", err)
	}
	return nil
}
