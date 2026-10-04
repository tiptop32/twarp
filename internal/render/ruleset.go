package render

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/fsutil"
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

// RuleSetFile is the gateway rule-set file name inside the rules directory.
const RuleSetFile = "gateway-ip.json"

// RuleSetPath returns the gateway rule-set path inside rulesDir.
func RuleSetPath(rulesDir string) string { return filepath.Join(rulesDir, RuleSetFile) }

// WriteRuleSet atomically replaces rules/gateway-ip.json with world-readable data.
func WriteRuleSet(dir string, prefixes []netip.Prefix) error {
	data, err := RenderRuleSet(prefixes)
	if err != nil {
		return err
	}
	path := RuleSetPath(dir)
	if err := writeAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write rule-set %q: %w", path, err)
	}
	return nil
}

// WriteRuleSetOwned behaves like WriteRuleSet and additionally gives the new
// rule-set to uid and gid while the temporary file is still open, before the
// atomic rename. Root-run install and apply must use it instead of a
// path-based Chown after WriteRuleSet: a chown of the final path follows a
// symlink that an unprivileged user can swap into the rules directory.
func WriteRuleSetOwned(dir string, prefixes []netip.Prefix, uid, gid int) error {
	data, err := RenderRuleSet(prefixes)
	if err != nil {
		return err
	}
	path := RuleSetPath(dir)
	if err := writeAtomicOwned(path, data, 0o644, uid, gid); err != nil {
		return fmt.Errorf("write rule-set %q: %w", path, err)
	}
	return nil
}

// OnChangeWriter adapts WriteRuleSet to state.Options.OnChange. Before
// `sudo twarp install` the rules directory does not exist and its root-owned
// parent cannot be created by the user, so the write is skipped: install
// renders the rule-set from the saved state. Callers detect this with
// Installed and tell the user.
func OnChangeWriter(rulesDir string) func([]netip.Prefix) error {
	return func(prefixes []netip.Prefix) error {
		if !Installed(rulesDir) {
			return nil
		}
		return WriteRuleSet(rulesDir, prefixes)
	}
}

// Installed reports whether the rules directory created by install exists.
func Installed(rulesDir string) bool {
	info, err := os.Stat(rulesDir)
	return err == nil && info.IsDir()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	return fsutil.WriteFileAtomic(path, data, mode)
}

func writeAtomicOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	return fsutil.WriteFileAtomicOwned(path, data, mode, uid, gid)
}
