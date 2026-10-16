package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// TrustedPath resolves path and checks that the file and every directory
// above it belong to root (or ownerUID; pass 0 for root only) and are not
// writable by group or others. A world-writable directory with the sticky
// bit, such as /tmp, is allowed: others cannot rename what they do not own.
// The resolved path is returned so a later symlink swap is no help.
func TrustedPath(path string, ownerUID int) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if resolved, err = filepath.Abs(resolved); err != nil {
		return "", err
	}
	for current := resolved; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return "", fmt.Errorf("cannot read the owner of %s", current)
		}
		if uid := int(stat.Uid); uid != 0 && uid != ownerUID {
			return "", fmt.Errorf("%s is owned by uid %d, not root", current, uid)
		}
		sticky := info.IsDir() && info.Mode()&os.ModeSticky != 0
		if info.Mode().Perm()&0o022 != 0 && !sticky {
			return "", fmt.Errorf("%s is writable by group or others", current)
		}
		if parent := filepath.Dir(current); parent == current {
			return resolved, nil
		}
	}
}
