package fsutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// LockExclusive serializes file transactions across processes. The lock file
// remains in place so concurrent callers always lock the same inode.
func LockExclusive(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %q: %w", path, err)
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %q: %w", path, err)
	}
	return func() { _ = file.Close() }, nil
}
