// Package fsutil holds the crash-safe file writes shared by twarp packages.
package fsutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// WriteFileAtomic replaces path with data and exactly mode. The data is synced
// to a temporary file in the same directory and renamed over path, so readers
// see either the old or the new contents. Unlike os.WriteFile it never keeps
// the permissions of an existing file. The directory must already exist.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) (returnErr error) {
	return writeFileAtomic(path, data, mode, -1, -1)
}

// WriteFileAtomicOwned sets ownership on the open temporary file before the
// rename, so no privileged Chown follows a path in a user-writable directory.
func WriteFileAtomicOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	return writeFileAtomic(path, data, mode, uid, gid)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode, uid, gid int) (returnErr error) {
	temporaryPath, err := writeFileCandidate(path, data, mode, uid, gid)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary file: %w", err))
		}
	}()
	return PromoteFile(temporaryPath, path)
}

// WriteFileCandidate writes and syncs data to a temporary file beside path
// without replacing path. Callers can validate the returned file before
// passing it to PromoteFile. The directory must already exist.
func WriteFileCandidate(path string, data []byte, mode os.FileMode) (candidatePath string, returnErr error) {
	return writeFileCandidate(path, data, mode, -1, -1)
}

func writeFileCandidate(path string, data []byte, mode os.FileMode, uid, gid int) (candidatePath string, returnErr error) {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary file: %w", err))
			}
		}
	}()

	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("set temporary file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync temporary file: %w", err)
	}
	if uid >= 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			_ = temporary.Close()
			return "", fmt.Errorf("set temporary file ownership: %w", err)
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			return "", fmt.Errorf("sync temporary file ownership: %w", err)
		}
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close temporary file: %w", err)
	}
	return temporaryPath, nil
}

// PromoteFile atomically renames a prepared candidate over path and syncs the
// destination directory so the replacement survives a crash.
func PromoteFile(candidatePath, path string) error {
	if filepath.Dir(candidatePath) != filepath.Dir(path) {
		return errors.New("candidate and destination must be in the same directory")
	}
	if err := os.Rename(candidatePath, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("replacement completed but opening destination directory for sync failed: %w", err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("replacement completed but syncing destination directory failed: %w", err)
	}
	return nil
}

// AppendJSONLine appends record as one JSON line to an owner-only file. The
// line is written with a single O_APPEND write, so concurrent writers of small
// records do not interleave and no lock is needed. File errors already name
// the path, so they are returned unwrapped.
func AppendJSONLine(path string, record any) error {
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode record for %q: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// userFileOwner is the uid every file under the user's twarp home must belong
// to when a root daemon reads it; -1 turns the check off.
var userFileOwner atomic.Int64

func init() { userFileOwner.Store(-1) }

// GuardUserFiles makes OpenUserFile refuse anything but regular files owned
// by uid that are not symlinks. twarpd calls it once at start: it reads the
// owner's files as root without a password prompt, so a symlink such as
// twarp.yaml -> /etc/master.passwd must not turn error messages into a way to
// read root-only files, and a FIFO must not hang the daemon.
func GuardUserFiles(uid int) { userFileOwner.Store(int64(uid)) }

// OpenUserFile opens a file from the user's twarp home for reading. Without
// GuardUserFiles it is os.Open.
func OpenUserFile(path string) (*os.File, error) {
	owner := userFileOwner.Load()
	if owner < 0 {
		return os.Open(path)
	}
	// O_NONBLOCK keeps open from waiting on a FIFO; the fstat below rejects it.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to read %s as root: it is a symlink", path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || int64(stat.Uid) != owner {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("refusing to read %s as root: not a regular file owned by uid %d", path, owner)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ReadUserFile reads a file opened with OpenUserFile, up to limit bytes.
func ReadUserFile(path string, limit int64) ([]byte, error) {
	file, err := OpenUserFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// TrustedExecutable resolves path and checks that the file and every directory
// above it belong to root (or ownerUID) and are not writable by group or
// others. A world-writable directory with the sticky bit, such as /tmp, is
// allowed: others cannot rename what they do not own. Running the resolved
// path keeps a later symlink swap from changing what runs as root.
func TrustedExecutable(path string, ownerUID int) (string, error) {
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

// LockExclusive takes an exclusive flock on path, creating it 0600, and
// returns its release function. Apply and install hold it while they replace
// config.json, so a sudo command and twarpd never interleave.
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
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
