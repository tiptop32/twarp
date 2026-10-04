// Package fsutil holds the crash-safe file writes shared by twarp packages.
package fsutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
