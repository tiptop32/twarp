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
	dir := filepath.Dir(path)
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
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync destination directory: %w", err)
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
