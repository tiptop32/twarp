package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
)

// ReadPrefixes reads the persisted gateway prefixes under a shared lock.
// It never creates the lock or state file, so root callers cannot leave files
// owned by root in the user's configuration directory.
func ReadPrefixes(file, lockFile string) ([]netip.Prefix, error) {
	lock, err := os.Open(lockFile)
	if err == nil {
		defer func() { _ = lock.Close() }()
		for {
			err = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH)
			if !errors.Is(err, syscall.EINTR) {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("lock %q: %w", lockFile, err)
		}
		defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open lock %q: %w", lockFile, err)
	}

	state, err := readStateFile(file, netip.Addr{})
	if err != nil {
		return nil, err
	}
	sortEntries(state.CIDRs)
	return state.prefixes(), nil
}

func readStateFile(file string, gatewaySocks netip.Addr) (diskState, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return diskState{Version: 1, CIDRs: []Entry{}}, nil
	}
	if err != nil {
		return diskState{}, fmt.Errorf("read state %q: %w", file, err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return diskState{}, fmt.Errorf("decode state %q: %w", file, err)
	}
	if state.Version != 1 {
		return diskState{}, fmt.Errorf("decode state %q: unknown version %d", file, state.Version)
	}
	if state.CIDRs == nil {
		state.CIDRs = []Entry{}
	}
	for i, entry := range state.CIDRs {
		if !entry.CIDR.IsValid() {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d] has invalid prefix", file, i)
		}
		if entry.CIDR != entry.CIDR.Masked() {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d] is not masked: %s", file, i, entry.CIDR)
		}
		validationSocks := gatewaySocks
		if !validationSocks.IsValid() {
			validationSocks = netip.MustParseAddr("192.0.2.1")
			if entry.CIDR.Addr().Is4() {
				validationSocks = netip.MustParseAddr("2001:db8::1")
			}
		}
		if err := validatePrefix(entry.CIDR, nil, validationSocks, true); err != nil {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d]: %w", file, i, err)
		}
	}
	return state, nil
}

// LockShared takes LOCK_SH on an existing lock file and returns its release
// function. A missing lock file means no writer has ever run, so there is
// nothing to wait for and nothing is created. apply holds this lock from
// reading the state until the rule-set is written, so a concurrent Add cannot
// be overwritten by a stale list.
func LockShared(lockFile string) (func(), error) {
	lock, err := os.Open(lockFile)
	if errors.Is(err, os.ErrNotExist) {
		return func() {}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open lock %q: %w", lockFile, err)
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock %q: %w", lockFile, err)
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}
