// Package state manages the persistent list of corporate network prefixes.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

const defaultMaxEntries = 256

// AddStatus describes the outcome of an Add operation.
type AddStatus string

// Add operation outcomes.
const (
	AddStatusAdded          AddStatus = "added"
	AddStatusAlreadyPresent AddStatus = "already_present"
	AddStatusCoveredBy      AddStatus = "covered_by"
)

// RemoveStatus describes the outcome of a Remove operation.
type RemoveStatus string

// Remove operation outcomes.
const (
	RemoveStatusRemoved  RemoveStatus = "removed"
	RemoveStatusNotFound RemoveStatus = "not_found"
)

// Entry is one persisted corporate network prefix and its provenance.
type Entry struct {
	CIDR    netip.Prefix `json:"cidr"`
	Comment string       `json:"comment"`
	AddedBy string       `json:"added_by"`
	AddedAt time.Time    `json:"added_at"`
}

// AddResult reports the normalized prefix and the outcome of an Add operation.
type AddResult struct {
	Status         AddStatus
	CIDR           netip.Prefix
	CoveredBy      netip.Prefix
	Warnings       []string
	SingBoxRunning bool
}

// RemoveResult reports the normalized prefix and the outcome of a Remove operation.
type RemoveResult struct {
	Status         RemoveStatus
	CIDR           netip.Prefix
	Warnings       []string
	SingBoxRunning bool
}

// Options configures Store persistence, validation, and runtime callbacks.
type Options struct {
	File          string
	LockFile      string
	AuditFile     string
	AllowedRanges []netip.Prefix
	CorpSocks     netip.Addr
	// OnChange runs after the state is atomically replaced. If it fails, Add or
	// Remove returns its error, but the new state remains persisted.
	OnChange   func([]netip.Prefix) error
	Running    func() bool
	Now        func() time.Time
	MaxEntries int
}

// Store provides serialized access to the persistent corporate prefix list.
type Store struct {
	opts Options
}

// New constructs a Store. Non-positive MaxEntries values use the default limit.
func New(opts Options) *Store {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.AllowedRanges = append([]netip.Prefix(nil), opts.AllowedRanges...)
	return &Store{opts: opts}
}

// Add validates and persists a prefix, or reports why no change was needed.
func (s *Store) Add(ctx context.Context, actor, input, comment string, force bool) (AddResult, error) {
	prefix, warnings, err := Normalize(input)
	if err == nil {
		err = validatePrefix(prefix, s.opts.AllowedRanges, s.opts.CorpSocks, force)
	}
	if err != nil {
		// Refused attempts are the most useful trace of what an agent tried to do.
		// O_APPEND keeps a single small record atomic without taking the state lock.
		auditErr := s.appendAudit(actor, "add", input, "rejected: "+err.Error(), prefix)
		return AddResult{}, errors.Join(err, auditErr)
	}

	lock, err := s.lock(ctx, syscall.LOCK_EX)
	if err != nil {
		return AddResult{}, err
	}
	defer lock.release()

	state, err := s.read()
	if err != nil {
		return AddResult{}, err
	}
	result := AddResult{CIDR: prefix, Warnings: warnings}
	for _, entry := range state.CIDRs {
		if entry.CIDR == prefix {
			result.Status = AddStatusAlreadyPresent
			return s.finishAdd(lock, result, actor, input, nil)
		}
	}
	for _, entry := range state.CIDRs {
		if entry.CIDR.Bits() <= prefix.Bits() && entry.CIDR.Contains(prefix.Addr()) {
			result.Status = AddStatusCoveredBy
			result.CoveredBy = entry.CIDR
			return s.finishAdd(lock, result, actor, input, nil)
		}
	}
	if len(state.CIDRs) >= s.opts.MaxEntries {
		return AddResult{}, fmt.Errorf("corporate CIDR limit reached: maximum %d entries", s.opts.MaxEntries)
	}

	result.Status = AddStatusAdded
	state.CIDRs = append(state.CIDRs, Entry{
		CIDR: prefix, Comment: comment, AddedBy: actor, AddedAt: s.now(),
	})
	sortEntries(state.CIDRs)
	if err := s.write(state); err != nil {
		return AddResult{}, err
	}
	var changeErr error
	if s.opts.OnChange != nil {
		if err := s.opts.OnChange(state.prefixes()); err != nil {
			changeErr = fmt.Errorf("state saved but OnChange failed: %w", err)
		}
	}
	return s.finishAdd(lock, result, actor, input, changeErr)
}

// Remove deletes the exact normalized prefix if it is present.
func (s *Store) Remove(ctx context.Context, actor, input string) (RemoveResult, error) {
	prefix, warnings, err := Normalize(input)
	if err != nil {
		return RemoveResult{}, err
	}

	lock, err := s.lock(ctx, syscall.LOCK_EX)
	if err != nil {
		return RemoveResult{}, err
	}
	defer lock.release()

	state, err := s.read()
	if err != nil {
		return RemoveResult{}, err
	}
	result := RemoveResult{Status: RemoveStatusNotFound, CIDR: prefix, Warnings: warnings}
	var changeErr error
	for i, entry := range state.CIDRs {
		if entry.CIDR != prefix {
			continue
		}
		result.Status = RemoveStatusRemoved
		state.CIDRs = append(state.CIDRs[:i], state.CIDRs[i+1:]...)
		sortEntries(state.CIDRs)
		if err := s.write(state); err != nil {
			return RemoveResult{}, err
		}
		if s.opts.OnChange != nil {
			if err := s.opts.OnChange(state.prefixes()); err != nil {
				changeErr = fmt.Errorf("state saved but OnChange failed: %w", err)
			}
		}
		break
	}
	return s.finishRemove(lock, result, actor, input, changeErr)
}

// List returns entries sorted by address and then prefix length.
func (s *Store) List() ([]Entry, error) {
	lock, err := s.lock(context.Background(), syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer lock.release()

	state, err := s.read()
	if err != nil {
		return nil, err
	}
	sortEntries(state.CIDRs)
	return append([]Entry(nil), state.CIDRs...), nil
}

type diskState struct {
	Version int     `json:"version"`
	CIDRs   []Entry `json:"cidrs"`
}

func (s *Store) read() (diskState, error) {
	data, err := os.ReadFile(s.opts.File)
	if errors.Is(err, os.ErrNotExist) {
		return diskState{Version: 1, CIDRs: []Entry{}}, nil
	}
	if err != nil {
		return diskState{}, fmt.Errorf("read state %q: %w", s.opts.File, err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return diskState{}, fmt.Errorf("decode state %q: %w", s.opts.File, err)
	}
	if state.Version != 1 {
		return diskState{}, fmt.Errorf("decode state %q: unknown version %d", s.opts.File, state.Version)
	}
	if state.CIDRs == nil {
		state.CIDRs = []Entry{}
	}
	for i, entry := range state.CIDRs {
		if !entry.CIDR.IsValid() {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d] has invalid prefix", s.opts.File, i)
		}
		if entry.CIDR != entry.CIDR.Masked() {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d] is not masked: %s", s.opts.File, i, entry.CIDR)
		}
		if err := validatePrefix(entry.CIDR, nil, s.opts.CorpSocks, true); err != nil {
			return diskState{}, fmt.Errorf("decode state %q: cidrs[%d]: %w", s.opts.File, i, err)
		}
	}
	return state, nil
}

func (s *Store) write(state diskState) error {
	dir := filepath.Dir(s.opts.File)
	temporary, err := os.CreateTemp(dir, ".corp-ips-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state for %q: %w", s.opts.File, err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary state permissions: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		return fmt.Errorf("encode state %q: %w", s.opts.File, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync state %q: %w", s.opts.File, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state %q: %w", s.opts.File, err)
	}
	if err := os.Rename(temporaryPath, s.opts.File); err != nil {
		return fmt.Errorf("replace state %q: %w", s.opts.File, err)
	}
	removeTemporary = false
	return nil
}

type fileLock struct {
	file *os.File
}

func (s *Store) lock(ctx context.Context, operation int) (*fileLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(s.opts.LockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %q: %w", s.opts.LockFile, err)
	}
	for {
		err = syscall.Flock(int(file.Fd()), operation|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock %q: %w", s.opts.LockFile, err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (lock *fileLock) release() {
	if lock.file == nil {
		return
	}
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	_ = lock.file.Close()
	lock.file = nil
}

func (s *Store) finishAdd(lock *fileLock, result AddResult, actor, input string, changeErr error) (AddResult, error) {
	auditErr := s.appendAudit(actor, "add", input, string(result.Status), result.CIDR)
	lock.release()
	result.SingBoxRunning = s.running()
	if !result.SingBoxRunning {
		result.Warnings = append(result.Warnings, "sing-box is not running")
	}
	return result, errors.Join(changeErr, auditErr)
}

func (s *Store) finishRemove(lock *fileLock, result RemoveResult, actor, input string, changeErr error) (RemoveResult, error) {
	auditErr := s.appendAudit(actor, "remove", input, string(result.Status), result.CIDR)
	lock.release()
	result.SingBoxRunning = s.running()
	if !result.SingBoxRunning {
		result.Warnings = append(result.Warnings, "sing-box is not running")
	}
	return result, errors.Join(changeErr, auditErr)
}

func (s *Store) running() bool {
	return s.opts.Running != nil && s.opts.Running()
}

func (s *Store) now() time.Time {
	return s.opts.Now().UTC()
}

func (state diskState) prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(state.CIDRs))
	for i, entry := range state.CIDRs {
		prefixes[i] = entry.CIDR
	}
	return prefixes
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		addressComparison := entries[i].CIDR.Addr().Compare(entries[j].CIDR.Addr())
		if addressComparison != 0 {
			return addressComparison < 0
		}
		return entries[i].CIDR.Bits() < entries[j].CIDR.Bits()
	})
}
