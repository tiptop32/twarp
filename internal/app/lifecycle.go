package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/sysexec"
)

// Start turns the tunnel on without reinstalling: it loads the installed
// sing-box daemon, or restarts it when it is loaded but not routing. It
// returns a one-line summary for the user.
func (s *Service) Start(ctx context.Context) (string, error) {
	if !s.isRoot() {
		return "", ErrRootRequired
	}
	if _, err := s.deps.FS.Stat(launchd.SingBoxPlistPath); errors.Is(err, os.ErrNotExist) {
		return "", errors.New("not installed: run sudo twarp install")
	} else if err != nil {
		return "", err
	}

	conflict, err := launchd.DetectConflict(ctx, s.deps.Runner)
	if err != nil {
		return "", err
	}
	switch {
	case conflict.OwnTUN:
		if err := sysexec.Enable(ctx, s.deps.Runner, sysexec.SystemTarget()); err != nil {
			return "", err
		}
		return "already running on " + conflict.Interface, nil
	case conflict.Hint != "":
		return "", fmt.Errorf("%s (%s %s)", conflict.Hint, conflict.Interface, conflict.Addr)
	}

	// A loaded service that does not hold the route has crashed or was stopped
	// by launchd; kickstart restarts it. An unloaded one needs bootstrap. stop
	// persists a disabled flag, so clear it first: launchd refuses kickstart
	// for a disabled service and bootstrap of one never runs it.
	service, printErr := s.deps.Runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if err := sysexec.Enable(ctx, s.deps.Runner, sysexec.SystemTarget()); err != nil {
		return "", err
	}
	if printErr == nil && strings.Contains(string(service), "state = running") {
		return "sing-box is running but does not hold the default route yet; check: twarp status", nil
	}
	if printErr == nil {
		err = sysexec.Kickstart(ctx, s.deps.Runner, sysexec.SystemTarget())
	} else {
		err = sysexec.Bootstrap(ctx, s.deps.Runner, "system", launchd.SingBoxPlistPath)
	}
	if err != nil {
		return "", err
	}
	return "started; check: twarp status", nil
}

// Stop turns the tunnel off and keeps everything installed, so the default
// route returns to the network (or to another VPN) until Start. The disabled
// flag persists across reboot, so launchd does not bring the tunnel back on
// its own.
func (s *Service) Stop(ctx context.Context) (string, error) {
	if !s.isRoot() {
		return "", ErrRootRequired
	}
	if err := sysexec.Bootout(ctx, s.deps.Runner, sysexec.SystemTarget()); err != nil {
		return "", err
	}
	if err := sysexec.Disable(ctx, s.deps.Runner, sysexec.SystemTarget()); err != nil {
		return "", err
	}
	return "stopped; start again: sudo twarp start", nil
}

// GeoUpdate downloads the geo rule-sets into the root-owned geo directory.
// The report lists the files written even when another source failed.
func (s *Service) GeoUpdate(ctx context.Context) (geo.Report, error) {
	if !s.isRoot() {
		return geo.Report{}, fmt.Errorf("%w: geo/ is owned by root", ErrRootRequired)
	}
	options := s.deps.GeoOptions
	options.Dir = filepath.Join(config.OutputDir(s.deps.Sys), "geo")
	options.AuditFile = RootAuditFile(s.deps.Sys)
	return geo.Update(ctx, options)
}

// RenderInputs loads config, secrets and gateway state and renders the
// production sing-box config.
func (s *Service) RenderInputs() (config.Paths, []netip.Prefix, []byte, error) {
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	prefixes, err := state.ReadPrefixes(paths.GatewayIPsFile(), paths.LockFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	data, err := render.Render(cfg, secrets, prefixes, render.Options{Paths: paths, Inbound: render.InboundTUN})
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	return paths, prefixes, data, nil
}

// Apply re-renders the config, checks it with sing-box and reloads or starts
// the daemon. Every failure after the paths resolve is written to the root
// audit log, and the previous config and rule-set are restored.
func (s *Service) Apply(ctx context.Context) (string, error) {
	if !s.isRoot() {
		return "", ErrRootRequired
	}
	if s.deps.Runner == nil || s.deps.FS == nil {
		return "", errors.New("dependencies are incomplete")
	}
	uid, gid, ok := config.SudoOwner(s.deps.Sys)
	if !ok {
		return "", fmt.Errorf("%w: SUDO_UID and SUDO_GID are required", ErrRootRequired)
	}

	resolved, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return "", s.failApply(err)
	}
	// Hold LOCK_SH from reading the state until the rule-set is written: a
	// concurrent gateway add (CLI, TUI or MCP) waits instead of being overwritten.
	release, err := state.LockShared(resolved.LockFile())
	if err != nil {
		return "", s.failApply(err)
	}
	ruleSetPath := render.RuleSetPath(resolved.RulesDir())
	previousRuleSet, readErr := os.ReadFile(ruleSetPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		release()
		return "", s.failApply(fmt.Errorf("read installed gateway rule-set: %w", readErr))
	}
	paths, prefixes, data, err := s.RenderInputs()
	if err != nil {
		release()
		return "", s.failApply(err)
	}
	previousConfig, configReadErr := os.ReadFile(paths.OutConfig())
	if configReadErr != nil && !errors.Is(configReadErr, os.ErrNotExist) {
		release()
		return "", s.failApply(fmt.Errorf("read installed sing-box config: %w", configReadErr))
	}
	restoreRuleSet := func() error {
		return s.restoreApplyRuleSet(ruleSetPath, previousRuleSet, readErr == nil, uid, gid)
	}
	candidatePath, err := s.writeApplyFiles(paths, prefixes, data, uid, gid)
	if err != nil {
		err = errors.Join(err, restoreRuleSet())
		release()
		return "", s.failApply(err)
	}
	failBeforePromotion := func(cause error) (string, error) {
		cause = discardApplyCandidate(candidatePath, cause)
		cause = errors.Join(cause, restoreRuleSet())
		release()
		return "", s.failApply(cause)
	}
	if err := singbox.Check(ctx, s.deps.Runner, paths.SingBox, candidatePath); err != nil {
		return failBeforePromotion(err)
	}
	stopped := false
	service, err := s.deps.Runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if err != nil {
		if _, statErr := s.deps.FS.Stat(launchd.SingBoxPlistPath); statErr == nil {
			disabled, disabledErr := s.deps.Runner.Run(ctx, "launchctl", "print-disabled", "system")
			if disabledErr == nil && serviceDisabled(disabled) {
				stopped = true
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return failBeforePromotion(fmt.Errorf("inspect sing-box service: %w", statErr))
		}
		if !stopped {
			return failBeforePromotion(errors.New("sing-box service is not installed; run: sudo twarp install"))
		}
	}
	if err := fsutil.PromoteFile(candidatePath, paths.OutConfig()); err != nil {
		err = errors.Join(err, restoreApplyConfig(paths.OutConfig(), previousConfig, configReadErr == nil))
		err = errors.Join(err, restoreRuleSet())
		release()
		return "", s.failApply(discardApplyCandidate(candidatePath, err))
	}
	if stopped {
		release()
		if err := s.appendRootAudit("apply", "stopped"); err != nil {
			return "", err
		}
		return "applied; sing-box stays stopped; start it: sudo twarp start", nil
	}
	failAfterPromotion := func(cause error, reload bool) (string, error) {
		cause = errors.Join(cause, restoreApplyConfig(paths.OutConfig(), previousConfig, configReadErr == nil))
		cause = errors.Join(cause, restoreRuleSet())
		if reload {
			if err := singbox.Reload(ctx, s.deps.Runner); err != nil {
				cause = errors.Join(cause, fmt.Errorf("reload restored sing-box config: %w", err))
			}
		}
		release()
		return "", s.failApply(cause)
	}
	result := "kickstarted"
	if strings.Contains(string(service), "state = running") {
		if err := singbox.Reload(ctx, s.deps.Runner); err != nil {
			return failAfterPromotion(fmt.Errorf("reload sing-box: %w", err), true)
		}
		result = "reloaded"
	} else if err := sysexec.Kickstart(ctx, s.deps.Runner, sysexec.SystemTarget()); err != nil {
		return failAfterPromotion(fmt.Errorf("kickstart sing-box: %w", err), false)
	}
	release()
	if err := s.appendRootAudit("apply", result); err != nil {
		return "", err
	}
	return fmt.Sprintf("applied and %s sing-box", result), nil
}

func serviceDisabled(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == `"`+sysexec.Label+`"` && fields[1] == "=>" {
			return fields[2] == "disabled" || fields[2] == "true"
		}
	}
	return false
}

func (s *Service) writeApplyFiles(paths config.Paths, prefixes []netip.Prefix, data []byte, uid, gid int) (string, error) {
	candidatePath, err := fsutil.WriteFileCandidate(paths.OutConfig(), data, 0o600)
	if err != nil {
		return "", err
	}
	if err := s.deps.FS.MkdirAll(paths.RulesDir(), 0o755); err != nil {
		return "", discardApplyCandidate(candidatePath, fmt.Errorf("create rule-set directory: %w", err))
	}
	ruleSetData, err := render.RenderRuleSet(prefixes)
	if err != nil {
		return "", discardApplyCandidate(candidatePath, err)
	}
	if err := s.deps.FS.WriteFileOwned(render.RuleSetPath(paths.RulesDir()), ruleSetData, 0o644, uid, gid); err != nil {
		return "", discardApplyCandidate(candidatePath, err)
	}
	return candidatePath, nil
}

func discardApplyCandidate(path string, cause error) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, fmt.Errorf("remove candidate config: %w", err))
	}
	return cause
}

func (s *Service) restoreApplyRuleSet(path string, previous []byte, existed bool, uid, gid int) error {
	if existed {
		if err := s.deps.FS.WriteFileOwned(path, previous, 0o644, uid, gid); err != nil {
			return fmt.Errorf("restore gateway rule-set: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove new gateway rule-set: %w", err)
	}
	return nil
}

func restoreApplyConfig(path string, previous []byte, existed bool) error {
	if existed {
		if err := fsutil.WriteFileAtomic(path, previous, 0o600); err != nil {
			return fmt.Errorf("restore sing-box config: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove new sing-box config: %w", err)
	}
	return nil
}

// failApply records err in the root audit log and returns it unchanged.
func (s *Service) failApply(err error) error {
	_ = s.appendRootAudit("apply", "error: "+err.Error())
	return err
}
