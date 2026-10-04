package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func runApply(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if code, stop := parseNoArgs("apply", args, stderr); stop {
		return code
	}
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp apply: run with sudo")
		return 1
	}
	if deps.Runner == nil || deps.FS == nil {
		_, _ = fmt.Fprintln(stderr, "twarp apply: dependencies are incomplete")
		return 1
	}
	uid, gid, ok := config.SudoOwner(deps.Sys)
	if !ok {
		_, _ = fmt.Fprintln(stderr, "twarp apply: run with sudo: SUDO_UID and SUDO_GID are required")
		return 1
	}

	resolved, err := config.Resolve(deps.Sys)
	if err != nil {
		return failApply(stderr, deps.Sys, err)
	}
	// Hold LOCK_SH from reading the state until the rule-set is written: a
	// concurrent gateway add (CLI or MCP) waits instead of being overwritten.
	release, err := state.LockShared(resolved.LockFile())
	if err != nil {
		return failApply(stderr, deps.Sys, err)
	}
	ruleSetPath := render.RuleSetPath(resolved.RulesDir())
	previousRuleSet, readErr := os.ReadFile(ruleSetPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		release()
		return failApply(stderr, deps.Sys, fmt.Errorf("read installed gateway rule-set: %w", readErr))
	}
	paths, prefixes, data, err := renderInputs(deps.Sys)
	if err != nil {
		release()
		return failApply(stderr, deps.Sys, err)
	}
	previousConfig, configReadErr := os.ReadFile(paths.OutConfig())
	if configReadErr != nil && !errors.Is(configReadErr, os.ErrNotExist) {
		release()
		return failApply(stderr, deps.Sys, fmt.Errorf("read installed sing-box config: %w", configReadErr))
	}
	candidatePath, err := writeApplyFiles(deps, paths, prefixes, data, uid, gid)
	if err != nil {
		err = errors.Join(err, restoreApplyRuleSet(deps, ruleSetPath, previousRuleSet, readErr == nil, uid, gid))
		release()
		return failApply(stderr, deps.Sys, err)
	}
	failBeforePromotion := func(cause error) int {
		cause = discardApplyCandidate(candidatePath, cause)
		cause = errors.Join(cause, restoreApplyRuleSet(deps, ruleSetPath, previousRuleSet, readErr == nil, uid, gid))
		release()
		return failApply(stderr, deps.Sys, cause)
	}
	ctx := context.Background()
	if err := singbox.Check(ctx, deps.Runner, paths.SingBox, candidatePath); err != nil {
		return failBeforePromotion(err)
	}
	stopped := false
	service, err := deps.Runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if err != nil {
		if _, statErr := deps.FS.Stat(launchd.SingBoxPlistPath); statErr == nil {
			disabled, disabledErr := deps.Runner.Run(ctx, "launchctl", "print-disabled", "system")
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
		err = errors.Join(err, restoreApplyRuleSet(deps, ruleSetPath, previousRuleSet, readErr == nil, uid, gid))
		release()
		return failApply(stderr, deps.Sys, discardApplyCandidate(candidatePath, err))
	}
	if stopped {
		release()
		if auditErr := appendCLIAudit(deps.Sys, "apply", "stopped"); auditErr != nil {
			_, _ = fmt.Fprintf(stderr, "twarp apply: %v\n", auditErr)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "applied; sing-box stays stopped; start it: sudo twarp start")
		return 0
	}
	failAfterPromotion := func(cause error, reload bool) int {
		cause = errors.Join(cause, restoreApplyConfig(paths.OutConfig(), previousConfig, configReadErr == nil))
		cause = errors.Join(cause, restoreApplyRuleSet(deps, ruleSetPath, previousRuleSet, readErr == nil, uid, gid))
		if reload {
			if err := singbox.Reload(ctx, deps.Runner); err != nil {
				cause = errors.Join(cause, fmt.Errorf("reload restored sing-box config: %w", err))
			}
		}
		release()
		return failApply(stderr, deps.Sys, cause)
	}
	result := "kickstarted"
	if strings.Contains(string(service), "state = running") {
		if err := singbox.Reload(ctx, deps.Runner); err != nil {
			return failAfterPromotion(fmt.Errorf("reload sing-box: %w", err), true)
		}
		result = "reloaded"
	} else if err := sysexec.Kickstart(ctx, deps.Runner, sysexec.SystemTarget()); err != nil {
		return failAfterPromotion(fmt.Errorf("kickstart sing-box: %w", err), false)
	}
	release()
	if err := appendCLIAudit(deps.Sys, "apply", result); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp apply: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "applied and %s sing-box\n", result)
	return 0
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

func writeApplyFiles(deps cliDeps, paths config.Paths, prefixes []netip.Prefix, data []byte, uid, gid int) (string, error) {
	candidatePath, err := fsutil.WriteFileCandidate(paths.OutConfig(), data, 0o600)
	if err != nil {
		return "", err
	}
	if err := deps.FS.MkdirAll(paths.RulesDir(), 0o755); err != nil {
		return "", discardApplyCandidate(candidatePath, fmt.Errorf("create rule-set directory: %w", err))
	}
	ruleSetData, err := render.RenderRuleSet(prefixes)
	if err != nil {
		return "", discardApplyCandidate(candidatePath, err)
	}
	if err := deps.FS.WriteFileOwned(render.RuleSetPath(paths.RulesDir()), ruleSetData, 0o644, uid, gid); err != nil {
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

func restoreApplyRuleSet(deps cliDeps, path string, previous []byte, existed bool, uid, gid int) error {
	if existed {
		if err := deps.FS.WriteFileOwned(path, previous, 0o644, uid, gid); err != nil {
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

func failApply(stderr io.Writer, system config.Sys, err error) int {
	_ = appendCLIAudit(system, "apply", "error: "+err.Error())
	_, _ = fmt.Fprintf(stderr, "twarp apply: %v\n", err)
	return 1
}

func appendCLIAudit(system config.Sys, operation, result string) error {
	path := rootAuditFile(system)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit directory %q: %w", filepath.Dir(path), err)
	}
	record := struct {
		TS     time.Time `json:"ts"`
		Actor  string    `json:"actor"`
		Op     string    `json:"op"`
		Result string    `json:"result"`
	}{TS: time.Now().UTC(), Actor: "cli", Op: operation, Result: result}
	if err := fsutil.AppendJSONLine(path, record); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

// rootAuditFile is the audit log written by root commands; user commands write
// to the audit log in the twarp home instead.
func rootAuditFile(system config.Sys) string {
	directory := system.Getenv("TWARP_LOG_DIR")
	if directory == "" {
		directory = defaultRootLogDir
	}
	return filepath.Join(directory, "audit.jsonl")
}
