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
	paths, prefixes, data, err := renderInputs(deps.Sys)
	if err != nil {
		release()
		return failApply(stderr, deps.Sys, err)
	}
	if err := writeApplyFiles(deps, paths, prefixes, data, uid, gid); err != nil {
		release()
		return failApply(stderr, deps.Sys, err)
	}
	release()
	ctx := context.Background()
	if err := singbox.Check(ctx, deps.Runner, paths.SingBox, paths.OutConfig()); err != nil {
		return failApply(stderr, deps.Sys, err)
	}
	service, err := deps.Runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	if err != nil {
		return failApply(stderr, deps.Sys, errors.New("sing-box service is not installed; run: sudo twarp install"))
	}
	result := "kickstarted"
	if strings.Contains(string(service), "state = running") {
		if err := singbox.Reload(ctx, deps.Runner); err != nil {
			return failApply(stderr, deps.Sys, fmt.Errorf("reload sing-box: %w", err))
		}
		result = "reloaded"
	} else if err := sysexec.Kickstart(ctx, deps.Runner, sysexec.SystemTarget()); err != nil {
		return failApply(stderr, deps.Sys, fmt.Errorf("kickstart sing-box: %w", err))
	}
	if err := appendCLIAudit(deps.Sys, "apply", result); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp apply: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "applied and %s sing-box\n", result)
	return 0
}

func writeApplyFiles(deps cliDeps, paths config.Paths, prefixes []netip.Prefix, data []byte, uid, gid int) error {
	if err := render.WriteConfig(paths.OutConfig(), data); err != nil {
		return err
	}
	if err := render.WriteRuleSet(paths.RulesDir(), prefixes); err != nil {
		return err
	}
	if err := deps.FS.Chown(render.RuleSetPath(paths.RulesDir()), uid, gid); err != nil {
		return fmt.Errorf("give gateway rule-set to sudo user: %w", err)
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
