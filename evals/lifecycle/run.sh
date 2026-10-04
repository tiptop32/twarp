#!/usr/bin/env bash
set -euo pipefail

# Executable eval for the start/stop lifecycle: stop must persist a disabled
# launchd flag, start must re-enable, a stale own utun after stop must not
# make start report "already running", apply after stop must not start the
# tunnel, and install after stop must re-enable before bootstrap. The
# scenarios run through the CLI regression tests, which drive runStart,
# runStop, runApply and launchd.Install against a fake launchctl and fail on
# a baseline without the fix.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

if ! command -v go >/dev/null 2>&1; then
  echo "eval: missing required command: go" >&2
  exit 1
fi

scenarios=(
  "stop persists disabled state:TestRunStopPersistsDisabledStateIdempotently"
  "start re-enables after stop:TestRunStartReenablesAfterStop"
  "start recovers from stale own utun:TestRunStartRecoversFromStaleOwnTunAfterStop"
  "start aborts on unexpected print error:TestRunStartFailsOnUnexpectedPrintError"
  "start recognizes loaded vs unloaded service:./internal/app:TestStartFailsOnUnexpectedPrintError|TestStartTreatsKnownAbsenceAsUnload"
  "start restores enabled state while running:TestRunStartEnablesActiveTunnel|TestRunStartEnablesRunningServiceWithoutRoute"
  "start loads and restarts services:TestRunStartLoadsUnloadedService|TestRunStartRestartsLoadedButInactiveService"
  "apply keeps stopped service stopped:TestRunApplyKeepsDisabledServiceStopped"
  "apply rejects uninstalled service:TestRunApplyRejectsUninstalledService"
  "install re-enables before bootstrap:TestInstallPerformsSystemSetupInOrder"
)

cd "$REPO_ROOT"
failed=0
for scenario in "${scenarios[@]}"; do
  name=${scenario%%:*}
  rest=${scenario#*:}
  pattern=$rest
  package=./cmd/twarp
  if [[ $rest == ./*:* ]]; then
    package=${rest%%:*}
    pattern=${rest#*:}
  elif [[ $name == "install re-enables before bootstrap" ]]; then
    package=./internal/launchd
  fi
  echo "== $name"
  if ! go test "$package" -list "$pattern" | grep -E '^Test' >/dev/null; then
    echo "FAIL $name: no matching tests"
    failed=$((failed + 1))
    continue
  fi
  if go test "$package" -run "$pattern" -count=1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    failed=$((failed + 1))
  fi
done

if ((failed > 0)); then
  echo "lifecycle eval: $failed scenario(s) failed"
  exit 1
fi
echo "lifecycle eval: all scenarios passed"
