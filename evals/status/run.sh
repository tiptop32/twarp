#!/usr/bin/env bash
set -euo pipefail

# Focused eval for status reporting: an own utun route counts as an active
# tunnel only while the launchd sing-box service is running. A stale route
# left after `twarp stop` (service booted out or stopped) must fail instead
# of reporting OK. The scenarios run through the app and CLI regression
# tests against a fake launchctl and fail on a baseline without the fix.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

if ! command -v go >/dev/null 2>&1; then
  echo "eval: missing required command: go" >&2
  exit 1
fi

scenarios=(
  "running own utun stays active:./internal/app:TestCheckTunnelReportsRunningOwnTunnel"
  "stale own utun fails app status:./internal/app:TestCheckTunnelRejectsStaleOwnTunnel"
  "stale own utun fails CLI status:./cmd/twarp:TestRunStatusReportsStaleOwnTunnel"
  "unexpected print error fails app status:./internal/app:TestCheckTunnelFailsOnUnexpectedPrintError"
  "unexpected print error fails CLI status:./cmd/twarp:TestRunStatusFailsOnUnexpectedPrintError"
  "non-own routes keep old behavior:./cmd/twarp:TestRunStatusReportsForeignTunnel|TestRunStatusWarnsWhenTunnelIsInactive"
)

cd "$REPO_ROOT"
failed=0
for scenario in "${scenarios[@]}"; do
  name=${scenario%%:*}
  rest=${scenario#*:}
  package=${rest%%:*}
  pattern=${rest#*:}
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
  echo "status eval: $failed scenario(s) failed"
  exit 1
fi
echo "status eval: all scenarios passed"
