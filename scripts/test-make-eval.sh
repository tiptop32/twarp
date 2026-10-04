#!/usr/bin/env bash
set -euo pipefail

work="$(mktemp -d "${TMPDIR:-/tmp}/twarp-make-eval.XXXXXX")"
trap 'rm -R -- "$work"' EXIT

printf '#!/bin/sh\nexit 23\n' >"$work/fail.sh"
cat >"$work/after.sh" <<'SH'
#!/bin/sh
: > "$TWARP_TEST_MARKER"
SH
chmod +x "$work/fail.sh" "$work/after.sh"

if TWARP_TEST_MARKER="$work/marker" make --no-print-directory eval \
  EVAL_SCRIPTS="$work/fail.sh $work/after.sh" >"$work/output" 2>&1; then
  echo "make eval succeeded after a failing scenario" >&2
  exit 1
fi
if [[ -e "$work/marker" ]]; then
  echo "make eval ran a scenario after a failure" >&2
  exit 1
fi
