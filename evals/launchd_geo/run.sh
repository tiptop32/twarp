#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

for dependency in go python3; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "eval: missing required command: $dependency" >&2
    exit 1
  fi
done

if ((EUID == 0)); then
  root_command=(env)
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "eval: sudo is required to reproduce the root LaunchDaemon invocation" >&2
    exit 1
  fi
  sudo -v
  root_command=(sudo env)
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/twarp-launchd-geo-eval.XXXXXX")"
cleanup() {
  if ((EUID != 0)); then
    sudo chown -R "$(id -u):$(id -g)" "$work" 2>/dev/null || true
  fi
  rm -R -- "$work"
}
trap cleanup EXIT

binary="$work/twarp"
out="$work/out"
log_dir="$work/log"
stdout_file="$work/stdout.txt"
stderr_file="$work/stderr.txt"

(
  cd "$REPO_ROOT"
  go build -o "$binary" ./cmd/twarp
)

"${root_command[@]}" \
  -u SUDO_USER -u SUDO_UID -u SUDO_GID -u TWARP_HOME -u TWARP_SINGBOX \
  TWARP_OUT="$out" TWARP_LOG_DIR="$log_dir" \
  "$binary" geo update >"$stdout_file" 2>"$stderr_file"

if ((EUID != 0)); then
  sudo chown -R "$(id -u):$(id -g)" "$work"
fi

python3 - "$out" "$log_dir/audit.jsonl" "$stdout_file" "$stderr_file" <<'PY'
import json
from pathlib import Path
import sys

out_dir, audit_path, stdout_path, stderr_path = map(Path, sys.argv[1:])
names = ("geoip-ru.srs", "geosite-category-ru.srs")
for name in names:
    path = out_dir / "geo" / name
    data = path.read_bytes()
    if not data.startswith(b"SRS"):
        raise SystemExit(f"eval: {path} is missing the SRS header")

stderr = stderr_path.read_text(encoding="utf-8")
if stderr:
    raise SystemExit(f"eval: geo update wrote stderr: {stderr.rstrip()}")

stdout = stdout_path.read_text(encoding="utf-8")
for name in names:
    if f"updated {name}:" not in stdout:
        raise SystemExit(f"eval: stdout has no success report for {name}")

records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
if not records or records[-1].get("op") != "geo_update" or records[-1].get("result") != "ok":
    raise SystemExit("eval: root audit has no successful geo_update record")
if sorted(file.get("name") for file in records[-1].get("files", [])) != sorted(names):
    raise SystemExit("eval: root audit does not list both geo rule-sets")
PY

echo "PASS: root geo update completed without SUDO_USER and honored TWARP_OUT"
