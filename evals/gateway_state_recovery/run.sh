#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/twarp-gateway-recovery-eval.XXXXXX")"
trap 'rm -R -- "$WORK"' EXIT

home="$WORK/home"
out="$WORK/out"
binary="$WORK/twarp"
mkdir -p "$home" "$out/rules"

write_config() {
  local socks=$1
  cat >"$home/twarp.yaml" <<YAML
gateway:
  socks: $socks
  domains: [intra.example]
  dns: 100.64.0.53
  allowed_ranges: [100.64.0.0/10]
YAML
}

(
  cd "$REPO_ROOT"
  go build -o "$binary" ./cmd/twarp
)

write_config "192.0.2.10:1080"
TWARP_HOME="$home" TWARP_OUT="$out" "$binary" gateway add 100.64.20.0/24 >/dev/null

write_config "100.64.20.10:1080"
list_output="$(TWARP_HOME="$home" TWARP_OUT="$out" "$binary" gateway ls)"
if [[ $list_output != *"100.64.20.0/24"* ]]; then
  echo "eval: list did not return the persisted recovery CIDR" >&2
  exit 1
fi

if TWARP_HOME="$home" TWARP_OUT="$out" "$binary" gateway add 100.64.20.10 >"$WORK/add.stdout" 2>"$WORK/add.stderr"; then
  echo "eval: add accepted a CIDR covering gateway.socks" >&2
  exit 1
fi
if ! grep -q "contains gateway SOCKS address" "$WORK/add.stderr"; then
  echo "eval: add failed without the gateway SOCKS exclusion" >&2
  exit 1
fi

TWARP_HOME="$home" TWARP_OUT="$out" "$binary" gateway rm 100.64.20.0/24 >/dev/null
python3 - "$home/gateway-ips.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    state = json.load(source)
if state.get("cidrs") != []:
    raise SystemExit("eval: remove did not clear the recovery CIDR")
PY

echo "gateway state recovery eval: PASS"
