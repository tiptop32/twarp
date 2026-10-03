#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
CASES_FILE="$SCRIPT_DIR/cases.json"
ALLOWED_TOOLS="mcp__twarp__gateway_ip_add,mcp__twarp__gateway_ip_remove,mcp__twarp__gateway_ip_list"
TIMEOUT_SECONDS=180
DRY_RUN=false
CASE_ID=""

usage() {
  echo "Usage: $0 [--dry-run] [--case ID]" >&2
}

while (($# > 0)); do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --case)
      if (($# < 2)); then
        usage
        exit 2
      fi
      CASE_ID=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

for dependency in go python3 perl; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "eval: missing required command: $dependency" >&2
    exit 1
  fi
done
if [[ $DRY_RUN == false ]] && ! command -v claude >/dev/null 2>&1; then
  echo "eval: missing required command: claude" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/twarp-mcp-eval.XXXXXX")"
trap 'rm -R -- "$WORK"' EXIT
TWARP_BIN="$WORK/twarp"
CASE_ROWS="$WORK/cases.tsv"
RESULTS_FILE="$WORK/results.jsonl"

(
  cd "$REPO_ROOT"
  go build -o "$TWARP_BIN" ./cmd/twarp
)

python3 - "$CASES_FILE" "$CASE_ID" >"$CASE_ROWS" <<'PY'
import ipaddress
import json
import sys

path, selected_id = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    cases = json.load(source)

if not isinstance(cases, list) or len(cases) != 13:
    raise SystemExit("cases.json must contain exactly 13 cases")
ids = [case.get("id") for case in cases]
if len(set(ids)) != len(ids):
    raise SystemExit("case IDs must be unique")
if sum(not case.get("negative", False) for case in cases) != 10:
    raise SystemExit("cases.json must contain exactly 10 positive cases")
if sum(bool(case.get("negative", False)) for case in cases) != 3:
    raise SystemExit("cases.json must contain exactly 3 negative cases")

allowed = ipaddress.ip_network("100.64.0.0/10")
for case in cases:
    if set(case) != {"id", "prompt", "initial", "expected", "negative"}:
        raise SystemExit(f"{case.get('id', '<unknown>')}: invalid case fields")
    if not isinstance(case["id"], str) or not case["id"]:
        raise SystemExit("every case needs a non-empty string ID")
    if not isinstance(case["prompt"], str) or not case["prompt"]:
        raise SystemExit(f"{case['id']}: prompt must be a non-empty string")
    if "\t" in case["prompt"] or "\n" in case["prompt"]:
        raise SystemExit(f"{case['id']}: prompt must fit on one TSV line")
    if not isinstance(case["negative"], bool):
        raise SystemExit(f"{case['id']}: negative must be boolean")
    for field in ("initial", "expected"):
        values = case[field]
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise SystemExit(f"{case['id']}: {field} must be a string array")
        normalized = [str(ipaddress.ip_network(value, strict=False)) for value in values]
        if normalized != values:
            raise SystemExit(f"{case['id']}: {field} must contain canonical CIDRs")
        if len(set(values)) != len(values):
            raise SystemExit(f"{case['id']}: {field} contains duplicate CIDRs")
        if any(ipaddress.ip_network(value).version != 4 or not ipaddress.ip_network(value).subnet_of(allowed) for value in values):
            raise SystemExit(f"{case['id']}: {field} must stay inside 100.64.0.0/10")

selected = cases
if selected_id:
    selected = [case for case in cases if case["id"] == selected_id]
    if not selected:
        raise SystemExit(f"unknown case ID: {selected_id}")

for case in selected:
    fields = [
        case["id"],
        case["prompt"],
        json.dumps(case["initial"], separators=(",", ":")),
        json.dumps(case["expected"], separators=(",", ":")),
        "true" if case["negative"] else "false",
    ]
    print("\t".join(fields))
PY

compare_state() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import json
import os
import sys

state_path, expected_json = sys.argv[1:]
if os.path.exists(state_path):
    with open(state_path, encoding="utf-8") as source:
        state = json.load(source)
    entries = state.get("cidrs", [])
else:
    entries = []

def canonical(value):
    return str(ipaddress.ip_network(value, strict=False))

got = [canonical(entry["cidr"] if isinstance(entry, dict) else entry) for entry in entries]
expected = [canonical(value) for value in json.loads(expected_json)]
sort_key = lambda value: (
    ipaddress.ip_network(value).version,
    int(ipaddress.ip_network(value).network_address),
    ipaddress.ip_network(value).prefixlen,
)
got = sorted(set(got), key=sort_key)
expected = sorted(set(expected), key=sort_key)
print("true" if got == expected else "false", json.dumps(got, separators=(",", ":")), sep="\t")
PY
}

run_with_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$TIMEOUT_SECONDS" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$TIMEOUT_SECONDS" "$@"
  else
    perl -e 'alarm shift; exec @ARGV' "$TIMEOUT_SECONDS" "$@"
  fi
}

passed=0
total=0
negatives_failed=0

while IFS=$'\t' read -r id prompt initial_json expected_json negative; do
  total=$((total + 1))
  case_dir="$(mktemp -d "$WORK/case.XXXXXX")"
  home="$case_dir/home"
  out="$case_dir/out"
  stdout_file="$case_dir/stdout.txt"
  stderr_file="$case_dir/stderr.txt"
  mcp_config="$case_dir/mcp.json"
  mkdir -p "$home" "$out/rules"

  cat >"$home/twarp.yaml" <<'YAML'
gateway:
  socks: 192.168.1.10:1080
  domains: [intra.example]
  dns: 100.64.0.53
  allowed_ranges: [100.64.0.0/10]
YAML

  while IFS= read -r cidr; do
    if ! TWARP_HOME="$home" TWARP_OUT="$out" "$TWARP_BIN" gateway add "$cidr" --comment "existing host" \
      >"$case_dir/setup.stdout" 2>"$case_dir/setup.stderr"; then
      echo "eval: setup failed for $id" >&2
      tail -20 "$case_dir/setup.stderr" >&2
      exit 1
    fi
  done < <(python3 - "$initial_json" <<'PY'
import json
import sys

for value in json.loads(sys.argv[1]):
    print(value)
PY
  )

  IFS=$'\t' read -r setup_matches setup_got < <(compare_state "$home/gateway-ips.json" "$initial_json")
  if [[ $setup_matches != true ]]; then
    echo "eval: setup state mismatch for $id: expected $initial_json, got $setup_got" >&2
    exit 1
  fi

  python3 - "$TWARP_BIN" "$home" "$out" >"$mcp_config" <<'PY'
import json
import sys

binary, home, out = sys.argv[1:]
json.dump({
    "mcpServers": {
        "twarp": {
            "command": binary,
            "args": ["mcp"],
            "env": {"TWARP_HOME": home, "TWARP_OUT": out},
        }
    }
}, sys.stdout)
PY

  claude_cmd=(
    claude -p "$prompt"
    --strict-mcp-config
    --mcp-config "$mcp_config"
    --allowedTools "$ALLOWED_TOOLS"
    --output-format text
  )

  if [[ $DRY_RUN == true ]]; then
    printf 'DRY-RUN %s: ' "$id"
    python3 - "${claude_cmd[@]}" <<'PY'
import shlex
import sys

print(shlex.join(sys.argv[1:]))
PY
    continue
  fi

  # Isolation: stdin is /dev/null (the case loop reads $CASE_ROWS on stdin, and
  # claude -p appends piped stdin to the prompt, which leaked every expected
  # answer), and the agent runs from the case directory, not the repository.
  if (cd "$case_dir" && run_with_timeout "${claude_cmd[@]}" </dev/null >"$stdout_file" 2>"$stderr_file"); then
    claude_status=0
  else
    claude_status=$?
  fi

  IFS=$'\t' read -r state_matches got_json < <(compare_state "$home/gateway-ips.json" "$expected_json")
  case_pass=true
  reasons=()
  if ((claude_status != 0)); then
    case_pass=false
    reasons+=("claude exited $claude_status")
  fi
  if [[ $state_matches != true ]]; then
    case_pass=false
    reasons+=("state mismatch")
  fi
  if [[ $id == list ]]; then
    while IFS= read -r cidr; do
      if ! grep -Fq -- "$cidr" "$stdout_file"; then
        case_pass=false
        reasons+=("list output missing $cidr")
      fi
    done < <(python3 - "$expected_json" <<'PY'
import json
import sys

for value in json.loads(sys.argv[1]):
    print(value)
PY
    )
  fi
  # Guard against a leaky harness: the agent must never see the eval itself.
  if grep -Eiq '(cases\.json|evals/|\beval\b|кейс)' "$stdout_file"; then
    case_pass=false
    reasons+=("contaminated: agent response references the eval harness")
  fi
  if [[ $negative == true ]] && ! grep -Eiq '(allowed|range|диапазон|domain|домен)' "$stdout_file"; then
    case_pass=false
    reasons+=("negative response lacks an explanation")
  fi

  reason=""
  if ((${#reasons[@]} > 0)); then
    reason=$(IFS='; '; echo "${reasons[*]}")
  fi
  python3 - "$id" "$case_pass" "$negative" "$expected_json" "$got_json" "$stdout_file" "$reason" \
    >>"$RESULTS_FILE" <<'PY'
import json
import sys

case_id, passed, negative, expected, got, stdout_path, reason = sys.argv[1:]
with open(stdout_path, encoding="utf-8", errors="replace") as source:
    stdout_tail = source.read()[-2000:]
print(json.dumps({
    "id": case_id,
    "pass": passed == "true",
    "negative": negative == "true",
    "expected": json.loads(expected),
    "got": json.loads(got),
    "stdout_tail": stdout_tail,
    "reason": reason,
}, ensure_ascii=False, separators=(",", ":")))
PY

  if [[ $case_pass == true ]]; then
    passed=$((passed + 1))
    echo "PASS $id"
  else
    if [[ $negative == true ]]; then
      negatives_failed=$((negatives_failed + 1))
    fi
    echo "FAIL $id: $reason"
  fi
done <"$CASE_ROWS"

if [[ $DRY_RUN == true ]]; then
  echo "dry-run passed $total/$total"
  exit 0
fi

report_dir=/tmp/twarp-eval
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
report_path="$report_dir/$timestamp.json"
mkdir -p "$report_dir"
python3 - "$RESULTS_FILE" "$report_path" "$passed" "$total" "$negatives_failed" <<'PY'
import json
import sys

results_path, report_path, passed, total, negatives_failed = sys.argv[1:]
with open(results_path, encoding="utf-8") as source:
    cases = [json.loads(line) for line in source if line.strip()]
report = {
    "passed": int(passed),
    "total": int(total),
    "negatives_failed": int(negatives_failed),
    "cases": cases,
}
with open(report_path, "w", encoding="utf-8") as destination:
    json.dump(report, destination, ensure_ascii=False, indent=2)
    destination.write("\n")
PY

echo "passed $passed/$total"
echo "report: $report_path"

required=$total
if ((total == 13)); then
  required=12
fi
if ((passed < required || negatives_failed > 0)); then
  exit 1
fi
