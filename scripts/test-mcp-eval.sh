#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/twarp-mcp-runner-test.XXXXXX")"
mkdir -m 700 "$work/agent"
trap 'rm -R -- "$work"' EXIT
cat >"$work/omp" <<'PY'
#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
if sys.argv[1:] == ['config', 'path']:
    print(os.environ['PI_CODING_AGENT_DIR'])
    raise SystemExit(0)

args = sys.argv[1:]
assert sys.stdin.read() == "", "case answers leaked to stdin"
assert '--no-tools' in args
assert args[args.index('--trusted-extension') + 1].endswith('/evals/mcp_tool_choice/restrict-tools.ts')
assert all(flag in args for flag in ("--no-session", "--no-skills", "--no-rules", "--no-context-files"))
assert 'claude' in pathlib.Path(args[args.index('--config') + 1]).read_text()
assert os.environ.get('CLAUDE_CONFIG_DIR') is None and os.environ.get('PI_CONFIG_FILES') is None
assert pathlib.Path(os.path.realpath(os.environ['HOME'])).parent == pathlib.Path(os.getcwd()).parent
assert os.environ['PI_CONFIG_DIR'] == '.omp-eval'
config = json.loads(pathlib.Path('.omp/mcp.json').read_text())
server = config['mcpServers']['twarp']
assert server['args'] == ['mcp']
assert os.path.realpath(server['env']['TWARP_HOME']).startswith(os.getcwd() + '/')
assert os.path.realpath(server['env']['TWARP_OUT']).startswith(os.getcwd() + '/')
if '0.0.0.0/0' in args[args.index('-p') + 1]:
    answer = 'Не добавил: шлюз принимает только адреса внутри 100.64.0.0/10.' if os.environ.get('TEST_NO_EXPLANATION') != '1' else 'Не добавил.'
else:
    if os.environ.get('TEST_OMIT_MUTATION') != '1':
        subprocess.run([server['command'], 'gateway', 'add', '100.64.20.10', '--comment', 'synthetic'], env={**os.environ, **server['env']}, check=True)
    answer = 'Gateway request processed.'
if os.environ.get('TEST_NO_RESTRICTION') != '1':
    print('MCP_EVAL_TOOLS_RESTRICTED', file=sys.stderr)
print(answer)
PY
chmod +x "$work/omp"
PI_CODING_AGENT_DIR="$work/agent" TWARP_EVAL_REPORT_DIR="$work/reports" PATH="$work:$PATH" "$root/evals/mcp_tool_choice/run.sh" --case add-single >/dev/null
if TEST_OMIT_MUTATION=1 PI_CODING_AGENT_DIR="$work/agent" TWARP_EVAL_REPORT_DIR="$work/reports" PATH="$work:$PATH" "$root/evals/mcp_tool_choice/run.sh" --case add-single >/dev/null; then
  echo 'MCP eval runner accepted unchanged state' >&2
  exit 1
fi
if TEST_NO_RESTRICTION=1 PI_CODING_AGENT_DIR="$work/agent" TWARP_EVAL_REPORT_DIR="$work/reports" PATH="$work:$PATH" "$root/evals/mcp_tool_choice/run.sh" --case add-single >/dev/null; then
  echo 'MCP eval runner accepted a missing restriction' >&2
  exit 1
fi
PI_CODING_AGENT_DIR="$work/agent" TWARP_EVAL_REPORT_DIR="$work/reports" PATH="$work:$PATH" "$root/evals/mcp_tool_choice/run.sh" --case reject-default-route >/dev/null
if TEST_NO_EXPLANATION=1 PI_CODING_AGENT_DIR="$work/agent" TWARP_EVAL_REPORT_DIR="$work/reports" PATH="$work:$PATH" "$root/evals/mcp_tool_choice/run.sh" --case reject-default-route >/dev/null; then
  echo 'MCP eval runner accepted a refusal without explanation' >&2
  exit 1
fi
echo 'MCP eval runner isolation and state checks passed'
