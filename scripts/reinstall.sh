#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/reinstall.sh [--xray TUNNEL]

Rebuild and update an existing system twarp installation, without uninstalling.
Run as your normal macOS user; sudo asks for the installation/restart password.
The existing user configuration and profiles must already be configured.

  --xray TUNNEL  Reinstall this configured Xray login agent after apply
                 (for example: --xray google-ai)
  -h, --help     Show this help
EOF
}

xray_tunnel=""
while (($# > 0)); do
  case "$1" in
    --xray)
      if (($# < 2)) || [[ -z $2 || -n $xray_tunnel ]]; then
        printf 'reinstall: --xray requires one tunnel name\n' >&2
        exit 2
      fi
      xray_tunnel=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'reinstall: unsupported argument; use --help\n' >&2
      exit 2
      ;;
  esac
done

if ((EUID == 0)); then
  printf 'reinstall: run as your normal user, not through sudo\n' >&2
  exit 1
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$root"
for command in make sudo launchctl nc sleep; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'reinstall: required command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

singbox=${TWARP_SINGBOX:-}
if [[ -z $singbox ]]; then
  for candidate in /opt/homebrew/opt/sing-box/bin/sing-box /usr/local/opt/sing-box/bin/sing-box; do
    if [[ -x $candidate ]]; then
      singbox=$candidate
      break
    fi
  done
fi
if [[ -z $singbox || ! -x $singbox ]]; then
  printf 'reinstall: install sing-box or set TWARP_SINGBOX to its executable path\n' >&2
  exit 1
fi
export TWARP_SINGBOX="$singbox"

# Rendered configs and diagnostics can contain credentials. Never echo them.
umask 077
work="$(mktemp -d "${TMPDIR:-/tmp}/twarp-reinstall.XXXXXX")"
cleanup() {
  if [[ -d $work ]]; then
    rm -R -- "$work"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

run_step() {
  local label=$1 code
  shift
  printf 'reinstall: %s\n' "$label"
  if "$@" >"$work/step.log" 2>&1; then
    return 0
  else
    code=$?
    printf 'reinstall: %s failed (exit %s); stopped. Command output is hidden to protect credentials.\n' "$label" "$code" >&2
    cleanup
    exit "$code"
  fi
}

wait_for_daemon() {
  local attempt
  for ((attempt = 0; attempt < 20; attempt++)); do
    if nc -z -w 1 -U "${TWARP_SOCKET:-/var/run/twarp/twarpd.sock}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_step build make build
run_step render ./twarp render --out "$work/render"
run_step validate sudo "$singbox" check -c "$work/render/config.json"
run_step install make install
run_step restart-daemon sudo launchctl kickstart -k system/dev.twarp.daemon
run_step wait-daemon wait_for_daemon
run_step apply ./twarp apply
if [[ -n $xray_tunnel ]]; then
  run_step install-xray ./twarp xray install "$xray_tunnel"
fi
run_step status ./twarp status --net
cleanup
printf 'reinstall: completed; status --net passed\n'
