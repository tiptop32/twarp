#!/usr/bin/env bash
set -uo pipefail

GATEWAY_HOST=${TWARP_SMOKE_GATEWAY_HOST:-}
IFACE=""
LEAK_CHECK=false
ISP_V6_PREFIX=""

passed=0
failed=0
skipped=0

usage() {
  cat <<'EOF'
Usage: scripts/smoke.sh [options]

Checks a live twarp installation without changing its configuration.

Options:
  --gateway-host HOST  Gateway-routed hostname to probe
                       (or set TWARP_SMOKE_GATEWAY_HOST)
  --iface IFACE        Physical interface for --leak-check (default: active en0/en1)
  --leak-check         Capture physical-interface UDP/53 traffic; requires sudo
  --isp-v6-prefix CIDR Fail if the observed IPv6 address belongs to this ISP prefix
  -h, --help           Show this help
EOF
}

argument_required() {
  if (($# < 2)) || [[ -z $2 ]]; then
    printf 'smoke: %s requires a value\n' "$1" >&2
    usage >&2
    exit 2
  fi
}

while (($# > 0)); do
  case "$1" in
    --gateway-host)
      argument_required "$@"
      GATEWAY_HOST=$2
      shift 2
      ;;
    --iface)
      argument_required "$@"
      IFACE=$2
      shift 2
      ;;
    --leak-check)
      LEAK_CHECK=true
      shift
      ;;
    --isp-v6-prefix)
      argument_required "$@"
      ISP_V6_PREFIX=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'smoke: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

pass() {
  passed=$((passed + 1))
  printf 'PASS %s: %s\n' "$1" "$2"
}

fail() {
  failed=$((failed + 1))
  printf 'FAIL %s: %s\n' "$1" "$2"
}

skip() {
  skipped=$((skipped + 1))
  printf 'SKIP %s: %s\n' "$1" "$2"
}

one_line() {
  tr '\n' ' ' <"$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/twarp-smoke.XXXXXX")
trap 'rm -R -- "$WORK"' EXIT

RENDER_ERROR=""
CLASH_CONTROLLER=""
VPN_SERVER=""
DIRECT_DNS=""
VPN_EGRESS_IP=""

load_render_config() {
  local rendered parsed parse_status

  if ! command -v twarp >/dev/null 2>&1; then
    RENDER_ERROR="twarp is not in PATH"
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    RENDER_ERROR="python3 is not in PATH"
    return
  fi
  if ! rendered=$(twarp render 2>"$WORK/render.err"); then
    RENDER_ERROR="twarp render failed: $(one_line "$WORK/render.err")"
    return
  fi

  parsed=$(python3 -c '
import json
import sys

try:
    config = json.load(sys.stdin)
    clash = config["experimental"]["clash_api"]["external_controller"]
    vpn = next(item["server"] for item in config["outbounds"] if item.get("tag") == "vpn")
    direct_dns = next(item["server"] for item in config["dns"]["servers"] if item.get("tag") == "direct")
    values = (clash, vpn, direct_dns)
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError("required values must be non-empty strings")
    print("\x1f".join(values))
except (KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"invalid rendered config: {error}", file=sys.stderr)
    raise SystemExit(1)
' <<<"$rendered" 2>"$WORK/render-parse.err")
  parse_status=$?
  if ((parse_status != 0)); then
    RENDER_ERROR=$(one_line "$WORK/render-parse.err")
    return
  fi

  IFS=$'\037' read -r CLASH_CONTROLLER VPN_SERVER DIRECT_DNS <<<"$parsed"
}

read_clash_secret() {
  local config_home secret_file

  if [[ -n ${TWARP_HOME:-} ]]; then
    config_home=$TWARP_HOME
  elif ((EUID == 0)); then
    if [[ -z ${SUDO_USER:-} ]]; then
      return 1
    fi
    if ! config_home=$(python3 - "$SUDO_USER" <<'PY'
import os
import pwd
import sys

print(os.path.join(pwd.getpwnam(sys.argv[1]).pw_dir, ".config", "twarp"))
PY
    ); then
      return 1
    fi
  else
    if [[ -z ${HOME:-} ]]; then
      return 1
    fi
    config_home=$HOME/.config/twarp
  fi
  secret_file=$config_home/secrets.yaml
  [[ -r $secret_file ]] || return 1

  python3 - "$secret_file" <<'PY'
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    for line in source:
        if line.startswith("clash_secret:"):
            value = line.split(":", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                print(value)
                raise SystemExit(0)
raise SystemExit(1)
PY
}

resolve_vpn_addresses() {
  local literal

  literal=$(python3 - "$VPN_SERVER" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_address(sys.argv[1]))
except ValueError:
    raise SystemExit(1)
PY
  ) && {
    printf '%s\n' "$literal"
    return
  }

  {
    dig +short "$VPN_SERVER" A
    dig +short "$VPN_SERVER" AAAA
  } | python3 -c '
import ipaddress
import sys

seen = set()
for line in sys.stdin:
    try:
        address = str(ipaddress.ip_address(line.strip()))
    except ValueError:
        continue
    if address not in seen:
        print(address)
        seen.add(address)
'
}

load_render_config

# 1. Installed service health.
if ! command -v twarp >/dev/null 2>&1; then
  fail status "twarp is not in PATH"
elif twarp status >"$WORK/status.out" 2>"$WORK/status.err"; then
  pass status "twarp status exited 0"
else
  status_reason=$(one_line "$WORK/status.err")
  [[ -n $status_reason ]] || status_reason=$(one_line "$WORK/status.out")
  [[ -n $status_reason ]] || status_reason="twarp status exited non-zero"
  fail status "$status_reason"
fi

# 2. Open a gateway host and inspect its live Clash route.
if [[ -z $GATEWAY_HOST ]]; then
  skip gateway-route "set --gateway-host HOST or TWARP_SMOKE_GATEWAY_HOST"
elif [[ -n $RENDER_ERROR ]]; then
  fail gateway-route "$RENDER_ERROR"
elif ! command -v curl >/dev/null 2>&1; then
  fail gateway-route "curl is not in PATH"
elif ! command -v python3 >/dev/null 2>&1; then
  fail gateway-route "python3 is not in PATH"
else
  clash_secret=""
  if ! clash_secret=$(read_clash_secret); then
    skip gateway-route "cannot read clash_secret from the user's secrets.yaml"
  else
    curl -fsSL --limit-rate 1 --max-time 10 -o /dev/null "https://$GATEWAY_HOST/" \
      2>"$WORK/gateway-curl.err" &
    gateway_curl_pid=$!
    gateway_match=false
    gateway_wrong_outbound=""
    gateway_api_error=""
    gateway_curl_was_running=false

    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      sleep 0.2
      if connections=$(curl -fsS --max-time 2 -H "Authorization: Bearer $clash_secret" \
        "http://$CLASH_CONTROLLER/connections" 2>"$WORK/clash.err"); then
        printf '%s\n' "$connections" >"$WORK/connections.json"
        python3 - "$GATEWAY_HOST" "$WORK/connections.json" >"$WORK/gateway-match.out" 2>"$WORK/gateway-match.err" <<'PY'
import json
import sys

host, path = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as source:
        payload = json.load(source)
except (TypeError, ValueError) as error:
    print(error, file=sys.stderr)
    raise SystemExit(2)

found = []
for connection in payload.get("connections", []):
    if connection.get("metadata", {}).get("host") != host:
        continue
    chains = connection.get("chains", [])
    outbound = chains[0] if chains else "<empty>"
    if outbound == "gateway":
        raise SystemExit(0)
    found.append(outbound)
if found:
    print(", ".join(sorted(set(found))))
    raise SystemExit(3)
raise SystemExit(4)
PY
        match_status=$?
        if ((match_status == 0)); then
          gateway_match=true
          break
        elif ((match_status == 3)); then
          gateway_wrong_outbound=$(one_line "$WORK/gateway-match.out")
        elif ((match_status == 2)); then
          gateway_api_error="invalid /connections JSON: $(one_line "$WORK/gateway-match.err")"
        fi
      else
        gateway_api_error="Clash /connections failed: $(one_line "$WORK/clash.err")"
      fi
      if ! kill -0 "$gateway_curl_pid" 2>/dev/null; then
        break
      fi
    done

    if kill -0 "$gateway_curl_pid" 2>/dev/null; then
      gateway_curl_was_running=true
      kill "$gateway_curl_pid" 2>/dev/null || true
    fi
    wait "$gateway_curl_pid" 2>/dev/null
    gateway_curl_status=$?

    if [[ $gateway_match == true ]]; then
      pass gateway-route "$GATEWAY_HOST opened through outbound gateway"
    elif [[ -n $gateway_wrong_outbound ]]; then
      fail gateway-route "$GATEWAY_HOST used outbound $gateway_wrong_outbound, want gateway"
    elif [[ -n $gateway_api_error ]]; then
      fail gateway-route "$gateway_api_error"
    elif [[ $gateway_curl_was_running == false ]] && ((gateway_curl_status != 0)); then
      fail gateway-route "gateway request failed: $(one_line "$WORK/gateway-curl.err")"
    else
      fail gateway-route "no active Clash connection found for $GATEWAY_HOST"
    fi
  fi
fi

# 3. IPv4 Internet traffic must leave through the VPN endpoint.
if [[ -n $RENDER_ERROR ]]; then
  fail vpn-egress "$RENDER_ERROR"
elif ! command -v curl >/dev/null 2>&1 || ! command -v dig >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  fail vpn-egress "requires curl, dig, and python3"
else
  vpn_addresses=$(resolve_vpn_addresses)
  vpn_ipv4=$(printf '%s\n' "$vpn_addresses" | python3 -c '
import ipaddress
import sys

for line in sys.stdin:
    try:
        address = ipaddress.ip_address(line.strip())
    except ValueError:
        continue
    if address.version == 4:
        print(address)
')
  if [[ -z $vpn_ipv4 ]]; then
    fail vpn-egress "dig returned no IPv4 address for the VPN server"
  elif ! vpn_body=$(curl -4 -fsS --max-time 10 https://ifconfig.me/ip 2>"$WORK/vpn-curl.err"); then
    fail vpn-egress "ifconfig.me failed: $(one_line "$WORK/vpn-curl.err")"
  elif ! VPN_EGRESS_IP=$(python3 -c '
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.stdin.read().strip())
except ValueError:
    raise SystemExit(1)
if address.version != 4:
    raise SystemExit(1)
print(address)
' <<<"$vpn_body"); then
    fail vpn-egress "ifconfig.me did not return one IPv4 address"
  elif grep -Fxq "$VPN_EGRESS_IP" <<<"$vpn_ipv4"; then
    pass vpn-egress "$VPN_EGRESS_IP matches the VPN server"
  else
    fail vpn-egress "$VPN_EGRESS_IP does not match VPN server addresses: $(tr '\n' ',' <<<"$vpn_ipv4" | sed 's/,$//')"
  fi
fi

# 4. RU traffic must use the direct/home connection.
if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  fail direct-egress "requires curl and python3"
elif [[ -z $VPN_EGRESS_IP ]]; then
  fail direct-egress "vpn-egress produced no reference IP"
elif ! direct_body=$(curl -fsS --max-time 10 -A curl https://2ip.ru 2>"$WORK/direct-curl.err"); then
  fail direct-egress "2ip.ru failed: $(one_line "$WORK/direct-curl.err")"
elif ! direct_ip=$(python3 -c '
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.stdin.read().strip())
except ValueError:
    raise SystemExit(1)
if address.version != 4:
    raise SystemExit(1)
print(address)
' <<<"$direct_body"); then
  fail direct-egress "2ip.ru did not return one IPv4 address"
elif [[ $direct_ip == "$VPN_EGRESS_IP" ]]; then
  fail direct-egress "$direct_ip equals the VPN egress IP"
else
  pass direct-egress "$direct_ip differs from VPN egress $VPN_EGRESS_IP"
fi

# 5. IPv6 may be unavailable or VPN-routed, but must not match a supplied ISP prefix.
if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  fail ipv6 "requires curl and python3"
elif ! ipv6_body=$(curl -6 -fsS --max-time 5 https://ifconfig.co 2>"$WORK/ipv6-curl.err"); then
  pass ipv6 "IPv6 request timed out or failed; no provider IPv6 observed"
elif ! ipv6_address=$(python3 -c '
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.stdin.read().strip())
except ValueError:
    raise SystemExit(1)
if address.version != 6:
    raise SystemExit(1)
print(address)
' <<<"$ipv6_body"); then
  fail ipv6 "ifconfig.co did not return one IPv6 address"
elif [[ -z $ISP_V6_PREFIX ]]; then
  pass ipv6 "$ipv6_address observed; verify manually that it belongs to the VPN, not the ISP"
else
  python3 - "$ipv6_address" "$ISP_V6_PREFIX" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
    network = ipaddress.ip_network(sys.argv[2], strict=False)
except ValueError as error:
    print(error, file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(0 if address in network else 1)
PY
  prefix_status=$?
  if ((prefix_status == 0)); then
    fail ipv6 "$ipv6_address belongs to ISP prefix $ISP_V6_PREFIX"
  elif ((prefix_status == 1)); then
    pass ipv6 "$ipv6_address is outside ISP prefix $ISP_V6_PREFIX"
  else
    fail ipv6 "invalid --isp-v6-prefix: $ISP_V6_PREFIX"
  fi
fi

# 6. The gateway hostname must resolve through twarp DNS.
if [[ -z $GATEWAY_HOST ]]; then
  skip gateway-dns "set --gateway-host HOST or TWARP_SMOKE_GATEWAY_HOST"
elif ! command -v dig >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  fail gateway-dns "requires dig and python3"
else
  gateway_dns_raw=$(dig +short "$GATEWAY_HOST" 2>"$WORK/gateway-dig.err")
  gateway_dig_status=$?
  gateway_addresses=$(printf '%s\n' "$gateway_dns_raw" | python3 -c '
import ipaddress
import sys

for line in sys.stdin:
    try:
        print(ipaddress.ip_address(line.strip()))
    except ValueError:
        pass
')
  if ((gateway_dig_status != 0)); then
    fail gateway-dns "dig failed: $(one_line "$WORK/gateway-dig.err")"
  elif [[ -z $gateway_addresses ]]; then
    fail gateway-dns "dig returned no address for $GATEWAY_HOST"
  else
    pass gateway-dns "$GATEWAY_HOST resolved to $(tr '\n' ',' <<<"$gateway_addresses" | sed 's/,$//')"
  fi
fi

# 7. Optional privileged capture: every physical UDP/53 destination is allowlisted.
if [[ $LEAK_CHECK == false ]]; then
  skip dns-leak "enable with --leak-check (requires sudo)"
elif ((EUID != 0)); then
  fail dns-leak "run with sudo for --leak-check"
elif [[ -n $RENDER_ERROR ]]; then
  fail dns-leak "$RENDER_ERROR"
elif ! command -v tcpdump >/dev/null 2>&1 || ! command -v dig >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  fail dns-leak "requires tcpdump, dig, and python3"
else
  leak_iface=$IFACE
  if [[ -z $leak_iface ]]; then
    for candidate in en0 en1; do
      if ifconfig "$candidate" 2>/dev/null | grep -q 'status: active'; then
        leak_iface=$candidate
        break
      fi
    done
  fi

  if [[ -z $leak_iface ]]; then
    fail dns-leak "no active en0/en1 interface found; pass --iface IFACE"
  elif ! ifconfig "$leak_iface" >/dev/null 2>&1; then
    fail dns-leak "interface $leak_iface does not exist"
  else
    vpn_allowed=$(resolve_vpn_addresses)
    if [[ -z $vpn_allowed ]]; then
      fail dns-leak "cannot resolve the VPN server for the allowlist"
    else
      vpn_allowed_args=()
      while IFS= read -r address; do
        [[ -n $address ]] && vpn_allowed_args+=("$address")
      done <<<"$vpn_allowed"
      tcpdump -n -l -i "$leak_iface" -c 50 'udp port 53' >"$WORK/tcpdump.out" 2>"$WORK/tcpdump.err" &
      tcpdump_pid=$!
      (
        sleep 10
        kill -INT "$tcpdump_pid" 2>/dev/null || true
      ) &
      timeout_pid=$!
      sleep 1

      if ! kill -0 "$tcpdump_pid" 2>/dev/null; then
        wait "$tcpdump_pid"
        kill "$timeout_pid" 2>/dev/null || true
        wait "$timeout_pid" 2>/dev/null || true
        fail dns-leak "tcpdump failed: $(one_line "$WORK/tcpdump.err")"
      else
        dig example.com >"$WORK/dig-example.out" 2>"$WORK/dig-example.err"
        dig_example_status=$?
        dig ya.ru >"$WORK/dig-ya.out" 2>"$WORK/dig-ya.err"
        dig_ya_status=$?
        wait "$tcpdump_pid"
        tcpdump_status=$?
        kill "$timeout_pid" 2>/dev/null || true
        wait "$timeout_pid" 2>/dev/null || true

        if ((dig_example_status != 0 || dig_ya_status != 0)); then
          fail dns-leak "probe dig failed; capture is inconclusive"
        elif ((tcpdump_status != 0)); then
          fail dns-leak "tcpdump failed: $(one_line "$WORK/tcpdump.err")"
        else
          python3 - "$WORK/tcpdump.out" "$DIRECT_DNS" "${vpn_allowed_args[@]}" >"$WORK/leak-result.out" <<'PY'
import ipaddress
import re
import sys

capture_path = sys.argv[1]
allowed = {str(ipaddress.ip_address(value)) for value in sys.argv[2:]}
observed = set()

with open(capture_path, encoding="utf-8", errors="replace") as capture:
    for line in capture:
        match = re.search(r">\s+(\S+)", line)
        if not match:
            continue
        token = match.group(1).rstrip(":")
        if not token.endswith(".53"):
            continue
        candidate = token[:-3].strip("[]")
        try:
            observed.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue

unexpected = sorted(observed - allowed)
if unexpected:
    print(",".join(unexpected))
    raise SystemExit(1)
print(",".join(sorted(observed)))
PY
          leak_status=$?
          leak_destinations=$(one_line "$WORK/leak-result.out")
          if ((leak_status != 0)); then
            fail dns-leak "unexpected physical UDP/53 destinations: $leak_destinations"
          elif [[ -z $leak_destinations ]]; then
            pass dns-leak "no physical UDP/53 queries observed on $leak_iface"
          else
            pass dns-leak "all physical UDP/53 destinations allowed: $leak_destinations"
          fi
        fi
      fi
    fi
  fi
fi

printf 'smoke: %d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if ((failed > 0)); then
  exit 1
fi
