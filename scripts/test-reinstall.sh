#!/usr/bin/env bash
set -euo pipefail

if ((EUID == 0)); then
  echo 'Reinstall workflow tests require an unprivileged user; skipped'
  exit 0
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep Unix socket paths below macOS's sockaddr_un limit, even with a long TMPDIR.
work="$(mktemp -d /tmp/twarp-reinstall-test.XXXXXX)"
fixture_pid=""
cleanup() {
  if [[ -n $fixture_pid ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -R -- "$work"
}
trap cleanup EXIT
export REAL_PERL="$(command -v perl)"
real_sleep="$(command -v sleep)"
mkdir -p "$work/repo/scripts" "$work/bin" "$work/home/.config/twarp" "$work/tmp"
cp "$root/scripts/reinstall.sh" "$work/repo/scripts/reinstall.sh"
printf 'existing configuration\n' >"$work/home/.config/twarp/twarp.yaml"
printf 'synthetic-sensitive-value\n' >"$work/home/.config/twarp/secrets.yaml"
cp "$work/home/.config/twarp/twarp.yaml" "$work/config.before"
cp "$work/home/.config/twarp/secrets.yaml" "$work/secrets.before"

cat >"$work/bin/make" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && ( $1 == build || $1 == install ) ]]
printf 'make %s\n' "$1" >>"$RUN_LOG"
printf 'synthetic-sensitive-value\n' >&2
if [[ ${FAIL_AT:-} == "$1" ]]; then exit 23; fi
if [[ $1 == build ]]; then
  cp "$TEST_WORK/cli" ./twarp
  chmod +x ./twarp
fi
SH
cat >"$work/cli" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  render)
    [[ $# == 3 && $2 == --out ]]
    printf 'twarp render\n' >>"$RUN_LOG"
    mkdir -p "$3"
    printf '{"password":"synthetic-sensitive-value"}\n' >"$3/config.json"
    ;;
  apply)
    [[ $# == 1 ]]
    printf 'twarp apply\n' >>"$RUN_LOG"
    ;;
  xray)
    [[ $# == 3 && $2 == install && $3 == google-ai ]]
    printf 'twarp xray install google-ai\n' >>"$RUN_LOG"
    ;;
  status)
    [[ $# == 2 && $2 == --net ]]
    printf 'twarp status --net\n' >>"$RUN_LOG"
    ;;
  *) exit 90 ;;
esac
printf 'synthetic-sensitive-value\n'
if [[ ${FAIL_AT:-} == "$1" ]]; then exit 23; fi
SH
cat >"$work/bin/sing-box" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 && $1 == check && $2 == -c && -f $3 && ${TEST_PRIVILEGED:-} == 1 ]]
printf 'sing-box check\n' >>"$RUN_LOG"
printf 'synthetic-sensitive-value\n' >&2
if [[ ${FAIL_AT:-} == validate ]]; then exit 23; fi
SH
cat >"$work/bin/sudo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == "$TWARP_SINGBOX" ]]; then
  shift
  TEST_PRIVILEGED=1 exec "$TWARP_SINGBOX" "$@"
fi
[[ $# == 4 && $1 == launchctl && $2 == kickstart && $3 == -k && $4 == system/dev.twarp.daemon ]]
printf 'sudo launchctl kickstart -k system/dev.twarp.daemon\n' >>"$RUN_LOG"
printf 'synthetic-sensitive-value\n' >&2
if [[ ${FAIL_AT:-} == restart ]]; then exit 23; fi
SH
# sudo records the restart without ever contacting the real system launchctl.
printf '#!/usr/bin/env bash\nexit 92\n' >"$work/bin/launchctl"
cat >"$work/bin/perl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'daemon ready probe\n' >>"$RUN_LOG"
if [[ ${TEST_REAL_PROBE:-0} == 1 ]]; then exec "$REAL_PERL" "$@"; fi
if [[ ${TEST_NOT_READY:-0} != 0 ]]; then
  count=0
  if [[ -f $TEST_WORK/probes ]]; then read -r count <"$TEST_WORK/probes"; fi
  count=$((count + 1))
  printf '%s\n' "$count" >"$TEST_WORK/probes"
  if ((count <= TEST_NOT_READY)); then exit 1; fi
fi
SH
printf '#!/usr/bin/env bash\nexit 0\n' >"$work/bin/sleep"
chmod +x "$work/bin/"*

export TEST_WORK="$work" RUN_LOG="$work/commands"
export HOME="$work/home" TMPDIR="$work/tmp" TWARP_SINGBOX="$work/bin/sing-box"
export TWARP_SOCKET="$work/daemon.sock"
export PATH="$work/bin:$PATH"
unset TWARP_HOME TWARP_OUT
cd -- "$work"

assert_private_cleanup() {
  if grep -qF 'synthetic-sensitive-value' "$work/output"; then
    echo 'reinstall leaked child command output' >&2
    exit 1
  fi
  local candidate
  for candidate in "$work/tmp"/twarp-reinstall.*; do
    if [[ -e $candidate ]]; then
      printf 'reinstall left behind private temporary files: %s (after %s)\n' "${candidate##*/}" "${stage:-successful run}" >&2
      find "$candidate" -maxdepth 2 -type f -print >&2
      cat "$work/output" >&2
      exit 1
    fi
  done
  cmp "$work/config.before" "$HOME/.config/twarp/twarp.yaml"
  cmp "$work/secrets.before" "$HOME/.config/twarp/secrets.yaml"
}

cat >"$work/expected" <<'EOF'
make build
twarp render
sing-box check
make install
sudo launchctl kickstart -k system/dev.twarp.daemon
daemon ready probe
twarp apply
twarp xray install google-ai
twarp status --net
EOF
: >"$RUN_LOG"
/bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1
diff -u "$work/expected" "$RUN_LOG"
assert_private_cleanup

# The optional agent is never touched unless the caller requests it.
: >"$RUN_LOG"
/bin/bash "$work/repo/scripts/reinstall.sh" >"$work/output" 2>&1
grep -v '^twarp xray ' "$work/expected" >"$work/expected-default"
diff -u "$work/expected-default" "$RUN_LOG"
assert_private_cleanup

# Wait for a listening daemon without retrying a mutating apply.
: >"$RUN_LOG"
rm -f "$work/probes"
TEST_NOT_READY=2 /bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1
head -n 5 "$work/expected" >"$work/expected-delayed"
printf 'daemon ready probe\ndaemon ready probe\ndaemon ready probe\n' >>"$work/expected-delayed"
tail -n 3 "$work/expected" >>"$work/expected-delayed"
diff -u "$work/expected-delayed" "$RUN_LOG"
assert_private_cleanup

: >"$RUN_LOG"
rm -f "$work/probes"
if TEST_NOT_READY=20 /bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1; then
  echo 'reinstall applied before daemon readiness' >&2
  exit 1
else
  code=$?
fi
[[ $code == 1 ]]
head -n 5 "$work/expected" >"$work/expected-timeout"
for ((probe = 0; probe < 20; probe++)); do
  printf 'daemon ready probe\n' >>"$work/expected-timeout"
done
diff -u "$work/expected-timeout" "$RUN_LOG"
assert_private_cleanup

# Exercise the actual connect-only probe against a real Unix socket.
# The listener sends nothing: readiness must not wait for daemon input or output.
cat >"$work/socket-fixture.go" <<'GO'
package main

import (
	"errors"
	"io"
	"net"
	"os"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: os.Args[1], Net: "unix"})
	must(err)
	defer listener.Close()
	if os.Args[2] == "stale" {
		listener.SetUnlinkOnClose(false)
		must(listener.Close())
		return
	}
	must(os.WriteFile(os.Args[3], nil, 0600))
	must(listener.SetDeadline(time.Now().Add(5 * time.Second)))
	conn, err := listener.AcceptUnix()
	must(err)
	defer conn.Close()
	must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
	var data [1]byte
	n, err := conn.Read(data[:])
	result := "probe did not disconnect before the server deadline\n"
	if n == 0 && errors.Is(err, io.EOF) {
		result = "closed\n"
	}
	must(os.WriteFile(os.Args[4], []byte(result), 0600))
}
GO
go build -o "$work/socket-fixture" "$work/socket-fixture.go"
"$work/socket-fixture" "$TWARP_SOCKET" listening "$work/listening" "$work/connection-result" >"$work/fixture.log" 2>&1 &
fixture_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  if [[ -f $work/listening ]]; then break; fi
  "$real_sleep" 0.05
done
[[ -f $work/listening ]]
: >"$RUN_LOG"
TEST_REAL_PROBE=1 /bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1
diff -u "$work/expected" "$RUN_LOG"
wait "$fixture_pid"
fixture_pid=""
[[ $(cat "$work/connection-result") == closed ]]
assert_private_cleanup

# A missing or stale socket must never admit apply, even with the real probe.
for socket_state in missing stale; do
  if [[ $socket_state == stale ]]; then
    "$work/socket-fixture" "$TWARP_SOCKET" stale
    [[ -S $TWARP_SOCKET ]]
  else
    [[ ! -e $TWARP_SOCKET ]]
  fi
  : >"$RUN_LOG"
  if TEST_REAL_PROBE=1 /bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1; then
    printf 'reinstall applied with a %s daemon socket\n' "$socket_state" >&2
    exit 1
  else
    code=$?
  fi
  [[ $code == 1 ]]
  diff -u "$work/expected-timeout" "$RUN_LOG"
  assert_private_cleanup
done

# Every failing boundary must prevent all subsequent changes and verification.
line=0
for stage in build render validate install restart apply xray status; do
  if [[ $stage == apply ]]; then line=$((line + 1)); fi
  line=$((line + 1))
  : >"$RUN_LOG"
  if FAIL_AT="$stage" /bin/bash "$work/repo/scripts/reinstall.sh" --xray google-ai >"$work/output" 2>&1; then
    printf 'reinstall ignored failure at %s\n' "$stage" >&2
    exit 1
  else
    code=$?
  fi
  if [[ $code != 23 ]]; then
    printf 'reinstall lost failure exit code at %s: %s\n' "$stage" "$code" >&2
    exit 1
  fi
  head -n "$line" "$work/expected" >"$work/expected-prefix"
  diff -u "$work/expected-prefix" "$RUN_LOG"
  assert_private_cleanup
done

for argument in --xray --unsupported; do
  : >"$RUN_LOG"
  if /bin/bash "$work/repo/scripts/reinstall.sh" "$argument" >"$work/output" 2>&1; then
    echo 'reinstall accepted an invalid argument' >&2
    exit 1
  else
    code=$?
  fi
  [[ $code == 2 && ! -s $RUN_LOG ]]
  assert_private_cleanup
done

echo 'Reinstall command ordering, fail-fast and private cleanup checks passed'
