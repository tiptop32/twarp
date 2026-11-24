#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
if [[ "$(go env GOOS)" != darwin ]]; then
  echo 'multi_vpn: requires macOS for process attribution' >&2
  exit 1
fi

go test -json -tags integration ./internal/itest -run '^(TestMultiVPN(RouteAndFailure|ProcessWinsAndDNSUsesSelectedDetour)|TestXraySidecarTrafficAndFailure)$' -count=1 |
  awk '
    /"Output":/ { print }
    /"Action":"pass"/ && /"Test":"TestMultiVPNRouteAndFailure"/ { route = 1 }
    /"Action":"pass"/ && /"Test":"TestMultiVPNProcessWinsAndDNSUsesSelectedDetour"/ { dns = 1 }
    /"Action":"pass"/ && /"Test":"TestXraySidecarTrafficAndFailure"/ { xray = 1 }
    END {
      if (!route || !dns || !xray) {
        print "multi_vpn: expected all three scenarios to pass (requires Xray)" > "/dev/stderr"
        exit 1
      }
    }
  '
