#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
go test -tags integration ./internal/itest -run '^TestVPNProxy(IgnoresSplitRoutingAndStopsWithSingBox|TLSRequiresTrustedPeer)$' -count=1
