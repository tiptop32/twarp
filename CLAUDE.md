# Agent instructions

## Checks

- Gate: `make test`.
- Lint and shell checks: `make lint`.
- Integration suite: `make integration`.
- MCP quality eval: `make eval`.
- Secret scan: `make secrets-check`.
- Enable the pre-commit hook with `git config core.hooksPath .githooks`.

Run the checks that cover the changed surface. Documentation-only changes still require `make test`, `make lint`, and `make secrets-check` before handoff.

## Project rules

- Keep the route order stable: explicit `gateway` rules must come before `ip_is_private`; otherwise RFC1918 gateway hosts can go direct.
- Support sing-box 1.14 or newer. Keep `route.default_domain_resolver` and `dns.strategy: prefer_ipv4` aligned with the current renderer.
- Never commit VPN URIs, UUIDs, private keys, public keys, passwords, or other credentials. Tests and examples use synthetic fixtures only: `example` domains, `100.64.0.0/10`, and TEST-NET ranges.
- Use neutral names in docs, code, and fixtures: `gateway`, `direct`, and `vpn`.
- Do not move or edit plans under `docs/plans/` unless the task explicitly asks for it.
