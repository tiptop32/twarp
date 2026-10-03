# MCP tool-choice eval

This eval measures whether Claude chooses the correct `twarp` MCP tool and CIDR from a natural-language request. It checks the final gateway state for 10 valid requests. It also checks that three unsafe or unsupported requests leave the state unchanged and receive an explanation.

## Run the eval

Run all 13 cases:

```sh
make eval
```

Run one case while editing a tool description:

```sh
./evals/mcp_tool_choice/run.sh --case add-single
```

Validate the cases, isolated setup, and generated Claude commands without calling Claude:

```sh
./evals/mcp_tool_choice/run.sh --dry-run
```

Each case gets fresh `TWARP_HOME` and `TWARP_OUT` directories. The runner builds `twarp`, loads the case's initial CIDRs through the CLI, and gives Claude access only to `gateway_ip_add`, `gateway_ip_remove`, and `gateway_ip_list`.

## Pass criteria and reports

A full run passes with at least 12 of 13 cases and no failed negative case. A single-case run passes only when that case passes.

The runner writes each full or single-case report to `/tmp/twarp-eval/<UTC timestamp>.json`. The report includes the expected and actual CIDRs, the tail of Claude's response, and the failure reason.

If a case fails because Claude chose the wrong tool, CIDR, or refusal, update the tool descriptions in `internal/mcp/server.go`. Rerun the failed case before running the full eval.
