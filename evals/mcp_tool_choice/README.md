# MCP tool-choice eval

This eval measures whether omp chooses the correct `twarp` MCP tool and CIDR from a natural-language request. It checks the final gateway state for 10 valid requests. It also checks that three unsafe or unsupported requests leave the state unchanged and receive an explanation.

## Run the eval

Run all 13 cases:

```sh
make eval
```

Run one case while editing a tool description:

```sh
./evals/mcp_tool_choice/run.sh --case add-single
```

Validate the cases, isolated setup, and generated omp commands without calling a model:

```sh
./evals/mcp_tool_choice/run.sh --dry-run
```

Each case gets fresh `TWARP_HOME` and `TWARP_OUT` directories. The runner builds `twarp` and loads the case's initial CIDRs through the CLI. It isolates omp discovery in a private temporary agent directory, disables foreign discovery and memory, and uses `agent-lb/gpt-6.2-sol`. Set `AGENT_LB_API_KEY` in the environment and configure the agent-lb provider in the active omp profile; bun is required to isolate its model metadata. Credentials, commands, and other provider configurations are not copied. An explicitly trusted extension restricts calls to `gateway_ip_add`, `gateway_ip_remove`, and `gateway_ip_list`; all other tools are blocked. The agent runs in the case directory with stdin closed and no repository context.

## Pass criteria and reports

A full run passes with at least 12 of 13 cases and no failed negative case. A single-case run passes only when that case passes.

The runner writes each full or single-case JSON report to a unique path under `/tmp/twarp-eval/`. The report includes the expected and actual CIDRs, the tail of the model's response, and the failure reason.

If a case fails because the model chose the wrong tool, CIDR, or refusal, update the tool descriptions in `internal/mcp/server.go`. Rerun the failed case before running the full eval.
