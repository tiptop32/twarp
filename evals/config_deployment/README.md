# Config deployment eval

This eval exercises the safety properties of `twarp apply` and `twarp install` at their command and launchd boundaries.

Run it with:

```sh
make eval-config-deployment
```

The scenarios verify that:

- a failed `sing-box check` restores the installed gateway rule-set, leaves `config.json` byte-identical, and does not touch the running service;
- a failed service lookup during `apply` and a failed plist write during `install` preserve the installed config without unloading the service;
- a geo service load failure during `install` does not unload the active sing-box service and restores both installed files;
- a failed `apply` reload restores both installed files and retries reload with the previous config;
- a failed config promotion during `install` restores the previous config and gateway rule-set;
- a successful check promotes the candidate with mode `0600` before reloading or installing the service;
- a concurrent gateway add waits for install to write its rule-set, then publishes the newer rule-set without losing the CIDR.
- root-run rule-set writes change ownership on the open temporary file before rename; a symlink at the destination is replaced without changing its target, and MCP writes stay unprivileged.

The concurrency scenario runs with Go's race detector. The command exits nonzero on any failed scenario.
