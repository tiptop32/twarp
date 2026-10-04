# LaunchDaemon geo eval

This eval reproduces the geo updater's launchd process context: effective UID 0, no `SUDO_USER`, and an explicit `TWARP_OUT`. It downloads both production rule-sets, verifies their SRS headers and output paths, and checks the root audit record.

Run it on a networked machine with `sudo` access:

```sh
make eval-launchd-geo
```

The runner builds a temporary `twarp` binary and writes only to a temporary directory. It removes the downloaded files when the eval finishes.
