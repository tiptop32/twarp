# Multiple VPN routing eval

`./evals/multi_vpn/run.sh` runs on macOS with sing-box 1.14+ and Xray on PATH. All three scenarios must pass; skipped or missing cases fail the runner.

- Concurrent primary and secondary routes, domain and CIDR selectors, gateway and primary-only loopback proxy, and a connection failure with the secondary unavailable.
- Process priority over a conflicting domain, process-attributed and domain-only DNS selection through independent SOCKS detours, and the local DNS exception.
- A real Xray-to-Xray VLESS REALITY connection through sing-box's fixed TCP bridge, with an authenticated local hop, DNS over HTTPS, and UDP/443. Stop the server and then the client. Try a different Xray key and a foreign proxy on the former port. The primary keeps accepting new connections; selected TCP, DNS, and UDP do not fall back.

The fixtures use synthetic credentials and loopback servers, not the installed tunnel or its credentials. The Xray scenario keeps the rendered DoH transport and trusts only its local test certificate for that resolver.

With `TWARP_TEST_XRAY_LAUNCHD=1`, the Xray scenario starts and removes a uniquely named login agent in the current GUI session using a temporary home. It never changes the installed sing-box or twarpd.
