# Multiple VPN routing eval

`./evals/multi_vpn/run.sh` runs on macOS with sing-box 1.14+ and Xray with TLS/XHTTP support on PATH. All four scenarios must pass; skipped or missing cases fail the runner. No sudo or installed VPN credentials are needed.

- Concurrent primary and secondary routes, domain and CIDR selectors, gateway and primary-only loopback proxy, and a connection failure with the secondary unavailable.
- Process priority over a conflicting domain, process-attributed and domain-only DNS selection through independent SOCKS detours, and the local DNS exception.
- A real Xray-to-Xray VLESS REALITY connection through sing-box's fixed TCP bridge, with an authenticated local hop, DNS over HTTPS, and UDP/443. Stop the server and then the client. Try a different Xray key and a foreign proxy on the former port. The primary keeps accepting new connections; selected TCP, DNS, and UDP do not fall back.
- A real Xray TLS/XHTTP server and HTTP upstream, reached through the rendered sing-box route, authenticated local Xray ingress, and sing-box's fixed TCP bridge. The fixture requires distinct TLS SNI and HTTP host, a custom path, HTTP/2, stream-up mode, and non-default padding from XHTTP `extra`. It observes both sing-box hops and checks the upstream response body.

The fixtures use synthetic credentials and loopback servers, not the installed tunnel or its credentials. The REALITY scenario keeps the rendered DoH transport and trusts only its local test certificate for that resolver. The XHTTP scenario trusts only its generated TLS certificate; it does not disable certificate or hostname verification.

With `TWARP_TEST_XRAY_LAUNCHD=1`, the REALITY scenario starts and removes a uniquely named login agent in the current GUI session using a temporary home. It never changes the installed sing-box or twarpd. The XHTTP scenario always uses local subprocesses.
