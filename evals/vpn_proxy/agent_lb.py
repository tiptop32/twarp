"""Exercise the sandboxed Agent LB HTTP path against a local synthetic upstream."""

import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


PROFILE = Path(__file__).resolve().parents[2] / "scripts" / "proxy-only.sb"
MODEL = "claude-sonnet-4-20250514"
MARKER = "synthetic-upstream-ok"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Upstream(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_POST(self):
        if self.path != "/v1/messages" or self.headers.get("Authorization") != "Bearer synthetic-access":
            self.send_error(404)
            return
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Upstream.requests += 1
        body = json.dumps({"id": "msg_example", "type": "message", "role": "assistant", "model": MODEL,
                           "content": [{"type": "text", "text": MARKER}], "stop_reason": "end_turn",
                           "usage": {"input_tokens": 2, "output_tokens": 3}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def ready(url):
    with OPENER.open(url + "/health/ready", timeout=1) as reply:
        return reply.status == 200


def messages(url):
    prompt = {"model": MODEL, "max_tokens": 8, "messages": [{"role": "user", "content": "Test"}]}
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01",
               "anthropic-beta": "oauth-2025-04-20", "User-Agent": "claude-cli/2.1.280 (external, cli)"}
    req = urllib.request.Request(url + "/v1/messages", data=json.dumps(prompt).encode(), headers=headers)
    try:
        with OPENER.open(req, timeout=12) as reply:
            return reply.status, json.load(reply)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.load(error)


def check(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def run(repo, sing_box):
    with contextlib.ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="twarp-vpn-proxy-")))
        upstream = stack.enter_context(http.server.HTTPServer(("127.0.0.1", 0), Upstream))
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        stack.callback(upstream.shutdown)
        with socket.socket() as a, socket.socket() as b:
            a.bind(("127.0.0.1", 0))
            b.bind(("127.0.0.1", 0))
            agent_port, proxy_port = a.getsockname()[1], b.getsockname()[1]
        url = f"http://127.0.0.1:{agent_port}"
        proxy = f"http://127.0.0.1:{proxy_port}"
        config = root / "proxy.json"
        config.write_text(json.dumps({
            "inbounds": [{"type": "mixed", "tag": "vpn-proxy-in", "listen": "127.0.0.1", "listen_port": proxy_port}],
            "outbounds": [{"type": "direct", "tag": "synthetic-upstream"}],
            "route": {"rules": [
                {"domain": ["upstream.example"], "outbound": "synthetic-upstream",
                 "override_address": "127.0.0.1", "override_port": upstream.server_port},
                {"action": "reject"},
            ]},
        }))
        env = {"HOME": str(root), "PATH": "/usr/bin:/bin", "http_proxy": proxy, "https_proxy": proxy,
               "AGENT_LB_DATA_DIR": str(root), "AGENT_LB_DATABASE_URL": f"sqlite+aiosqlite:///{root}/store.db",
               "AGENT_LB_METRICS_ENABLED": "false", "AGENT_LB_ANTHROPIC_UPSTREAM_BASE_URL": "http://upstream.example",
               "AGENT_LB_ANTHROPIC_POOL_EXHAUSTED_WAIT_ENABLED": "false"}
        box = subprocess.Popen([sing_box, "run", "-c", str(config)], cwd=root, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stop, box)
        sandbox = ["/usr/bin/sandbox-exec", "-D", f"PROXY_PORT={proxy_port}", "-f", str(PROFILE)]
        with (root / "agent.log").open("w") as log:
            agent = subprocess.Popen(sandbox + [str(repo / ".venv/bin/agent-lb"), "--host", "127.0.0.1",
                                               "--port", str(agent_port)], cwd=repo, env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
        stack.callback(stop, agent)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            check(box.poll() is None and agent.poll() is None, "sing-box or Agent LB exited before readiness")
            try:
                if ready(url):
                    with socket.create_connection(("127.0.0.1", proxy_port), 1):
                        break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("readiness timeout")
        seed = ("import asyncio; from tests.floor.anthropic_proxy_support import _insert_account; "
                "asyncio.run(_insert_account(account_id='test', provider='anthropic', "
                "access_token='synthetic-access', email='routing@example.com'))")
        subprocess.run(sandbox + [str(repo / ".venv/bin/python"), "-c", seed], cwd=repo, env=env,
                       check=True, timeout=12)
        status, body = messages(url)
        check(status == 200 and body["content"][0]["text"] == MARKER and Upstream.requests == 1,
              f"proxy running: expected HTTP 200 and one upstream request, got {status}, {Upstream.requests}")
        stop(box)
        status, _ = messages(url)
        check(500 <= status < 600 and Upstream.requests == 1 and ready(url),
              f"proxy stopped: expected upstream failure and local readiness, got {status}, {Upstream.requests}")
        print(f"Agent LB: HTTP 200 through sing-box; after shutdown HTTP {status}, readiness 200, no additional upstream requests")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path, help="Agent LB checkout with dependencies installed in .venv")
    args = parser.parse_args()
    repo = args.repo.resolve()
    if any((repo / name).exists() for name in (".env", ".env.local")):
        parser.error("use an Agent LB checkout without .env or .env.local")
    if not all(os.access(repo / name, os.X_OK) for name in (".venv/bin/python", ".venv/bin/agent-lb")):
        parser.error("install the Agent LB checkout into its .venv first")
    sing_box = shutil.which("sing-box")
    if sing_box is None or not Path("/usr/bin/sandbox-exec").is_file():
        parser.error("requires macOS sandbox-exec and sing-box on PATH")
    run(repo, os.path.abspath(sing_box))
