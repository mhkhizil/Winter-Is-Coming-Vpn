#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Contract check: is the Android client wired to every endpoint it needs?

Two questions, answered against a live vpnd:

  A. For each endpoint the client actually calls, does the server accept the *exact*
     request the client builds, and does the response contain the fields the client
     parses? Sending what a human would send is not the same test.

  B. For each implemented endpoint the client does *not* call, does it exist and
     behave as documented? That is what keeps API-COVERAGE.md honest: a new endpoint
     shows up here instead of silently existing.

  python scripts/api-contract.py --port 8096 --metrics-port 9196
"""
import argparse
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid

FAILURES = []
CHECKS = []


def check(label, ok, detail=""):
    CHECKS.append((label, ok, detail))
    if not ok:
        FAILURES.append(f"{label}: {detail}")
    return ok


class Server:
    def __init__(self, port, vpnd, config, env):
        self.port = port
        self.vpnd = vpnd
        self.config = config
        self.env = env
        self.proc = None

    def call(self, method, path, body=None, token=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        payload = None
        if body is not None:
            payload = body if isinstance(body, str) else json.dumps(body)
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        text = response.read().decode("utf-8", "replace")
        status = response.status
        conn.close()
        if raw:
            return status, text
        try:
            return status, (json.loads(text) if text else {})
        except json.JSONDecodeError:
            return status, text

    def start(self):
        self.proc = subprocess.Popen(
            [self.vpnd, "--config", self.config],
            stdout=open(os.path.join(os.path.dirname(self.config), "vpnd.log"), "w"),
            stderr=subprocess.STDOUT,
            env=self.env,
        )
        for _ in range(100):
            time.sleep(0.1)
            try:
                status, _ = self.call("GET", "/healthz")
                if status == 200:
                    return True
            except OSError:
                continue
        return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8096)
    ap.add_argument("--metrics-port", type=int, default=9196)
    ap.add_argument("--vpnd", default=os.path.join("out", "build-release", "server", "vpnd.exe"))
    ap.add_argument(
        "--external",
        action="store_true",
        help="a vpnd is already listening on --port; do not start or stop one "
             "(needed on hosts where an application-control policy blocks python "
             "from spawning the daemon)",
    )
    args = ap.parse_args()

    if args.external:
        run(Server(args.port, "", "", {}))
        return report()

    vpnd = os.path.abspath(args.vpnd)
    if not os.path.exists(vpnd):
        print(f"SKIP: {vpnd} not built")
        return 2

    work = tempfile.mkdtemp(prefix="vpn-contract-")
    config = os.path.join(work, "vpnd.toml")
    with open(config, "w", encoding="ascii") as handle:
        handle.write(
            'environment = "development"\n'
            f'[http]\nbind = "127.0.0.1:{args.port}"\n'
            f'[metrics]\nbind = "127.0.0.1:{args.metrics_port}"\n'
            "[rate_limit]\nrequests_per_second = 20000\nburst = 50000\n"
        )
    env = dict(os.environ)
    env["VPN_STORE_PATH"] = os.path.join(work, "control.log")
    env["VPN_BOOTSTRAP_EMAIL"] = "admin@example.invalid"
    env["VPN_BOOTSTRAP_PASSWORD"] = "admin-password"
    # Without this the first account is an "owner", which is not an administrator, and
    # the whole /admin/* surface plus /dp/config is unreachable on a fresh deployment.
    env["VPN_BOOTSTRAP_ROLE"] = "admin"

    server = Server(args.port, vpnd, config, env)
    if not server.start():
        print("FAIL: vpnd did not start")
        return 1
    try:
        run(server)
    finally:
        server.stop()

    return report()


def report():
    print()
    width = max(len(label) for label, _, _ in CHECKS)
    for label, ok, detail in CHECKS:
        print(f"  {'PASS' if ok else 'FAIL'}  {label.ljust(width)}  {detail}")
    print()
    if FAILURES:
        print(f"{len(FAILURES)} contract failure(s) of {len(CHECKS)} checks")
        return 1
    print(f"all {len(CHECKS)} contract checks passed")
    return 0


def run(srv):
    # ---- A. the endpoints the client actually calls ---------------------------
    # The bodies below are byte-for-byte what VpnApi builds, because a contract test
    # that sends friendlier input than the app does is theatre.
    status, body = srv.call("POST", "/api/v1/auth/login",
                            {"email": "admin@example.invalid", "password": "admin-password"})
    check("A1 POST /api/v1/auth/login (client)", status == 200 and "access_token" in body,
          f"HTTP {status}")
    token = body.get("access_token", "") if isinstance(body, dict) else ""
    check("A1b login returns user_id (client parses it)", bool(body.get("user_id")),
          f"user_id={body.get('user_id')!r}")

    status, body = srv.call("GET", "/api/v1/me", token=token)
    access = body.get("access") if isinstance(body, dict) else None
    check("A2 GET /api/v1/me (client reads access.plan/status/days_left)",
          status == 200 and isinstance(access, dict) and {"plan", "status", "days_left"} <= set(access),
          f"HTTP {status} access={access}")

    status, body = srv.call("POST", "/api/v1/devices",
                            {"name": "Pixel 8 Pro", "platform": "android"}, token=token)
    device_id = body.get("id") if isinstance(body, dict) else None
    check("A3 POST /api/v1/devices (client sends name+platform, reads id)",
          status == 201 and bool(device_id), f"HTTP {status}")

    status, _ = srv.call("PUT", f"/api/v1/devices/{device_id}/key",
                         {"public_key": "ab" * 32}, token=token)
    check("A4 PUT /api/v1/devices/{id}/key (client uploads 64-hex)", status == 204, f"HTTP {status}")

    # A node must exist or the server refuses to name an endpoint (503 no_node).
    status, _ = srv.call("POST", "/api/v1/nodes",
                         {"host": "vpn.example.com", "region": "eu", "public_key": "cd" * 32},
                         token=token)
    check("A5 POST /api/v1/nodes (operator; prerequisite for peers)", status in (200, 201), f"HTTP {status}")

    status, body = srv.call("POST", "/api/v1/peers", {"device_id": device_id}, token=token)
    peer_id = body.get("peer_id") if isinstance(body, dict) else None
    iface = body.get("interface") if isinstance(body, dict) else None
    server_block = body.get("server") if isinstance(body, dict) else None
    fields_ok = (
        status == 201
        and bool(peer_id)
        and bool(body.get("device_id"))
        and bool(body.get("status"))
        and isinstance(iface, dict)
        and isinstance(iface.get("addresses"), list) and bool(iface["addresses"])
        and isinstance(iface.get("dns"), list)
        and isinstance(iface.get("mtu"), int)
        and isinstance(iface.get("persistent_keepalive"), int)
        and iface.get("private_key", "MISSING") is None
        and isinstance(server_block, dict)
        and ":" in str(server_block.get("endpoint", ""))
        and bool(server_block.get("public_key"))
        and isinstance(server_block.get("allowed_ips"), list) and bool(server_block["allowed_ips"])
    )
    check("A6 POST /api/v1/peers (every field PeerConfigParser requires)", fields_ok,
          f"HTTP {status} keys={sorted(body) if isinstance(body, dict) else body}")

    status, body = srv.call("GET", "/api/v1/servers", token=token)
    catalog = body.get("data") if isinstance(body, dict) else None
    check("A7 GET /api/v1/servers (client lists the catalog)",
          status == 200 and isinstance(catalog, list) and bool(catalog)
          and {"endpoint", "public_key"} <= set(catalog[0]),
          f"HTTP {status} first={catalog[0] if catalog else None}")

    status, body = srv.call("POST", "/api/v1/auth/rotate", {}, token=token)
    rotated = body.get("access_token", "") if isinstance(body, dict) else ""
    check("A8 POST /api/v1/auth/rotate (client rotates on 401)",
          status == 200 and bool(rotated) and rotated != token, f"HTTP {status}")
    old_status, _ = srv.call("GET", "/api/v1/me", token=token)
    check("A8b rotation kills the old token, as the client assumes", old_status == 401,
          f"HTTP {old_status}")
    token = rotated

    # ---- B. implemented endpoints the client does not call --------------------
    status, body = srv.call("GET", "/api/v1/devices", token=token)
    check("B1 GET /api/v1/devices (unused: client caches device_id)",
          status == 200 and isinstance(body.get("data"), list), f"HTTP {status}")

    status, body = srv.call("GET", "/api/v1/peers", token=token)
    check("B2 GET /api/v1/peers (unused: client creates instead of reusing)",
          status == 200 and isinstance(body.get("data"), list), f"HTTP {status}")

    status, _ = srv.call("GET", f"/api/v1/peers/{peer_id}", token=token)
    check("B3 GET /api/v1/peers/{id} (unused)", status == 200, f"HTTP {status}")

    status, text = srv.call("GET", f"/api/v1/peers/{peer_id}/config", token=token, raw=True)
    check("B4 GET /api/v1/peers/{id}/config (unused: client re-creates instead)",
          status == 200 and "[Interface]" in text, f"HTTP {status}")

    status, _ = srv.call("DELETE", f"/api/v1/peers/{peer_id}", token=token)
    check("B5 DELETE /api/v1/peers/{id} (unused: no client-side revoke)", status == 204, f"HTTP {status}")

    status, _ = srv.call("POST", "/api/v1/me/password",
                         {"current_password": "admin-password", "new_password": "admin-password2"},
                         token=token)
    check("B6 POST /api/v1/me/password (unused: no change-password UI)", status == 204, f"HTTP {status}")
    status, body = srv.call("POST", "/api/v1/auth/login",
                            {"email": "admin@example.invalid", "password": "admin-password2"})
    token = body.get("access_token", "") if isinstance(body, dict) else ""

    customer = f"cust-{uuid.uuid4().hex[:8]}@example.invalid"
    status, body = srv.call("POST", "/api/v1/admin/users",
                            {"email": customer, "password": "cust-password", "days": 30}, token=token)
    user_id = body.get("id") if isinstance(body, dict) else None
    check("B7 POST /api/v1/admin/users (admin only, correctly absent from client)",
          status in (200, 201) and bool(user_id), f"HTTP {status}")

    status, body = srv.call("GET", "/api/v1/admin/users", token=token)
    check("B8 GET /api/v1/admin/users (admin only)",
          status == 200 and isinstance(body.get("data"), list), f"HTTP {status}")
    status, _ = srv.call("GET", f"/api/v1/admin/users/{user_id}", token=token)
    check("B9 GET /api/v1/admin/users/{id} (admin only)", status == 200, f"HTTP {status}")
    status, _ = srv.call("POST", f"/api/v1/admin/users/{user_id}/access", {"days": 30}, token=token)
    check("B10 POST /api/v1/admin/users/{id}/access (admin only)",
          status in (200, 204), f"HTTP {status}")
    status, _ = srv.call("POST", f"/api/v1/admin/users/{user_id}/password",
                         {"password": "cust-password2"}, token=token)
    check("B11 POST /api/v1/admin/users/{id}/password (admin only)", status == 204, f"HTTP {status}")
    status, _ = srv.call("POST", f"/api/v1/admin/users/{user_id}/revoke", {}, token=token)
    check("B12 POST /api/v1/admin/users/{id}/revoke (admin only)",
          status in (200, 204), f"HTTP {status}")

    status, body = srv.call("GET", "/api/v1/admin/audit", token=token)
    check("B13 GET /api/v1/admin/audit (admin only)",
          status == 200 and isinstance(body.get("data"), list), f"HTTP {status}")

    status, body = srv.call("POST", "/api/v1/admin/reminders/run?dry_run=1", token=token)
    check("B14 POST /api/v1/admin/reminders/run (admin; 503 without SMTP is documented)",
          status in (200, 503), f"HTTP {status}")

    status, text = srv.call("GET", "/api/v1/dp/config?node=srv_default", token=token, raw=True)
    check("B15 GET /api/v1/dp/config (node-only, admin)", status == 200, f"HTTP {status}")

    status, _ = srv.call("POST", "/api/v1/auth/logout", {}, token=token)
    check("B16 POST /api/v1/auth/logout (unused: sign-out only clears the device)",
          status in (200, 204), f"HTTP {status}")


if __name__ == "__main__":
    raise SystemExit(main())


