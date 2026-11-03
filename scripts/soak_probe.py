#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Soak probe: sustained create/delete churn against vpnd.

The interesting leak questions for this server are not "does it leak per request"
(a plain read loop answers that) but "does anything grow across thousands of
mutations, deletes and re-auths" - tombstones, the append-only log, the audit ring,
ID/index maps. Each cycle here creates a device, uploads a key, creates a peer,
deletes it, rotates the token and signs in again, so every one of those paths runs
repeatedly.

  python scripts/soak_probe.py --port 8080 --cycles 200
"""
import argparse
import http.client
import json
import time


def call(port, method, path, body=None, token=None, timeout=15):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    response = conn.getresponse()
    data = response.read()
    status = response.status
    conn.close()
    return status, data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--cycles", type=int, default=200)
    parser.add_argument("--email", default="soak@example.invalid")
    parser.add_argument("--password", default="soak-password")
    args = parser.parse_args()

    status, data = call(args.port, "POST", "/api/v1/auth/login",
                        {"email": args.email, "password": args.password})
    if status != 200:
        print(f"login failed: {status} {data[:160]}")
        return 1
    token = json.loads(data)["access_token"]

    started = time.perf_counter()
    failures = []
    for cycle in range(1, args.cycles + 1):
        status, data = call(args.port, "POST", "/api/v1/devices",
                            {"name": f"soak-{cycle}", "platform": "soak"}, token)
        if status != 201:
            failures.append(f"device {status}")
            continue
        device = json.loads(data)["id"]
        status, _ = call(args.port, "PUT", f"/api/v1/devices/{device}/key",
                         {"public_key": f"{cycle:064x}"}, token)
        if status not in (200, 204):
            failures.append(f"key {status}")
        status, data = call(args.port, "POST", "/api/v1/peers", {"device_id": device}, token)
        if status != 201:
            failures.append(f"peer {status}")
            continue
        peer = json.loads(data)["peer_id"]
        status, _ = call(args.port, "DELETE", f"/api/v1/peers/{peer}", None, token)
        if status not in (200, 204):
            failures.append(f"delete {status}")
        # Token churn: rotate invalidates the old value, so re-login each cycle too.
        status, data = call(args.port, "POST", "/api/v1/auth/rotate", {}, token)
        if status == 200:
            token = json.loads(data)["access_token"]
        else:
            failures.append(f"rotate {status}")
            status, data = call(args.port, "POST", "/api/v1/auth/login",
                                {"email": args.email, "password": args.password})
            if status == 200:
                token = json.loads(data)["access_token"]
        if cycle % 50 == 0:
            elapsed = time.perf_counter() - started
            print(f"  cycle {cycle}/{args.cycles}: {elapsed:.1f}s "
                  f"({cycle / elapsed:.1f} cycles/s), failures so far {len(failures)}")

    total = time.perf_counter() - started
    print(f"soak: {args.cycles} cycles in {total:.1f}s, {len(failures)} failures")
    if failures:
        print("  first failures:", failures[:5])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
