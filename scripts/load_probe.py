#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Small load/leak probe for vpnd.

Fires a fixed number of requests over plain HTTP/1.1 (no keep-alive, which is what
the server implements), then a mutation burst that exercises the fsync'ed store,
and reports timings so a before/after comparison is possible.

  python scripts/load_probe.py --port 8080 --requests 2000 --mutations 200
"""
import argparse
import http.client
import json
import time


def call(port, method, path, body=None, token=None, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = json.dumps(body) if body is not None else None
    started = time.perf_counter()
    conn.request(method, path, body=payload, headers=headers)
    response = conn.getresponse()
    data = response.read()
    elapsed = time.perf_counter() - started
    status = response.status
    conn.close()
    return status, data, elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--mutations", type=int, default=200)
    parser.add_argument("--email", default="dev@example.invalid")
    parser.add_argument("--password", default="dev-password")
    args = parser.parse_args()

    status, data, _ = call(args.port, "POST", "/api/v1/auth/login",
                           {"email": args.email, "password": args.password})
    if status != 200:
        print(f"login failed: {status} {data[:200]}")
        return 1
    token = json.loads(data)["access_token"]

    # 1. read path: unchanged state, pure HTTP + auth + routing cost
    started = time.perf_counter()
    latencies = []
    for _ in range(args.requests):
        _, _, elapsed = call(args.port, "GET", "/api/v1/health")
        latencies.append(elapsed)
    read_total = time.perf_counter() - started
    latencies.sort()
    print(f"read  : {args.requests} reqs in {read_total:.2f}s "
          f"({args.requests / read_total:.0f} req/s, "
          f"p50 {latencies[len(latencies) // 2] * 1000:.2f}ms, "
          f"p99 {latencies[int(len(latencies) * 0.99)] * 1000:.2f}ms)")

    # 2. write path: each iteration mutates the store (device, key, peer)
    started = time.perf_counter()
    created = 0
    for i in range(args.mutations):
        status, data, _ = call(args.port, "POST", "/api/v1/devices",
                               {"name": f"dev{i}", "platform": "load"}, token)
        if status != 201:
            print(f"  device create failed: {status} {data[:120]}")
            break
        device = json.loads(data)["id"]
        # 1-based: an all-zero key is (correctly) rejected as invalid.
        key = f"{i + 1:064x}"
        status, data, _ = call(args.port, "PUT", f"/api/v1/devices/{device}/key",
                               {"public_key": key}, token)
        if status not in (200, 204):
            print(f"  key upload failed: {status} {data[:120]}")
            break
        status, data, _ = call(args.port, "POST", "/api/v1/peers", {"device_id": device}, token)
        if status == 201:
            created += 1
        else:
            print(f"  peer create failed: {status} {data[:120]}")
            break
    write_total = time.perf_counter() - started
    per_op = write_total / max(1, created * 3)
    print(f"write : {created} peers ({created * 3} mutations) in {write_total:.2f}s "
          f"({per_op * 1000:.2f}ms per mutation)")

    # 3. auth cost: a token check is an HMAC plus a map lookup
    started = time.perf_counter()
    for _ in range(args.requests):
        call(args.port, "GET", "/api/v1/me", token=token)
    auth_total = time.perf_counter() - started
    print(f"auth  : {args.requests} authed reqs in {auth_total:.2f}s "
          f"({args.requests / auth_total:.0f} req/s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
