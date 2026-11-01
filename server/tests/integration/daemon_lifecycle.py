#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Process-contract probe for vpnd: CLI flags, exit codes, bind errors, shutdown.

Usage:
    python daemon_lifecycle.py --daemon build/vpnd.exe

Covers the stable CLI contract documented in main.cpp / docs/RUNBOOK.md:
  0 success, 2 usage/config error, 3 runtime error.

Note on signals: on POSIX a SIGTERM is delivered and the graceful path is
measured end to end. On Windows a console control event is the only portable
equivalent and Python cannot synthesise one for an arbitrary child, so the
shutdown-latency requirement is covered by tests/unit/test_http_server.cpp
(which drives the exact code path the signal handler triggers: stop()).
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time

RESULTS = []


def record(name, ok, detail):
    RESULTS.append((name, ok, detail))
    print("%s  %-52s %s" % ("PASS" if ok else "FAIL", name, detail))
    sys.stdout.flush()


def run(args, env=None, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(host, port, proc, budget=10.0):
    deadline = time.time() + budget
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def spawn(daemon, bind, log=None):
    stderr = open(log, "w") if log else subprocess.DEVNULL
    return subprocess.Popen([daemon, "--bind", bind], stdout=subprocess.DEVNULL,
                            stderr=stderr)


def cli_cases(daemon):
    print("\n=== A. CLI contract and exit codes ===")

    p = run([daemon, "--print-version"])
    record("--print-version exits 0", p.returncode == 0,
           "exit=%d stdout=%r" % (p.returncode, p.stdout.strip()))

    p = run([daemon, "--validate-config"])
    record("--validate-config exits 0", p.returncode == 0,
           "exit=%d stdout=%r" % (p.returncode, p.stdout.strip()))

    env = dict(os.environ)
    env["VPN_ADMIN_TOKEN"] = "super-secret-token-value"
    env["VPN_ENVIRONMENT"] = "production"
    env["VPN_TLS_CERT_FILE"] = "/etc/vpn/cert.pem"
    env["VPN_TLS_KEY_FILE"] = "/etc/vpn/key.pem"
    p = run([daemon, "--print-config"], env=env)
    leaked = "super-secret-token-value" in p.stdout or "/etc/vpn/key.pem" in p.stdout
    record("--print-config redacts secrets", p.returncode == 0 and not leaked,
           "exit=%d leaked=%s admin_token_line=%r" %
           (p.returncode, leaked,
            [l for l in p.stdout.splitlines() if "admin_token" in l]))

    p = run([daemon, "--totally-unknown-flag"])
    record("unknown flag exits 2", p.returncode == 2,
           "exit=%d stderr[0]=%r" % (p.returncode,
                                     p.stderr.splitlines()[0] if p.stderr else ""))

    p = run([daemon, "--bind"])
    record("missing flag value exits 2", p.returncode == 2,
           "exit=%d stderr=%r" % (p.returncode, p.stderr.strip()))

    p = run([daemon, "--bind", "not-an-endpoint"])
    record("malformed --bind exits 2", p.returncode == 2,
           "exit=%d stderr=%r" % (p.returncode, p.stderr.strip()))

    p = run([daemon, "--config", "/nonexistent/vpnd.toml"])
    record("missing config file exits 2", p.returncode == 2,
           "exit=%d stderr=%r" % (p.returncode, p.stderr.strip()))

    bad = os.path.join(os.path.dirname(os.path.abspath(daemon)), "_bad.toml")
    with open(bad, "w") as fh:
        fh.write("[http]\nbind = \"127.0.0.1:8080\"\nrequest_timeout_secs = 0\n")
    p = run([daemon, "--config", bad])
    record("invalid config value exits 2", p.returncode == 2,
           "exit=%d stderr=%r" % (p.returncode, p.stderr.strip()))
    os.unlink(bad)


def bind_cases(daemon, workdir):
    print("\n=== B. bind failures and port conflicts ===")

    port = free_port()
    bind = "127.0.0.1:%d" % port
    first = spawn(daemon, bind, log=os.path.join(workdir, "first.log"))
    if not wait_listening("127.0.0.1", port, first):
        record("first daemon starts", False, "did not listen on %s" % bind)
        first.kill()
        return None
    record("first daemon starts", True, "listening on %s" % bind)

    second = None
    try:
        second = subprocess.run([daemon, "--bind", bind], capture_output=True, text=True,
                                timeout=8)
        code = second.returncode
        stderr = second.stderr
    except subprocess.TimeoutExpired as exc:
        # The second instance is still running: on Windows SO_REUSEADDR allows a
        # second bind of the same address, so no EADDRINUSE is reported at all.
        code = "still-running"
        stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(
            exc.stderr, bytes) else (exc.stderr or "")
    record("port in use exits 3 (runtime error)", code == 3,
           "exit=%r stderr=%r" % (code, stderr.strip()[:300]))
    record("port in use message names the address",
           "127.0.0.1" in stderr or str(port) in stderr,
           "stderr=%r" % stderr.strip()[:300])
    return first


def shutdown_cases(daemon, proc, workdir):
    print("\n=== C. shutdown latency ===")

    if proc is None:
        return

    if sys.platform == "win32":
        record("SIGTERM latency (POSIX-only case)", True,
               "SKIPPED on Windows: no portable console control event; covered by "
               "tests/unit/test_http_server.cpp")
        proc.kill()
        proc.wait(timeout=10)
        return

    started = time.time()
    proc.send_signal(signal.SIGTERM)
    try:
        code = proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        code = None
        proc.kill()
    record("SIGTERM while idle exits <2s", code == 0 and time.time() - started < 2.0,
           "exit=%r elapsed=%.2fs" % (code, time.time() - started))

    # Now with a stalled client in flight: this is the case that would otherwise
    # wait http.request_timeout_secs (10 s by default).
    port = free_port()
    proc = spawn(daemon, "127.0.0.1:%d" % port,
                 log=os.path.join(workdir, "shutdown.log"))
    if not wait_listening("127.0.0.1", port, proc):
        record("daemon with in-flight client", False, "did not start")
        return
    stalled = socket.create_connection(("127.0.0.1", port), timeout=5)
    stalled.sendall(b"GET /healthz HT")  # deliberately incomplete
    time.sleep(0.3)
    started = time.time()
    proc.send_signal(signal.SIGTERM)
    try:
        code = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        code = None
        proc.kill()
    elapsed = time.time() - started
    stalled.close()
    record("SIGTERM with a stalled client exits <2s", code == 0 and elapsed < 2.0,
           "exit=%r elapsed=%.2fs" % (code, elapsed))


def wildcard_cases(daemon, workdir):
    print("\n=== D. wildcard bind / dual stack ===")

    # An empty host (":8080") is rejected by config validation, so the wildcard
    # cases go through the two literal forms.
    port = free_port()
    proc = spawn(daemon, "0.0.0.0:%d" % port, log=os.path.join(workdir, "wildcard4.log"))
    if not wait_listening("127.0.0.1", port, proc):
        record("0.0.0.0 wildcard bind starts", False, "did not listen on 0.0.0.0:%d" % port)
        proc.kill()
        return
    record("0.0.0.0 wildcard bind accepts IPv4", True, "127.0.0.1:%d" % port)
    proc.kill()
    proc.wait(timeout=10)

    port = free_port()
    proc = spawn(daemon, "[::]:%d" % port, log=os.path.join(workdir, "wildcard6.log"))
    time.sleep(0.5)
    for host in ("::1", "127.0.0.1"):
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(b"GET /healthz HTTP/1.1\r\nHost: p\r\n\r\n")
            data = s.recv(64)
            s.close()
            record("[::] bind accepts %s" % host, b"200" in data,
                   "%s:%d -> %r" % (host, port, data[:20]))
        except OSError as exc:
            record("[::] bind accepts %s" % host, False, "%s:%d -> %s" % (host, port, exc))
    proc.kill()
    proc.wait(timeout=10)

    print("\n=== E. empty-host form (documented as 'all interfaces') ===")
    p = subprocess.run([daemon, "--bind", ":%d" % free_port()], capture_output=True,
                       text=True, timeout=10)
    record("':port' is accepted as a wildcard bind", p.returncode == 0,
           "exit=%d stderr=%r" % (p.returncode, p.stderr.strip()[:160]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", required=True)
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--only", default="a,b,c,d",
                    help="comma separated sections: a=cli b=bind c=shutdown d=wildcard")
    args = ap.parse_args()

    daemon = os.path.abspath(args.daemon)
    if not os.path.exists(daemon):
        print("FATAL: daemon not found: %s" % daemon)
        return 1
    os.makedirs(args.workdir, exist_ok=True)
    only = set(part.strip().lower() for part in args.only.split(","))

    if "a" in only:
        cli_cases(daemon)
    proc = None
    if "b" in only:
        proc = bind_cases(daemon, args.workdir)
    if "c" in only:
        shutdown_cases(daemon, proc, args.workdir)
    if "d" in only:
        wildcard_cases(daemon, args.workdir)

    failed = [r for r in RESULTS if not r[1]]
    print("\n%d case(s), %d failure(s)" % (len(RESULTS), len(failed)))
    for name, _, detail in failed:
        print("  FAILED %s :: %s" % (name, detail))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())

