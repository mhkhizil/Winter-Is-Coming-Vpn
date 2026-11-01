#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Demonstrate whether a byte-dribbling client can hold the daemon indefinitely.

SO_RCVTIMEO bounds a single recv() call, not the whole header block. A client
that sends one byte every few seconds therefore keeps resetting the timer, and
because the M0 accept loop is single-threaded it blocks every other request for
as long as it likes. This script measures exactly that.

Usage:
    python slowloris_probe.py --daemon out/vpnd.exe --port 18099

Prints the wall-clock time until (a) the daemon drops the dribbling connection
and (b) a pipelined health request succeeds again. Exits 0 if the daemon
recovers within BUDGET seconds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import threading
import time

BUDGET = 14.0  # > http.request_timeout_secs (default 10 s)


def wait_port(host, port, proc, budget=10.0):
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18099)
    args = ap.parse_args()

    proc = subprocess.Popen([args.daemon, "--bind", "%s:%d" % (args.host, args.port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(args.host, args.port, proc):
        print("FATAL: daemon did not start")
        proc.kill()
        return 1

    # Dribble one byte every 2 s: each recv() returns well inside SO_RCVTIMEO.
    dribble = socket.create_connection((args.host, args.port), timeout=30)
    dribble.sendall(b"GET /healthz HTTP/1.1\r\nX-Slow: ")
    t0 = time.time()

    dropped = threading.Event()
    drop_time = [None]

    def dribbler():
        try:
            while time.time() - t0 < BUDGET:
                dribble.sendall(b"a")
                time.sleep(2.0)
                # If the server closed on us, sendall raises.
        except OSError:
            drop_time[0] = time.time() - t0
        dropped.set()

    # A concurrent client tries a normal request every 250 ms.
    recovered = [None]
    errors = []

    def poller():
        while time.time() - t0 < BUDGET:
            try:
                s = socket.create_connection((args.host, args.port), timeout=0.3)
                s.sendall(b"GET /healthz HTTP/1.1\r\nHost: p\r\n\r\n")
                data = s.recv(64)
                s.close()
                if b"200" in data:
                    recovered[0] = time.time() - t0
                    return
            except OSError as exc:
                errors.append(str(exc))
            time.sleep(0.25)

    threads = [threading.Thread(target=dribbler), threading.Thread(target=poller)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(BUDGET + 5)

    # Read whatever the server eventually wrote on the dribbled connection.
    dribble.settimeout(2.0)
    late = b""
    try:
        late = dribble.recv(64)
    except OSError:
        pass
    dribble.close()

    print("dribbling client started at t=0, budget=%.1fs" % BUDGET)
    print("server closed the dribbling connection at: %s"
          % ("%.2fs" % drop_time[0] if drop_time[0] else "NEVER (within budget)"))
    print("concurrent /healthz succeeded again at:     %s"
          % ("%.2fs" % recovered[0] if recovered[0] else "NEVER (within budget)"))
    print("late bytes on the dribbled connection:      %r" % late[:40])
    if errors:
        print("concurrent client errors (first 3):         %s" % errors[:3])

    proc.kill()
    proc.wait(timeout=10)

    ok = recovered[0] is not None and recovered[0] <= BUDGET
    print("\nRESULT: %s" % ("recovered within %.0fs" % BUDGET if ok else
                            "STILL BLOCKED after %.0fs - one client starves the daemon"
                            % BUDGET))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
