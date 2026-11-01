#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Raw-socket conformance and hardening probe for the vpnd M0 control plane.

Deliberately does not use an HTTP client library: every byte on the wire is
written by this script, which is the only way to exercise malformed request
lines, pipelining, split segments, abrupt resets and slowloris behaviour.

Usage (against an already running daemon):
    python raw_http_probe.py --port 8080

Usage (spawn and probe a freshly built binary):
    python raw_http_probe.py --daemon build/vpnd.exe --port 18080

Exit code: 0 if every case matches the expectation table, 1 otherwise.
Each case prints the exact bytes sent and received so the output is evidence.
"""

from __future__ import annotations

import argparse
import random
import re
import socket
import struct
import subprocess
import sys
import time

CRLF = b"\r\n"
RECV_TIMEOUT = 6.0

# --------------------------------------------------------------------------- #
# wire helpers
# --------------------------------------------------------------------------- #


def connect(host: str, port: int, timeout: float = RECV_TIMEOUT) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def read_until_eof(sock: socket.socket, timeout: float = RECV_TIMEOUT) -> bytes:
    """The server always answers `Connection: close`, so EOF delimits the reply."""
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def split_message(raw: bytes) -> "tuple[bytes, dict[str, str], bytes]":
    """Split a response into (status line, headers, body) without being strict."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0] if lines else b""
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep:
            headers[key.strip().decode("latin-1").lower()] = value.strip().decode("latin-1")
    return status_line, headers, body


def status_of(raw: bytes) -> int:
    line, _, _ = split_message(raw)
    parts = line.split(b" ")
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


def escaped(data: bytes, limit: int = 400) -> str:
    text = data[:limit].decode("latin-1")
    out = []
    for ch in text:
        if ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n\n     ")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("\\x%02x" % ord(ch))
    suffix = " ...(%d bytes)" % len(data) if len(data) > limit else ""
    return "".join(out) + suffix


class Probe:
    def __init__(self, host: str, port: int, verbose: bool = True) -> None:
        self.host = host
        self.port = port
        self.verbose = verbose
        self.results = []

    def record(self, name, ok, detail, sent=None, got=None) -> None:
        self.results.append((name, ok, detail))
        print("%s  %-52s %s" % ("PASS" if ok else "FAIL", name, detail))
        if self.verbose and sent is not None:
            print("        >>> %s" % escaped(sent))
        if self.verbose and got is not None:
            print("        <<< %s" % escaped(got))
        sys.stdout.flush()

    def check(self, name, ok, detail, sent=None, got=None) -> bool:
        self.record(name, ok, detail, sent, got)
        return ok

    def exchange(self, name: str, payload: bytes, timeout: float = RECV_TIMEOUT) -> bytes:
        try:
            s = connect(self.host, self.port, timeout)
        except OSError as exc:
            self.record(name, False, "connect failed: %s" % exc)
            return b""
        try:
            s.sendall(payload)
            data = read_until_eof(s, timeout)
        except OSError as exc:
            self.record(name, False, "send/recv failed: %s" % exc, payload, b"")
            return b""
        finally:
            s.close()
        return data

    def get(self, name: str, target: str, method: str = "GET",
            version: str = "HTTP/1.1") -> bytes:
        payload = ("%s %s %s\r\nHost: probe\r\n\r\n" % (method, target, version)).encode()
        return self.exchange(name, payload)

    def metrics_text(self) -> str:
        raw = self.get("metrics-scrape", "/metrics")
        _, _, body = split_message(raw)
        return body.decode("latin-1")


# --------------------------------------------------------------------------- #
# cases
# --------------------------------------------------------------------------- #
def common_header_checks(p: Probe, label: str, raw: bytes) -> None:
    _, headers, _ = split_message(raw)
    p.check("%s: Connection: close" % label, headers.get("connection") == "close",
            "Connection=%r" % headers.get("connection"))
    p.check("%s: Content-Length present" % label, "content-length" in headers,
            "Content-Length=%r" % headers.get("content-length"))
    p.check("%s: nosniff" % label,
            headers.get("x-content-type-options") == "nosniff",
            "X-Content-Type-Options=%r" % headers.get("x-content-type-options"))


def run_happy_path(p: Probe) -> None:
    print("\n=== 1. happy path / method semantics ===")

    raw = p.get("GET /healthz", "/healthz")
    p.check("GET /healthz -> 200", status_of(raw) == 200, "status=%d" % status_of(raw),
            b"GET /healthz HTTP/1.1\r\n\r\n", raw)
    p.check("GET /healthz body", b'"status":"ok"' in raw,
            "body=%r" % escaped(split_message(raw)[2], 120))
    common_header_checks(p, "GET /healthz", raw)
    _, h_get, b_get = split_message(raw)
    p.check("GET /healthz Content-Length matches body",
            h_get.get("content-length") == str(len(b_get)),
            "header=%s actual=%d" % (h_get.get("content-length"), len(b_get)))

    raw = p.get("HEAD /healthz", "/healthz", "HEAD")
    _, h_head, b_head = split_message(raw)
    p.check("HEAD /healthz -> 200", status_of(raw) == 200, "status=%d" % status_of(raw),
            b"HEAD /healthz HTTP/1.1\r\n\r\n", raw)
    p.check("HEAD /healthz sends no body", b_head == b"", "body=%r" % b_head)
    p.check("HEAD /healthz keeps Content-Length",
            h_head.get("content-length") == h_get.get("content-length"),
            "HEAD=%s GET=%s" % (h_head.get("content-length"), h_get.get("content-length")))

    raw = p.get("GET /readyz", "/readyz")
    p.check("GET /readyz -> 200 ready",
            status_of(raw) == 200 and b'"ready"' in raw,
            "status=%d body=%r" % (status_of(raw), escaped(split_message(raw)[2], 120)))

    raw = p.get("GET /", "/")
    p.check("GET / -> 200 endpoint list",
            status_of(raw) == 200 and b"/healthz" in raw,
            "status=%d" % status_of(raw), None, raw)

    raw = p.get("GET /nope", "/nope")
    _, h404, b404 = split_message(raw)
    p.check("GET /nope -> 404 problem+json",
            status_of(raw) == 404 and
            h404.get("content-type", "").startswith("application/problem+json"),
            "status=%d ct=%r" % (status_of(raw), h404.get("content-type")), None, raw)
    p.check("GET /nope body is valid problem JSON",
            b404.strip().startswith(b"{") and b'"status":404' in b404,
            "body=%r" % escaped(b404, 160))

    raw = p.get("POST /healthz", "/healthz", "POST")
    _, h405, _ = split_message(raw)
    p.check("POST /healthz -> 405 with Allow",
            status_of(raw) == 405 and h405.get("allow") == "GET, HEAD",
            "status=%d Allow=%r" % (status_of(raw), h405.get("allow")),
            b"POST /healthz HTTP/1.1\r\n\r\n", raw)

    for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"):
        raw = p.get("%s /metrics -> 405" % method, "/metrics", method)
        p.check("%s /metrics -> 405" % method, status_of(raw) == 405,
                "status=%d" % status_of(raw))


def run_request_line(p: Probe) -> None:
    print("\n=== 2. request-line robustness ===")

    sent = b"GET /healthz\r\n\r\n"
    raw = p.exchange("HTTP/0.9 request line", sent)
    p.check("HTTP/0.9 request line -> 400", status_of(raw) == 400,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"BOGUS\r\n\r\n"
    raw = p.exchange("garbage request line", sent)
    p.check("garbage request line -> 400", status_of(raw) == 400,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"\r\n\r\n"
    raw = p.exchange("empty request line", sent)
    p.check("empty request line -> 400", status_of(raw) == 400,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"GET  /healthz HTTP/1.1\r\nHost: p\r\n\r\n"
    raw = p.exchange("double space", sent)
    p.check("double SP in request line -> 400", status_of(raw) == 400,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"GET http://127.0.0.1/healthz HTTP/1.1\r\nHost: p\r\n\r\n"
    raw = p.exchange("absolute-form URI", sent)
    p.check("absolute-form URI accepted -> 200", status_of(raw) == 200,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"GET /healthz?x=1&y=2 HTTP/1.1\r\nHost: p\r\n\r\n"
    raw = p.exchange("query string", sent)
    p.check("query string does not break routing -> 200", status_of(raw) == 200,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"GET /\xff\xfe HTTP/1.1\r\nHost: p\r\n\r\n"
    raw = p.exchange("non-ASCII target", sent)
    p.check("non-ASCII target -> 404 (no crash)", status_of(raw) == 404,
            "status=%d" % status_of(raw), sent, raw)

    sent = b"GET /healthz HTTP/9.9\r\nHost: p\r\n\r\n"
    raw = p.exchange("bogus HTTP version", sent)
    p.check("bogus HTTP version handled deterministically",
            status_of(raw) in (200, 400, 505),
            "status=%d" % status_of(raw), sent, raw)


def run_header_limits(p: Probe) -> None:
    print("\n=== 3. header size limits ===")

    sent = b"GET /healthz HTTP/1.1\r\nX-Filler: " + b"A" * 9000 + b"\r\n\r\n"
    raw = p.exchange("9 KB header", sent)
    _, h431, b431 = split_message(raw)
    p.check("9 KB header -> 431", status_of(raw) == 431, "status=%d" % status_of(raw),
            sent[:60] + b"...", raw[:300])
    p.check("431 has correct Content-Length",
            h431.get("content-length") == str(len(b431)),
            "header=%r body=%d" % (h431.get("content-length"), len(b431)))
    p.check("431 keeps hardening headers",
            h431.get("x-content-type-options") == "nosniff" and
            h431.get("connection") == "close",
            "nosniff=%r connection=%r" % (h431.get("x-content-type-options"),
                                          h431.get("connection")))

    sent = b"GET /healthz HTTP/1.1\r\nX-Big: " + b"B" * 100000 + b"\r\n\r\n"
    raw = p.exchange("100 KB header in one write", sent)
    p.check("100 KB header in one write -> 431", status_of(raw) == 431,
            "status=%d" % status_of(raw), b"GET ... X-Big:<100000 bytes>", raw[:200])

    padding = 8192 - len(b"GET /healthz HTTP/1.1\r\nX-P: \r\n\r\n") - 8
    sent = b"GET /healthz HTTP/1.1\r\nX-P: " + b"C" * max(padding, 0) + b"\r\n\r\n"
    raw = p.exchange("header at the 8 KiB limit", sent)
    p.check("header at the limit -> 200 (not 431)", status_of(raw) == 200,
            "status=%d sent=%d bytes" % (status_of(raw), len(sent)), None, raw[:120])


def run_framing(p: Probe) -> None:
    print("\n=== 4. framing / segmentation / pipelining ===")

    s = connect(p.host, p.port)
    for part in (b"GET /hea", b"lthz HTT", b"P/1.1\r\n", b"Host: p\r\n", b"\r\n"):
        s.sendall(part)
        time.sleep(0.05)
    raw = read_until_eof(s)
    s.close()
    p.check("request split across 5 segments -> 200", status_of(raw) == 200,
            "status=%d" % status_of(raw), b"<5 segments>", raw)

    sent = (b"GET /healthz HTTP/1.1\r\nHost: p\r\n\r\n"
            b"GET /readyz HTTP/1.1\r\nHost: p\r\n\r\n")
    raw = p.exchange("pipelined x2", sent)
    p.check("pipelined: first request answered once",
            status_of(raw) == 200 and raw.count(b"HTTP/1.1 ") == 1,
            "responses=%d status=%d" % (raw.count(b"HTTP/1.1 "), status_of(raw)),
            b"<2 pipelined requests>", raw[:200])

    s = connect(p.host, p.port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: p\r\n")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
    s.close()
    time.sleep(0.1)
    raw = p.get("server alive after client RST", "/healthz")
    p.check("server survives abrupt client RST", status_of(raw) == 200,
            "status=%d" % status_of(raw))

    s = connect(p.host, p.port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: p\r\n\r\n")
    s.shutdown(socket.SHUT_WR)
    raw = read_until_eof(s)
    s.close()
    p.check("half-closed client still gets a response", status_of(raw) == 200,
            "status=%d" % status_of(raw), None, raw[:120])

    for _ in range(5):
        connect(p.host, p.port).close()
    raw = p.get("server alive after 5 empty connections", "/healthz")
    p.check("server survives connect-and-close x5", status_of(raw) == 200,
            "status=%d" % status_of(raw))

    s = connect(p.host, p.port)
    s.sendall(b"POST /healthz HTTP/1.1\r\nHost: p\r\nContent-Length: 200000\r\n\r\n")
    s.sendall(b"z" * 200000)
    raw = read_until_eof(s)
    s.close()
    p.check("POST with a 200 KB body -> 405 (body never parsed)",
            status_of(raw) == 405, "status=%d" % status_of(raw),
            b"<POST + 200 KB body>", raw[:160])


def run_metrics_format(p: Probe) -> None:
    print("\n=== 5. metrics exposition format ===")

    raw = p.get("metrics content type", "/metrics")
    _, headers, body = split_message(raw)
    text = body.decode("latin-1")
    p.check("/metrics content type is exposition 0.0.4",
            "version=0.0.4" in headers.get("content-type", ""),
            "ct=%r" % headers.get("content-type"))

    type_lines = [line for line in text.splitlines() if line.startswith("# TYPE ")]
    names = [line.split()[2] for line in type_lines]
    p.check("/metrics has TYPE lines", bool(type_lines), "count=%d" % len(type_lines))
    p.check("/metrics has no duplicate TYPE lines", len(names) == len(set(names)),
            "duplicates=%s" % sorted({n for n in names if names.count(n) > 1}))
    print("        <<< %s" % text.replace("\n", "\n            ")[:1200])

    bad = [line for line in text.splitlines()
           if line and not line.startswith("#") and
           not re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? [^ ]+$", line)]
    p.check("/metrics sample lines are well formed", not bad, "offending=%r" % bad[:3])


def run_cardinality(p: Probe) -> None:
    print("\n=== 6. metrics label cardinality (scanner simulation) ===")

    before = p.metrics_text()
    before_routes = set(re.findall(r'route="([^"]*)"', before))
    before_methods = set(re.findall(r'method="([^"]*)"', before))

    injected = 40
    for i in range(injected):
        p.exchange("scan %d" % i, b"GET /scan-%d-%d HTTP/1.1\r\nHost: p\r\n\r\n"
                   % (i, random.randint(0, 10 ** 6)))
    for i in range(10):
        p.exchange("odd method %d" % i, b"M%d /healthz HTTP/1.1\r\nHost: p\r\n\r\n" % i)

    after = p.metrics_text()
    after_routes = set(re.findall(r'route="([^"]*)"', after))
    after_methods = set(re.findall(r'method="([^"]*)"', after))
    print("     routes before=%d after=%d" % (len(before_routes), len(after_routes)))
    print("     route values: %s" % sorted(after_routes)[:20])
    print("     methods before=%d after=%d" % (len(before_methods), len(after_methods)))
    print("     method values: %s" % sorted(after_methods)[:20])
    p.check("route label is bounded (<=8 distinct values)", len(after_routes) <= 8,
            "distinct route values after %d random paths = %d"
            % (injected, len(after_routes)))
    p.check("method label is bounded (<=8 distinct values)", len(after_methods) <= 8,
            "distinct method values after 10 random methods = %d" % len(after_methods))

    p.exchange("quote in path", b'GET /a"b HTTP/1.1\r\nHost: p\r\n\r\n')
    p.exchange("backslash in path", b'GET /a\\b HTTP/1.1\r\nHost: p\r\n\r\n')
    text = p.metrics_text()
    bad = [line for line in text.splitlines()
           if line and not line.startswith("#") and
           not re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{.*\})? [^ ]+$", line)]
    p.check("/metrics escapes quotes/backslashes in labels", not bad,
            "offending=%r" % bad[:3])


def run_concurrency(p: Probe) -> None:
    print("\n=== 7. concurrency / slowloris (M0 limitation, measured) ===")

    stalled = connect(p.host, p.port)
    stalled.sendall(b"GET /healthz HT")
    time.sleep(0.2)
    started = time.time()
    raw = p.get("health request while a client stalls", "/healthz")
    stalled_for = time.time() - started
    stalled.close()
    time.sleep(0.1)
    p.check("documented: one stalled client delays others", True,
            "concurrent /healthz took %.2fs, status=%d (single-threaded accept loop)"
            % (stalled_for, status_of(raw)))

    idle = []
    for _ in range(100):
        try:
            idle.append(connect(p.host, p.port, timeout=2.0))
        except OSError:
            break
    opened = len(idle)
    for s in idle:
        s.close()
    time.sleep(0.2)
    raw = p.get("server alive after 100 idle connections", "/healthz")
    p.check("server survives %d concurrent idle connections" % opened,
            status_of(raw) == 200, "opened=%d status=%d" % (opened, status_of(raw)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--daemon", default=None, help="spawn this vpnd binary first")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    proc = None
    if args.daemon:
        print("spawning %s --bind %s:%d" % (args.daemon, args.host, args.port))
        proc = subprocess.Popen(
            [args.daemon, "--bind", "%s:%d" % (args.host, args.port)],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        for _ in range(100):
            try:
                connect(args.host, args.port, timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            print("FATAL: daemon did not start listening")
            proc.kill()
            return 1

    probe = Probe(args.host, args.port, verbose=not args.quiet)
    try:
        run_happy_path(probe)
        run_request_line(probe)
        run_header_limits(probe)
        run_framing(probe)
        run_metrics_format(probe)
        run_cardinality(probe)
        run_concurrency(probe)
    finally:
        if proc is not None:
            proc.kill()
            proc.wait(timeout=10)

    failed = [r for r in probe.results if not r[1]]
    print("\n%d case(s), %d failure(s)" % (len(probe.results), len(failed)))
    for name, _, detail in failed:
        print("  FAILED %s :: %s" % (name, detail))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())




