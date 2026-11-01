#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Independent verification of server/src/crypto/blake2s.cpp.

Three independent implementations are compared:

  * ``hashlib.blake2s`` (CPython's bundled BLAKE2s - an independent reference
    implementation)                       -> the authority for expected values
  * ``PortBlake2s`` - a line-by-line port of server/src/crypto/blake2s.cpp that
    faithfully reproduces its buffering, key-block and counter handling. A
    mismatch against hashlib therefore points at a defect *in the C++*.
  * ``rfc_blake2s`` - a from-scratch RFC 7693 implementation written in a
    different shape (explicit block list, no ring buffer).

If a C++ compiler is available the real C++ code is additionally exercised
through server/tests/golden/drivers/blake2s_driver.cpp for the same case list,
including streaming split points.

Usage:
  python verify_blake2s.py                       # hashlib vs both Python models
  python verify_blake2s.py --cxx <compiler>      # also build+run the C++ driver
  python verify_blake2s.py --driver <built exe>  # use a pre-built driver
Exit code 0 == every check passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
INCLUDE = os.path.join(REPO, "server", "include")
SRC = os.path.join(REPO, "server", "src")
WORK = os.path.join(HERE, "work")
DRIVER_SRC = os.path.join(HERE, "drivers", "blake2s_driver.cpp")

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

BLOCK = 64
M32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & M32


def ref_blake2s(data: bytes, key: bytes = b"", out_len: int = 32) -> bytes:
    """The authority: CPython's independent BLAKE2s."""
    if key:
        return hashlib.blake2s(data, key=key, digest_size=out_len).digest()
    return hashlib.blake2s(data, digest_size=out_len).digest()


# ---------------------------------------------------------------------------
# Model A: line-by-line port of server/src/crypto/blake2s.cpp
# ---------------------------------------------------------------------------
class PortBlake2s:
    """Mirrors blake2s.cpp exactly, including its buffer bookkeeping."""

    def __init__(self, out_len: int, key: bytes = b"") -> None:
        self.h = list(IV)
        self.t = 0                 # uint64_t t_
        self.buf = bytearray(BLOCK)
        self.buflen = 0
        self.out_len = out_len
        key_len = len(key)
        # h_[0] ^= 0x01010000U ^ (key_len << 8) ^ out_len   (uint32 arithmetic)
        self.h[0] ^= (0x01010000 ^ (key_len << 8) ^ out_len) & M32
        if key:
            # The C++ constructor performs no length check here (only the
            # blake2s() helper does); a >64-byte key would overflow buf_.
            if len(key) > BLOCK:
                raise ValueError("key longer than the 64-byte buffer")
            self.buf[0:len(key)] = key
            self.buflen = BLOCK    # key block is a full block, compressed later

    def _mix(self, v, a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M32
        v[d] = _rotr(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & M32
        v[b] = _rotr(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b] + y) & M32
        v[d] = _rotr(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & M32
        v[b] = _rotr(v[b] ^ v[c], 7)

    def _compress(self, block: bytes, last: bool) -> None:
        m = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
        v = [0] * 16
        for i in range(8):
            v[i] = self.h[i]
            v[i + 8] = IV[i]
        v[12] ^= self.t & M32
        v[13] ^= (self.t >> 32) & M32
        if last:
            v[14] = (~v[14]) & M32
        for s in SIGMA:
            self._mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            self._mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            self._mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            self._mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            self._mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            self._mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            self._mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            self._mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        for i in range(8):
            self.h[i] = (self.h[i] ^ v[i] ^ v[i + 8]) & M32

    def update(self, data: bytes) -> None:
        if not data:
            return
        p = 0
        n = len(data)
        left = self.buflen
        fill = BLOCK - left
        if n > fill:
            if fill > 0:
                self.buf[left:left + fill] = data[0:fill]
            self.buflen = 0
            self.t += BLOCK
            self._compress(bytes(self.buf), False)
            p += fill
            n -= fill
            while n > BLOCK:                # keep the last block buffered
                self.t += BLOCK
                self._compress(data[p:p + BLOCK], False)
                p += BLOCK
                n -= BLOCK
            self.buf[0:n] = data[p:p + n]
            self.buflen = n
        else:
            self.buf[left:left + n] = data[0:n]
            self.buflen = left + n

    def final(self, out_size: int) -> bytes:
        if out_size < self.out_len:
            return b""                      # the C++ returns 0 (failure)
        self.t += self.buflen
        for i in range(self.buflen, BLOCK):
            self.buf[i] = 0
        self._compress(bytes(self.buf), True)
        full = b"".join(x.to_bytes(4, "little") for x in self.h)
        return full[:self.out_len]


def port_hash(data: bytes, key: bytes = b"", out_len: int = 32,
              chunk: int = 0) -> bytes:
    """Run the ported implementation, optionally with chunked updates."""
    h = PortBlake2s(out_len, key)
    if chunk <= 0:
        h.update(data)
    else:
        for i in range(0, len(data), chunk):
            h.update(data[i:i + chunk])
    return h.final(out_len)


# ---------------------------------------------------------------------------
# Model B: from-scratch RFC 7693 implementation (deliberately different shape)
# ---------------------------------------------------------------------------
def rfc_blake2s(data: bytes, key: bytes = b"", out_len: int = 32) -> bytes:
    if not 1 <= out_len <= 32:
        raise ValueError("out_len must be 1..32")
    if len(key) > 32:
        raise ValueError("key must be at most 32 bytes")

    h = list(IV)
    h[0] ^= (0x01010000 ^ (len(key) << 8) ^ out_len) & M32

    # Explicit block sequence: [padded key block] + message blocks. The key
    # block counts as 64 hashed bytes (RFC 7693 section 3.3); if the message is
    # empty it *is* the final block.
    chunks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    if not chunks:
        chunks = [b""]
    seq: list[bytes] = []
    if key:
        seq.append(key + bytes(BLOCK - len(key)))
        seq.extend(chunks)
        if not data:
            seq = seq[:1]
    else:
        seq = chunks

    t = 0
    for idx, blk in enumerate(seq):
        last = idx == len(seq) - 1
        t += BLOCK if (key and idx == 0) else len(blk)
        block = blk + bytes(BLOCK - len(blk))
        m = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
        v = h[:] + list(IV)
        v[12] ^= t & M32
        v[13] ^= (t >> 32) & M32
        if last:
            v[14] = (~v[14]) & M32

        def g(a, b, c, d, x, y, v=v):
            v[a] = (v[a] + v[b] + x) & M32
            v[d] = _rotr(v[d] ^ v[a], 16)
            v[c] = (v[c] + v[d]) & M32
            v[b] = _rotr(v[b] ^ v[c], 12)
            v[a] = (v[a] + v[b] + y) & M32
            v[d] = _rotr(v[d] ^ v[a], 8)
            v[c] = (v[c] + v[d]) & M32
            v[b] = _rotr(v[b] ^ v[c], 7)

        for s in SIGMA:
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        h = [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]

    return b"".join(x.to_bytes(4, "little") for x in h)[:out_len]


# ---------------------------------------------------------------------------
# Case list (deterministic, shared with the C++ driver)
# ---------------------------------------------------------------------------
def pattern(n: int) -> bytes:
    """The same pattern the existing unit test uses for its 1000-byte input."""
    return bytes(((i * 31 + 7) & 0xFF) for i in range(n))


FIXED_INPUTS = [
    ("empty", b""),
    ("abc", b"abc"),
    ("len1", bytes([0x2A])),
    ("len63", pattern(63)),
    ("len64", pattern(64)),
    ("len65", pattern(65)),
    ("len127", pattern(127)),
    ("len128", pattern(128)),
    ("len129", pattern(129)),
    ("len1000", pattern(1000)),
]

KEYED_KEYS = [
    ("k1", bytes([0x2A])),                                   # 1-byte key
    ("k16", bytes((i * 7 + 1) & 0xFF for i in range(16))),
    ("k32", bytes((i * 5 + 3) & 0xFF for i in range(32))),
]

SPLITS = [0, 1, 7, 63, 64, 65, 127, 128, 129, 999]


def build_cases() -> list[dict]:
    cases: list[dict] = []
    for name, data in FIXED_INPUTS:
        variants = [("", b"")] + list(KEYED_KEYS)
        for key_name, key in variants:
            for out_len in (32, 16):
                splits = [0, 7, 64]           # one-shot + representative splits
                if name == "len1000":
                    splits = SPLITS
                elif len(data) in (64, 65, 128, 129):
                    splits = [0, 1, 63, 64, 65]
                for chunk in splits:
                    label = f"{name}/{key_name or 'unkeyed'}/out{out_len}/chunk{chunk}"
                    cases.append({"label": label, "out_len": out_len, "key": key,
                                  "data": data, "chunk": chunk})

    rng = random.Random(20260214)             # fixed seed: reproducible everywhere
    for i in range(200):
        n = rng.choice([0, 1, 2, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257,
                        rng.randint(0, 300)])
        data = bytes(rng.getrandbits(8) for _ in range(n))
        klen = rng.choice([0, 0, 1, 16, 32])
        key = bytes(rng.getrandbits(8) for _ in range(klen))
        out_len = rng.choice([16, 32, 32, 16, rng.randint(1, 32)])
        chunk = rng.choice([0, 0, 1, 3, 7, 64, 65, rng.randint(1, 200)])
        label = f"rand{i:03d}/len{n}/kenv{klen}/out{out_len}/chunk{chunk}"
        cases.append({"label": label, "out_len": out_len, "key": key,
                      "data": data, "chunk": chunk})
    return cases


# ---------------------------------------------------------------------------
# C++ driver plumbing
# ---------------------------------------------------------------------------
def find_compiler(explicit: str | None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    from shutil import which
    zig = os.path.expanduser(
        os.path.join("~", ".local", "pylibs", "ziglang", "zig.exe"))
    if os.path.isfile(zig):
        return zig
    for cand in ("g++", "clang++", "c++"):
        if which(cand):
            return cand
    return None


def build_driver(cxx: str, exe: str) -> bool:
    cmd = [cxx]
    if os.path.basename(cxx).lower().startswith("zig"):
        cmd += ["c++"]
    cmd += ["-std=c++20", "-O2", "-Wall", "-Wextra", f"-I{INCLUDE}",
            os.path.join(SRC, "crypto", "blake2s.cpp"),
            os.path.join(SRC, "crypto", "ct.cpp"),
            DRIVER_SRC, "-o", exe]
    print(f"[build] {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr)
        return False
    return True


def run_driver(exe: str, cases: list[dict]) -> dict[str, str] | None:
    os.makedirs(WORK, exist_ok=True)
    spec_path = os.path.join(WORK, "blake2s_cases.txt")
    with open(spec_path, "w", encoding="ascii") as f:
        for c in cases:
            key_hex = c["key"].hex() or "-"
            data_hex = c["data"].hex() or "-"
            f.write(f"{c['label']}|{c['out_len']}|{key_hex}|{data_hex}|"
                    f"{c['chunk']}\n")
    res = subprocess.run([exe, spec_path], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[driver] exit {res.returncode}\n{res.stdout}\n{res.stderr}")
        return None
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            label, status, digest = parts
            out[label] = digest if status == "OK" else f"<{status}>"
    return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
# Every digest hard-coded in server/tests/unit/test_blake2s.cpp is re-derived
# here from hashlib. Two shapes exist in that file:
#   * the two RFC 7693 Appendix B vectors, found by test name;
#   * the rows of the `kGolden` table, each re-derived from its OWN documented
#     (data_len, key_len, out_len) plus the file's byte patterns. A vector whose
#     digest is right but whose parameters are quoted wrong therefore fails too.
# A coverage row then insists that no digest literal in the file escapes this
# audit, so a vector added later cannot silently go unchecked.
UNIT_TEST_SRC = os.path.join(REPO, "server", "tests", "unit", "test_blake2s.cpp")

_GOLDEN_ROW = re.compile(
    r'\{"([A-Za-z0-9_]+)",\s*(\d+),\s*(\d+),\s*(\d+),\s*"([0-9a-fA-F]+)"\}')
_HEX_LITERAL = re.compile(r'"([0-9a-fA-F]{32,})"')
_TEST_BLOCK = re.compile(r'TEST\(\w+,\s*(\w+)\)\s*\{(.*?)\n\}', re.S)


def pattern_key(n: int) -> bytes:
    """test_blake2s.cpp pattern_key(): byte[i] = (i * 7 + 1) & 0xFF."""
    return bytes(((i * 7 + 1) & 0xFF) for i in range(n))


def audit_unit_test_vectors() -> tuple[list[dict], int]:
    """Verify every hard-coded digest in test_blake2s.cpp against hashlib."""
    rows: list[dict] = []
    failures = 0

    def record(check: str, expected: str, observed: str) -> None:
        nonlocal failures
        ok = expected == observed
        failures += 0 if ok else 1
        rows.append({"check": check, "expected": expected, "observed": observed,
                     "verdict": "PASS" if ok else "FAIL"})

    try:
        with open(UNIT_TEST_SRC, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:                                    # pragma: no cover
        record("test_blake2s.cpp: readable", "readable", f"<{exc}>")
        return rows, failures

    # 1. the RFC 7693 Appendix B vectors, located by test name
    rfc_inputs = {"empty_input_rfc_vector": b"", "abc_rfc_vector": b"abc"}
    for match in _TEST_BLOCK.finditer(text):
        name = match.group(1)
        if name not in rfc_inputs:
            continue
        literal = _HEX_LITERAL.search(match.group(2))
        expected = literal.group(1).lower() if literal else "<no digest found>"
        record(f"test_blake2s.cpp: {name}", expected,
               ref_blake2s(rfc_inputs[name], b"", 32).hex())

    # 2. every row of the kGolden table, using that row's own parameters
    for match in _GOLDEN_ROW.finditer(text):
        label, data_len, key_len, out_len, expected = match.groups()
        record(f"test_blake2s.cpp: golden/{label}", expected.lower(),
               ref_blake2s(pattern(int(data_len)), pattern_key(int(key_len)),
                           int(out_len)).hex())

    # 3. coverage: every digest literal in the file must be a value this audit
    #    re-derived with hashlib. A repeated known-answer constant (e.g. the
    #    same "abc" digest quoted in a second test) is fine; a literal nobody
    #    verified is not.
    literals = [h.lower() for h in _HEX_LITERAL.findall(text)]
    verified = {row["observed"] for row in rows if row["verdict"] == "PASS"}
    unverified = sorted({h for h in literals if h not in verified})
    if unverified:
        record("test_blake2s.cpp: coverage (no unverified digest literals)",
               "every digest literal re-derived with hashlib",
               f"{len(unverified)} unverified literal(s): " + ", ".join(unverified))

    return rows, failures


def write_markdown(summary: dict, path: str, driver_status: str) -> None:
    """Emit the verification record for the mandated fixed cases."""
    rows = [r for r in summary["results"] if r["chunk"] == 0]
    lines = []
    lines.append("### Mandated fixed cases (one-shot)\n")
    lines.append("| # | input | key len | out len | expected (hashlib) | "
                 "port of blake2s.cpp | RFC 7693 model | C++ | verdict |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        cxx = r.get("cxx", "n/a")
        verdict = "PASS"
        if r["port"] != r["expected"] or r["rfc"] != r["expected"]:
            verdict = "FAIL"
        if "cxx" in r and r["cxx_verdict"] != "PASS":
            verdict = "FAIL"
        lines.append(f"| {i} | `{r['label'].split('/')[0]}` | {r['key_len']} | "
                     f"{r['out_len']} | `{r['expected']}` | "
                     f"`{'match' if r['port'] == r['expected'] else r['port']}` | "
                     f"`{'match' if r['rfc'] == r['expected'] else r['rfc']}` | "
                     f"`{'match' if cxx == r['expected'] else cxx}` | {verdict} |")
    lines.append("")
    lines.append("### Streaming splits (same inputs, digested in chunks)\n")
    lines.append("| cases | port == hashlib | RFC model == hashlib | C++ == hashlib |")
    lines.append("|---|---|---|---|")
    streamed = [r for r in summary["results"] if r["chunk"] != 0]
    p_ok = sum(1 for r in streamed if r["port"] == r["expected"])
    r_ok = sum(1 for r in streamed if r["rfc"] == r["expected"])
    c_ok = sum(1 for r in streamed
               if r.get("cxx") == r["expected"]) if streamed and "cxx" in streamed[0] else None
    lines.append(f"| {len(streamed)} | {p_ok}/{len(streamed)} | {r_ok}/{len(streamed)} | "
                 f"{'n/a' if c_ok is None else str(c_ok) + '/' + str(len(streamed))} |")
    lines.append("")
    lines.append("### Randomised differential cases\n")
    rand = [r for r in summary["results"] if r["label"].startswith("rand")]
    p_ok = sum(1 for r in rand if r["port"] == r["expected"])
    r_ok = sum(1 for r in rand if r["rfc"] == r["expected"])
    c_ok = sum(1 for r in rand
               if r.get("cxx") == r["expected"]) if rand and "cxx" in rand[0] else None
    lines.append("| cases | port == hashlib | RFC model == hashlib | C++ == hashlib |")
    lines.append("|---|---|---|---|")
    lines.append(f"| {len(rand)} | {p_ok}/{len(rand)} | {r_ok}/{len(rand)} | "
                 f"{'n/a' if c_ok is None else str(c_ok) + '/' + str(len(rand))} |")
    lines.append("")
    lines.append(f"Driver: {driver_status}")
    lines.append("")
    lines.append("### Hard-coded vectors in server/tests/unit/test_blake2s.cpp\n")
    lines.append("| test | expected | hashlib says | verdict |")
    lines.append("|---|---|---|---|")
    for v in summary["unit_vectors"]:
        lines.append(f"| `{v['check'].split(': ')[1]}` | `{v['expected']}` | "
                     f"`{v['observed']}` | {v['verdict']} |")
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[doc  ] wrote {path}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", help="C++ compiler (zig.exe, g++, clang++)")
    ap.add_argument("--driver", help="pre-built driver executable")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--markdown", help="write the markdown record to this path")
    args = ap.parse_args(argv[1:])

    os.makedirs(WORK, exist_ok=True)
    cases = build_cases()
    results: list[dict] = []
    failures = 0

    # --- 1. every hard-coded digest in test_blake2s.cpp vs hashlib ----------
    vector_rows, vector_failures = audit_unit_test_vectors()
    failures += vector_failures
    for row in vector_rows:
        print(f"[vector] {'ok  ' if row['verdict'] == 'PASS' else 'FAIL'} "
              f"{row['check']}")
        if row["verdict"] != "PASS":
            print(f"        expected (hashlib) = {row['observed']}")
            print(f"        quoted in the test = {row['expected']}")

    # --- 2. Python models vs hashlib ---------------------------------------
    port_fail = rfc_fail = 0
    for c in cases:
        expected = ref_blake2s(c["data"], c["key"], c["out_len"])
        ported = port_hash(c["data"], c["key"], c["out_len"], c["chunk"])
        rfc = rfc_blake2s(c["data"], c["key"], c["out_len"])
        if ported != expected:
            port_fail += 1
            if port_fail <= 10:
                print(f"[port] MISMATCH {c['label']}\n  ref={expected.hex()}\n"
                      f"  port={ported.hex()}")
        if rfc != expected:
            rfc_fail += 1
            if rfc_fail <= 10:
                print(f"[rfc]  MISMATCH {c['label']}\n  ref={expected.hex()}\n"
                      f"  rfc ={rfc.hex()}")
        results.append({"label": c["label"], "out_len": c["out_len"],
                        "key_len": len(c["key"]), "data_len": len(c["data"]),
                        "chunk": c["chunk"], "expected": expected.hex(),
                        "port": ported.hex(), "rfc": rfc.hex()})
    print(f"[port] line-by-line port of blake2s.cpp: "
          f"{len(cases) - port_fail}/{len(cases)} cases match hashlib")
    print(f"[rfc ] from-scratch RFC 7693 model:      "
          f"{len(cases) - rfc_fail}/{len(cases)} cases match hashlib")
    failures += port_fail + rfc_fail

    # --- 3. the real C++ through the driver --------------------------------
    driver_status = "skipped (no compiler found)"
    cxx_fail = 0
    if not args.no_build:
        exe = args.driver
        if exe:
            driver_status = f"prebuilt {exe}"
        else:
            cxx = find_compiler(args.cxx)
            if cxx:
                exe = os.path.join(WORK, "blake2s_driver.exe")
                if build_driver(cxx, exe):
                    driver_status = f"built with {cxx}"
                else:
                    driver_status = "build FAILED"
                    failures += 1
                    exe = None
            else:
                driver_status = "skipped (no compiler at --cxx and none on PATH)"
        if exe and os.path.isfile(exe):
            got = run_driver(exe, cases)
            if got is None:
                driver_status += " / run FAILED"
                failures += 1
            else:
                by_label = {r["label"]: r for r in results}
                for c in cases:
                    row = by_label[c["label"]]
                    observed = got.get(c["label"], "<missing>")
                    ok = observed == row["expected"]
                    if not ok:
                        cxx_fail += 1
                        if cxx_fail <= 10:
                            print(f"[cxx]  MISMATCH {c['label']}\n"
                                  f"  ref={row['expected']}\n  cxx={observed}")
                    row["cxx"] = observed
                    row["cxx_verdict"] = "PASS" if ok else "FAIL"
                print(f"[cxx ] C++ implementation: {len(cases) - cxx_fail}/"
                      f"{len(cases)} cases match hashlib  ({driver_status})")
                failures += cxx_fail

    summary = {
        "cases": len(cases),
        "port_failures": port_fail,
        "rfc_failures": rfc_fail,
        "cxx_failures": cxx_fail,
        "driver": driver_status,
        "unit_vectors": vector_rows,
        "results": results,
    }
    with open(os.path.join(WORK, "blake2s_results.json"), "w",
              encoding="ascii") as f:
        json.dump(summary, f, indent=1)

    print("\n=== BLAKE2s verification summary ===")
    print(f"cases                        : {len(cases)}")
    print(f"hashlib vs port(blake2s.cpp) : {len(cases) - port_fail} pass / "
          f"{port_fail} fail")
    print(f"hashlib vs rfc7693 model     : {len(cases) - rfc_fail} pass / "
          f"{rfc_fail} fail")
    print(f"C++ driver                   : {driver_status}")
    if cxx_fail or "built with" in driver_status or "prebuilt" in driver_status:
        print(f"hashlib vs real C++          : {len(cases) - cxx_fail} pass / "
              f"{cxx_fail} fail")
    print(f"unit-test vectors            : "
          f"{sum(1 for r in vector_rows if r['verdict'] == 'PASS')}"
          f"/{len(vector_rows)} correct")
    if args.markdown:
        write_markdown(summary, args.markdown, driver_status)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
