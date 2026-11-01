#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Independent verification of mac1 / mac2 / cookie derivation and of the
WireGuard message layout in server/src/wire/message.cpp.

The expected values are computed here with ``hashlib.blake2s`` (keyed BLAKE2s)
directly from the WireGuard specification:

    mac1_key = BLAKE2s-256("mac1----" || Spub_receiver)
    mac1     = keyed-BLAKE2s-128(key = mac1_key, msg[0 : mac1_offset))
    mac2     = keyed-BLAKE2s-128(key = cookie,    msg[0 : mac2_offset))
    cookie   = keyed-BLAKE2s-128(key = cookie_secret,
                                 source_ip || source_port_be)

and the message layouts are re-implemented from the protocol document (field
offsets below), so the C++ is compared against an independent model rather than
against itself. The real C++ is exercised through
server/tests/golden/drivers/mac_driver.cpp when a compiler is available.

Usage:
  python verify_macs.py [--cxx <compiler>] [--driver <exe>] [--no-build]
Exit code 0 == every check that is expected to pass did pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

from verify_blake2s import WORK, INCLUDE, SRC, find_compiler

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER_SRC = os.path.join(HERE, "drivers", "mac_driver.cpp")

# --- WireGuard v1 message layouts, straight from the protocol document -------
# https://www.wireguard.com/protocol/ (message formats)
L_INIT = {"type": (0, 4), "sender": (4, 4), "ephemeral": (8, 32),
          "encrypted_static": (40, 48), "encrypted_timestamp": (88, 28),
          "mac1": (116, 16), "mac2": (132, 16)}
L_RESP = {"type": (0, 4), "sender": (4, 4), "receiver": (8, 4),
          "ephemeral": (12, 32), "encrypted_nothing": (44, 16),
          "mac1": (60, 16), "mac2": (76, 16)}
L_COOKIE = {"type": (0, 4), "receiver": (4, 4), "nonce": (8, 24),
            "encrypted_cookie": (32, 32)}
L_TRANSPORT = {"type": (0, 4), "receiver": (4, 4), "counter": (8, 8)}

INIT_SIZE, RESP_SIZE, COOKIE_SIZE, TRANSPORT_HDR = 148, 92, 64, 16
MAC1_LABEL = b"mac1----"
COOKIE_LABEL = b"cookie--"


def b2s(data: bytes, key: bytes = b"", digest_size: int = 32) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=digest_size).digest()


def mac1_key(spub: bytes) -> bytes:
    assert len(spub) == 32
    return b2s(MAC1_LABEL + spub)


def ref_mac1(msg_prefix: bytes, spub: bytes) -> bytes:
    return b2s(msg_prefix, key=mac1_key(spub), digest_size=16)


def ref_mac2(msg_prefix: bytes, cookie: bytes) -> bytes:
    return b2s(msg_prefix, key=cookie, digest_size=16)


def ref_cookie(secret: bytes, ip: bytes, port: int) -> bytes:
    return b2s(ip + port.to_bytes(2, "big"), key=secret, digest_size=16)


# --- independent packer: builds the datagrams field by field ----------------
def build_initiation(sender: int, spub_server: bytes) -> bytes:
    msg = bytearray(INIT_SIZE)
    msg[0:4] = (1).to_bytes(4, "little")
    msg[4:8] = sender.to_bytes(4, "little")
    for name in ("ephemeral", "encrypted_static", "encrypted_timestamp"):
        off, ln = L_INIT[name]
        msg[off:off + ln] = bytes(((off + i) * 17 + 5) & 0xFF for i in range(ln))
    msg[8] = 0x33                       # keep the ephemeral non-zero
    mac1 = ref_mac1(bytes(msg[0:116]), spub_server)
    msg[116:132] = mac1                 # mac2 covers mac1
    msg[132:148] = ref_mac2(bytes(msg[0:132]), bytes(range(16)))
    return bytes(msg)


def build_response(sender: int, receiver: int, spub_server: bytes) -> bytes:
    msg = bytearray(RESP_SIZE)
    msg[0:4] = (2).to_bytes(4, "little")
    msg[4:8] = sender.to_bytes(4, "little")
    msg[8:12] = receiver.to_bytes(4, "little")
    for name in ("ephemeral", "encrypted_nothing"):
        off, ln = L_RESP[name]
        msg[off:off + ln] = bytes(((off + i) * 23 + 9) & 0xFF for i in range(ln))
    msg[12] = 0x44
    msg[60:76] = ref_mac1(bytes(msg[0:60]), spub_server)
    msg[76:92] = ref_mac2(bytes(msg[0:76]), bytes(range(16)))
    return bytes(msg)


def build_cookie_reply(receiver: int) -> bytes:
    msg = bytearray(COOKIE_SIZE)
    msg[0:4] = (3).to_bytes(4, "little")
    msg[4:8] = receiver.to_bytes(4, "little")
    msg[8:32] = bytes(((i * 11) + 1) & 0xFF for i in range(24))
    msg[32:64] = bytes(((i * 13) + 2) & 0xFF for i in range(32))
    return bytes(msg)


def build_transport(receiver: int, counter: int, ct_len: int) -> bytes:
    msg = bytearray(TRANSPORT_HDR + ct_len + 16)
    msg[0:4] = (4).to_bytes(4, "little")
    msg[4:8] = receiver.to_bytes(4, "little")
    msg[8:16] = counter.to_bytes(8, "little")
    for i in range(ct_len + 16):
        msg[TRANSPORT_HDR + i] = (i * 7 + 3) & 0xFF
    return bytes(msg)


# ---------------------------------------------------------------------------
# Case construction
# ---------------------------------------------------------------------------
SPUB_A = bytes((i * 3 + 1) & 0xFF for i in range(32))
SPUB_B = bytes((i * 5 + 2) & 0xFF for i in range(32))
COOKIE_A = bytes((i * 7 + 4) & 0xFF for i in range(16))
SECRET = bytes((i * 11 + 6) & 0xFF for i in range(32))
IPV4 = bytes([203, 0, 113, 7])
IPV6 = bytes.fromhex("20010db8000000000000000000000001")


def build_spec() -> tuple[list[dict], dict[str, bytes]]:
    """Returns (driver cases, mapping label -> expected hex)."""
    cases: list[dict] = []
    expect: dict[str, str] = {}
    init = build_initiation(0xA1B2C3D4, SPUB_A)
    resp = build_response(0x11223344, 0xA1B2C3D4, SPUB_A)

    def add(label: str, kind: str, pub: bytes, cookie: bytes, data: bytes,
            port: int, expected: bytes) -> None:
        cases.append({"label": label, "kind": kind, "pub": pub, "cookie": cookie,
                      "data": data, "port": port})
        expect[label] = expected.hex()

    # --- mac1 key ----------------------------------------------------------
    add("mac1_key/spubA", "mac1key", SPUB_A, b"", b"", 0, mac1_key(SPUB_A))
    add("mac1_key/spubB", "mac1key", SPUB_B, b"", b"", 0, mac1_key(SPUB_B))

    # --- initiation: mac1 over [0,116), mac2 over [0,132) -------------------
    add("init/mac1[0:116)", "mac1", SPUB_A, b"", init[0:116], 0,
        ref_mac1(init[0:116], SPUB_A))
    add("init/mac2[0:132)", "mac2", b"", COOKIE_A, init[0:132], 0,
        ref_mac2(init[0:132], COOKIE_A))
    # wrong-coverage probes: these must NOT equal the correct MACs above.
    add("init/mac1[0:132) WRONG", "mac1", SPUB_A, b"", init[0:132], 0,
        ref_mac1(init[0:132], SPUB_A))
    add("init/mac1[0:115) WRONG", "mac1", SPUB_A, b"", init[0:115], 0,
        ref_mac1(init[0:115], SPUB_A))
    add("init/mac2[0:116) WRONG", "mac2", b"", COOKIE_A, init[0:116], 0,
        ref_mac2(init[0:116], COOKIE_A))
    add("init/mac2[0:148) WRONG", "mac2", b"", COOKIE_A, init[0:148], 0,
        ref_mac2(init[0:148], COOKIE_A))

    # --- response: mac1 over [0,60), mac2 over [0,76) ----------------------
    add("resp/mac1[0:60)", "mac1", SPUB_A, b"", resp[0:60], 0,
        ref_mac1(resp[0:60], SPUB_A))
    add("resp/mac2[0:76)", "mac2", b"", COOKIE_A, resp[0:76], 0,
        ref_mac2(resp[0:76], COOKIE_A))
    add("resp/mac1[0:76) WRONG", "mac1", SPUB_A, b"", resp[0:76], 0,
        ref_mac1(resp[0:76], SPUB_A))
    add("resp/mac2[0:60) WRONG", "mac2", b"", COOKIE_A, resp[0:60], 0,
        ref_mac2(resp[0:60], COOKIE_A))

    # --- cookies -----------------------------------------------------------
    for port in (0, 1, 51820, 65535):
        add(f"cookie/v4/port{port}", "cookie", SECRET, b"", IPV4, port,
            ref_cookie(SECRET, IPV4, port))
    add("cookie/v6/port51820", "cookie", SECRET, b"", IPV6, 51820,
        ref_cookie(SECRET, IPV6, 51820))
    add("cookie/other-secret", "cookie", SPUB_A, b"", IPV4, 51820,
        ref_cookie(SPUB_A, IPV4, 51820))
    # Degenerate input: an empty address span. The derivation must still hash
    # exactly `ip || port_be` == the port, i.e. two bytes - not two zero bytes
    # (which was the observable symptom of the old fixed-offset port bug).
    add("cookie/empty-ip/port51820", "cookie", SECRET, b"", b"", 51820,
        ref_cookie(SECRET, b"", 51820))

    # --- codec round-trip (offset conformance of decode/encode) ------------
    # Transport datagrams are compared on the header+payload prefix only:
    # encode() reserves 16 trailing tag bytes but never writes them (the crypto
    # layer owns the AEAD tag), so an exact comparison is not meaningful there.
    for label, datagram in (
            ("roundtrip/initiation", init),
            ("roundtrip/response", resp),
            ("roundtrip/cookie", build_cookie_reply(0xDEADBEEF)),
            ("roundtrip/keepalive", build_transport(7, 0, 0)),
            ("roundtrip/transport16", build_transport(7, 0x0102030405060708, 16)),
            ("roundtrip/transport64", build_transport(9, 2 ** 63 + 17, 64))):
        is_transport = label.startswith("roundtrip/transport") or \
            label.startswith("roundtrip/keepalive")
        add(label, "roundtrip", b"", b"", datagram, 0, datagram)
        if is_transport:
            cases[-1]["compare_bytes"] = len(datagram) - 16

    return cases, expect


# ---------------------------------------------------------------------------
# Driver plumbing
# ---------------------------------------------------------------------------
def build_driver(cxx: str, exe: str) -> bool:
    cmd = [cxx]
    if os.path.basename(cxx).lower().startswith("zig"):
        cmd += ["c++"]
    cmd += ["-std=c++20", "-O2", "-Wall", "-Wextra", f"-I{INCLUDE}",
            os.path.join(SRC, "crypto", "blake2s.cpp"),
            os.path.join(SRC, "crypto", "ct.cpp"),
            os.path.join(SRC, "wire", "message.cpp"),
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
    spec_path = os.path.join(WORK, "mac_cases.txt")
    with open(spec_path, "w", encoding="ascii") as f:
        for c in cases:
            f.write("|".join([
                c["label"], c["kind"],
                c["pub"].hex() or "-", c["cookie"].hex() or "-",
                c["data"].hex() or "-", str(c["port"])]) + "\n")
    res = subprocess.run([exe, spec_path], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[driver] exit {res.returncode}\n{res.stdout}\n{res.stderr}")
        return None
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            out[parts[0]] = parts[2] if parts[1] == "OK" else f"<{parts[1]}:{parts[2]}>"
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", help="C++ compiler (zig.exe, g++, clang++)")
    ap.add_argument("--driver", help="pre-built mac_driver executable")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args(argv[1:])

    os.makedirs(WORK, exist_ok=True)
    cases, expect = build_spec()
    rows: list[dict] = []
    failures = 0

    # --- 1. the WireGuard derivation is self-consistent (Python only) ------
    init = build_initiation(0xA1B2C3D4, SPUB_A)
    resp = build_response(0x11223344, 0xA1B2C3D4, SPUB_A)
    independence = [
        ("mac1 coverage: [0,116) != [0,132) (mac1 must not cover mac2)",
         ref_mac1(init[0:116], SPUB_A) != ref_mac1(init[0:132], SPUB_A)),
        ("mac2 coverage: [0,132) != [0,116) (mac2 must cover mac1)",
         ref_mac2(init[0:132], COOKIE_A) != ref_mac2(init[0:116], COOKIE_A)),
        ("mac1 is bound to the receiver static pubkey",
         ref_mac1(init[0:116], SPUB_A) != ref_mac1(init[0:116], SPUB_B)),
        ("mac2 is bound to the cookie",
         ref_mac2(init[0:132], COOKIE_A) != ref_mac2(init[0:132], bytes(16))),
        ("cookie is bound to the port",
         ref_cookie(SECRET, IPV4, 51820) != ref_cookie(SECRET, IPV4, 51821)),
        ("cookie is bound to the IPv4 address",
         ref_cookie(SECRET, IPV4, 51820) != ref_cookie(SECRET, bytes([203, 0, 113, 8]), 51820)),
        ("cookie distinguishes IPv4 (4+2 bytes) from a zero-padded 16-byte form",
         ref_cookie(SECRET, IPV4, 51820) !=
         ref_cookie(SECRET, IPV4 + bytes(12), 51820)),
        ("layout sizes: 148 / 92 / 64 / 16",
         (len(init), len(resp), len(build_cookie_reply(1)),
          len(build_transport(1, 0, 0)[:TRANSPORT_HDR])) == (148, 92, 64, 16)),
        ("mac1 label is exactly 8 bytes ('mac1----')", len(MAC1_LABEL) == 8),
        ("mac1 key != raw static public key", mac1_key(SPUB_A) != SPUB_A),
    ]
    for check, ok in independence:
        failures += 0 if ok else 1
        rows.append({"check": check, "expected": "holds",
                     "observed": "holds" if ok else "VIOLATED",
                     "verdict": "PASS" if ok else "FAIL"})
        print(f"[spec] {'ok  ' if ok else 'FAIL'} {check}")

    # --- 2. the real C++ against the independent reference ----------------
    driver_status = "skipped (no compiler found)"
    exe = args.driver
    got: dict[str, str] = {}
    if not args.no_build:
        if not exe:
            cxx = find_compiler(args.cxx)
            if cxx:
                exe = os.path.join(WORK, "mac_driver.exe")
                driver_status = (f"built with {cxx}" if build_driver(cxx, exe)
                                 else "build FAILED")
                if "FAILED" in driver_status:
                    failures += 1
                    exe = None
            else:
                driver_status = "skipped (no compiler)"
        else:
            driver_status = f"prebuilt {exe}"

    if exe and os.path.isfile(exe):
        got = run_driver(exe, cases)
        if got is None:
            driver_status += " / run FAILED"
            failures += 1
            got = {}
        else:
            for c in cases:
                label = c["label"]
                observed = got.get(label, "<missing>")
                n = c.get("compare_bytes")
                if n is None:
                    ok = observed == expect[label]
                else:
                    ok = observed[:2 * n] == expect[label][:2 * n]
                failures += 0 if ok else 1
                rows.append({"check": label, "expected": expect[label],
                             "observed": observed,
                             "verdict": "PASS" if ok else "FAIL"})
                print(f"[cxx ] {'ok  ' if ok else 'FAIL'} {label}"
                      + ("" if ok else f"\n        exp={expect[label]}\n"
                                       f"        got={observed}"))
            # Explicit cross-checks that the codec re-serialises our layout.
            for label in [k for k in expect if k.startswith("roundtrip/")]:
                entry = next(c for c in cases if c["label"] == label)
                n = entry.get("compare_bytes")
                n = len(expect[label]) // 2 if n is None else n
                ok = got.get(label, "")[:2 * n] == expect[label][:2 * n]
                note = ("byte-identical decode->encode round-trip"
                        if ok else "ROUND-TRIP CHANGED BYTES")
                print(f"[cxx ] {'ok  ' if ok else 'FAIL'} {label}: {note}")

            # encode(TransportData) returns header+payload+tag but writes only
            # header+payload: the 16 tag bytes are the crypto layer's job.
            tag_holes = []
            for c in cases:
                if c.get("compare_bytes") is None:
                    continue
                label = c["label"]
                tail = got.get(label, "")[2 * c["compare_bytes"]:]
                tag_holes.append(len(tail) == 32 and set(tail) == {"0"})
            untouched = all(tag_holes) if tag_holes else False
            rows.append({
                "check": "encode(TransportData) leaves the 16 AEAD tag bytes "
                         "unwritten (caller must fill them)",
                "expected": "unwritten by design (documented)",
                "observed": "unwritten" if untouched else "written",
                "verdict": "INFO" if untouched else "PASS"})
            print(f"[cxx ] info encode(TransportData) leaves the 16 AEAD tag bytes "
                  f"untouched: {untouched}")

            # The IPv4 cookie must bind the source port (WireGuard:
            # blake2s(key=secret, ip || port_be) with no padding).
            v4 = [got.get(f"cookie/v4/port{p}", "") for p in (0, 1, 51820, 65535)]
            if len(set(v4)) == 1:
                rows.append({
                    "check": "IPv4 cookie binds the source port",
                    "expected": "four different cookies for four ports",
                    "observed": "identical cookie for every port (BUG W-1)",
                    "verdict": "FAIL"})
                failures += 1
                print("[cxx ] FAIL IPv4 cookie ignores the source port "
                      f"({v4[0]}) - see BUG W-1")
            else:
                rows.append({"check": "IPv4 cookie binds the source port",
                             "expected": "four different cookies for four ports",
                             "observed": "distinct", "verdict": "PASS"})
                print("[cxx ] ok   IPv4 cookie binds the source port")

    # --- 3. latent defects found while probing ----------------------------
    # An empty source-address span must hash exactly two bytes (the port). The
    # old fixed-offset write hashed two ZERO bytes instead; this compares the
    # real C++ output against the reference rather than asserting from memory.
    empty_ip_expected = ref_cookie(SECRET, b"", 51820).hex()
    empty_ip_observed = got.get("cookie/empty-ip/port51820", "<not run>")
    empty_ip_ok = empty_ip_observed == empty_ip_expected

    with open(os.path.join(WORK, "mac_results.json"), "w", encoding="ascii") as f:
        json.dump({"driver": driver_status, "rows": rows,
                   "empty_ip_expected": empty_ip_expected,
                   "empty_ip_observed": empty_ip_observed,
                   "empty_ip_matches": empty_ip_ok}, f, indent=1)

    print("\n=== mac1/mac2/cookie verification summary ===")
    spec_rows = rows[:len(independence)]
    print(f"spec self-consistency checks : "
          f"{sum(1 for r in spec_rows if r['verdict'] == 'PASS')}/{len(spec_rows)}")
    print(f"C++ driver                   : {driver_status}")
    if len(rows) > len(independence):
        cxx_rows = [r for r in rows[len(independence):] if r["verdict"] != "INFO"]
        print(f"C++ vs independent reference : "
              f"{sum(1 for r in cxx_rows if r['verdict'] == 'PASS')}/"
              f"{len(cxx_rows)}")
    print(f"compute_cookie() empty-address case matches the reference: "
          f"{empty_ip_ok} (expected {empty_ip_expected}, got {empty_ip_observed})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
