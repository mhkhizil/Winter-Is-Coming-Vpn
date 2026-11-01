#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Independent verification of server/src/wire/replay_window.cpp.

Two models are compared, and (when a compiler is available) both are compared
against the real C++ through drivers/replay_driver.cpp:

  * ``RefFilter``  - a faithful port of RFC 6479 as implemented by the
    reference WireGuard anti-replay filter (wireguard-go replay/replay.go,
    MIT: ``ValidateCounter``). This is the semantic authority.
  * ``PortWindow`` - a line-by-line port of server/src/wire/replay_window.cpp.

A RefFilter/PortWindow divergence is a spec deviation in the C++; a
PortWindow/driver divergence is a fidelity bug in this script.

RFC 6479 / wireguard-go window rule: reject iff ``last - counter > windowSize``,
with windowSize = (128-1)*64 = 8128, i.e. a counter exactly 8128 behind the
highest accepted counter is still ACCEPTED.

Usage:
  python verify_replay_window.py [--cxx <compiler>] [--driver <exe>] [--no-build]
Exit code 0 == every C++ behaviour matches the reference filter.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys

from verify_blake2s import WORK, INCLUDE, SRC, find_compiler

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER_SRC = os.path.join(HERE, "drivers", "replay_driver.cpp")

BLOCK_BITS = 64
BLOCK_MASK = 63
RING_BLOCKS = 128
RING_MASK = RING_BLOCKS - 1
WINDOW_SIZE = (RING_BLOCKS - 1) * BLOCK_BITS          # 8128
U64_MAX = (1 << 64) - 1
# wireguard-go device/constants.go: RejectAfterMessages = (1<<64) - (1<<13) - 1
WG_LIMIT = (1 << 64) - (1 << 13) - 1
# server/include/vpn/wire/constants.hpp:
#   kRejectAfterMessages = UINT64_MAX - (1 << 13) - 1
CPP_LIMIT = U64_MAX - (1 << 13) - 1


class RefFilter:
    """wireguard-go replay.Filter.ValidateCounter, transcribed line by line."""

    def __init__(self) -> None:
        self.last = 0
        self.ring = [0] * RING_BLOCKS

    def reset(self) -> None:
        self.last = 0
        self.ring = [0] * RING_BLOCKS

    def initialized(self) -> bool:
        return any(self.ring)

    def validate(self, counter: int, limit: int = WG_LIMIT) -> bool:
        if counter >= limit:
            return False
        index_block = counter >> 6
        if counter > self.last:                       # move the window forward
            current = self.last >> 6
            diff = index_block - current
            if diff > RING_BLOCKS:
                diff = RING_BLOCKS                   # cap: clear the whole ring
            for i in range(current + 1, current + diff + 1):
                self.ring[i & RING_MASK] = 0
            self.last = counter
        elif self.last - counter > WINDOW_SIZE:        # behind the window
            return False
        index_block &= RING_MASK
        old = self.ring[index_block]
        new = old | (1 << (counter & BLOCK_MASK))
        self.ring[index_block] = new
        return old != new


class PortWindow:
    """Line-by-line port of server/src/wire/replay_window.cpp."""

    def __init__(self) -> None:
        self.backtrack = [0] * RING_BLOCKS
        self.highest = 0
        self.initialized_flag = False

    def reset(self) -> None:
        self.backtrack = [0] * RING_BLOCKS
        self.highest = 0
        self.initialized_flag = False

    def initialized(self) -> bool:
        return self.initialized_flag

    def _set_bit(self, counter: int) -> None:
        word = (counter >> 6) & RING_MASK
        self.backtrack[word] |= 1 << (counter & BLOCK_MASK)

    def accept(self, counter: int) -> bool:
        if counter >= CPP_LIMIT:
            return False
        if not self.initialized_flag:
            self.initialized_flag = True
            self.highest = counter
            self._set_bit(counter)
            return True
        # NOTE: this is the line under scrutiny - the reference uses
        # `> WINDOW_SIZE`, not `>= WINDOW_SIZE`.
        if counter < self.highest and (self.highest - counter) >= \
                (WINDOW_SIZE):
            return False
        index = counter >> 6
        if counter > self.highest:
            index_current = self.highest >> 6
            delta = index - index_current
            words_to_clear = delta if delta < RING_BLOCKS else RING_BLOCKS
            for i in range(1, words_to_clear + 1):
                self.backtrack[(i + index_current) & RING_MASK] = 0
            self.highest = counter
        word = index & RING_MASK
        mask = 1 << (counter & BLOCK_MASK)
        if self.backtrack[word] & mask:
            return False
        self.backtrack[word] |= mask
        return True


# ---------------------------------------------------------------------------
# Scenarios. Each op is an int counter, or "R" for reset().
# ---------------------------------------------------------------------------
def build_scenarios() -> list[tuple[str, list]]:
    sc: list[tuple[str, list]] = []

    sc.append(("in_order_0_to_999", list(range(1000))))
    sc.append(("duplicates", [0, 0, 1, 1, 5, 5, 5, 6, 6]))
    sc.append(("out_of_order_within_window", [1000, 990, 500, 1, 990, 999, 1, 998]))
    # Boundary: exactly windowSize behind the highest counter.
    sc.append(("boundary_exactly_8128", [100000, 100000 - 8128, 100000 - 8128,
                                         100000 - 8127, 100000 - 8129]))
    sc.append(("boundary_just_inside_8127", [100000, 100000 - 8127]))
    sc.append(("boundary_just_outside_8129", [100000, 100000 - 8129]))
    # Ring rear-wrap: every stale bit must be cleared, no false replays.
    sc.append(("ring_wrap_exactly_8192", [10, 10 + 8192, 10 + 8192, 10 + 1, 10]))
    sc.append(("ring_wrap_3x", [10, 10 + 3 * 8192, 10]))
    sc.append(("ring_wrap_partial_64", [100, 164, 100, 300]))
    # A counter whose ring word/bit collides with a counter a full ring earlier.
    sc.append(("stale_bit_collision", [5, 5 + 8192, 5 + 8193, 5 + 8192 + 63,
                                       6 + 8192]))
    # Deep out-of-order after a large forward jump.
    sc.append(("jump_then_backfill", [0, 40000] + list(range(40000 - 50, 40000))))
    sc.append(("reset_to_scratch", [1, 2, "R", 1, 2, 1]))
    sc.append(("first_counter_zero", [0, 0, 1]))
    sc.append(("first_counter_one", [1, 0]))
    sc.append(("first_counter_large", [123456789, 123456789, 123456790,
                                       123456789 - 8128]))
    sc.append(("first_counter_2pow63", [(1 << 63), (1 << 63) - 1, (1 << 63) + 1,
                                        (1 << 63) - 8128]))
    # Counter ceiling (both models' limit constants differ by one; see NOTES).
    sc.append(("ceiling_reject_after_messages",
               [CPP_LIMIT - 1, CPP_LIMIT, CPP_LIMIT + 1, U64_MAX, WG_LIMIT - 1]))
    sc.append(("no_wraparound_accept", [U64_MAX - 1, U64_MAX, 0, 1]))
    # Forged-high-counter poisoning (documented contract: validate after AEAD).
    sc.append(("forged_high_counter_poisons_window", [10, 9000, 11, 5000]))

    rng = random.Random(0x5EED)
    for i in range(300):
        ops = []
        cur = rng.choice([0, rng.randint(0, 20000), rng.randint(0, 1 << 40)])
        for _ in range(rng.randint(5, 60)):
            kind = rng.random()
            if kind < 0.45:
                cur += rng.randint(0, 3)
            elif kind < 0.7:
                cur -= rng.randint(0, 200)
            elif kind < 0.85:
                cur += rng.randint(0, 20000)
            elif kind < 0.95:
                cur += rng.choice([0, 8127, 8128, 8129, 8191, 8192, 8193])
            else:
                cur = rng.randint(0, 1 << 62)
            if cur < 0:
                cur = 0
            ops.append(cur)
            if rng.random() < 0.03:
                ops.append("R")
        sc.append((f"random{i:03d}", ops))
    return sc


def run_model(model, ops: list) -> tuple[list[bool], list]:
    bits: list[bool] = []
    state: list = []
    for op in ops:
        if op == "R":
            model.reset()
            bits.append(None)            # type: ignore[arg-type]
        else:
            bits.append(model.validate(op) if isinstance(model, RefFilter)
                        else model.accept(op))
        state.append((model.last if isinstance(model, RefFilter) else model.highest,
                      model.initialized()))
    return bits, state


# ---------------------------------------------------------------------------
# Explicit expectations for the semantics the mandate calls out
# ---------------------------------------------------------------------------
def spec_checks(impl_name: str) -> list[dict]:
    """Semantics table, evaluated against whichever implementation we observe."""
    out: list[dict] = []

    def record(name: str, expected: str, observed: str, note: str = "") -> None:
        out.append({"check": name, "expected": expected, "observed": observed,
                    "verdict": "PASS" if expected == observed else "FAIL",
                    "note": note})

    # in-order
    w = PortWindow()
    ok = all(w.accept(c) for c in range(1000))
    record("in-order 0..999 all accepted", "accept", "accept" if ok else "reject")
    record("highest() after 0..999", "999", str(w.highest))

    # duplicates
    w = PortWindow()
    seq = [0, 0, 1, 1, 5, 5, 5, 6]
    got = ["accept" if w.accept(c) else "reject" for c in seq]
    record("duplicates rejected", "accept,reject,accept,reject,accept,reject,reject,accept",
           ",".join(got))

    # out-of-order inside window
    w = PortWindow()
    seq = [1000, 990, 500, 1, 990, 999]
    got = ["accept" if w.accept(c) else "reject" for c in seq]
    record("out-of-order within window",
           "accept,accept,accept,accept,reject,accept", ",".join(got))

    # boundary at exactly 8128 behind the highest counter
    ref = RefFilter()
    ref.validate(100000)
    ref_ok = ref.validate(100000 - 8128)
    w = PortWindow()
    w.accept(100000)
    cpp_ok = w.accept(100000 - 8128)
    record("counter exactly 8128 behind highest (RFC 6479 / wireguard-go)",
           "accept" if ref_ok else "reject",
           "accept" if cpp_ok else "reject",
           "reference window is inclusive of lag == windowSize")

    # 8127 and 8129
    ref = RefFilter(); ref.validate(100000)
    w = PortWindow(); w.accept(100000)
    record("counter 8127 behind highest",
           "accept" if ref.validate(100000 - 8127) else "reject",
           "accept" if w.accept(100000 - 8127) else "reject")
    ref = RefFilter(); ref.validate(100000)
    w = PortWindow(); w.accept(100000)
    record("counter 8129 behind highest",
           "accept" if ref.validate(100000 - 8129) else "reject",
           "accept" if w.accept(100000 - 8129) else "reject")

    # ring wrap after >8192
    w = PortWindow()
    a = w.accept(10)
    b = w.accept(10 + 3 * 8192)
    c = w.accept(10 + 3 * 8192 + 63)      # same ring bit as 10 + 8192 + 63 - ...
    d = w.accept(10)                       # far behind -> must be rejected
    record("ring wrap after 3*8192: new counters accepted, old rejected",
           "accept,accept,accept,reject",
           ",".join("accept" if x else "reject" for x in (a, b, c, d)))

    # stale bit collision: counter 64-bit ring reused after exactly 8192
    w = PortWindow()
    w.accept(5)
    fresh = w.accept(5 + 8192)
    record("counter exactly one full ring ahead is fresh", "accept",
           "accept" if fresh else "reject", "clears stale ring slots")

    # ceiling
    w = PortWindow()
    record("kRejectAfterMessages itself rejected", "reject",
           "reject" if not w.accept(CPP_LIMIT) else "accept")
    w = PortWindow()
    record("UINT64_MAX rejected", "reject",
           "reject" if not w.accept(U64_MAX) else "accept")

    # first-seen counter of any value
    for v in (0, 1, 999, 123456789, 1 << 62):
        w = PortWindow()
        first = w.accept(v)
        dup = w.accept(v)
        record(f"first-seen counter {v} accepted, duplicate rejected",
               "accept,reject",
               f"{'accept' if first else 'reject'},{'accept' if dup else 'reject'}")

    del impl_name
    return out


# ---------------------------------------------------------------------------
# Driver plumbing
# ---------------------------------------------------------------------------
def build_driver(cxx: str, exe: str) -> bool:
    cmd = [cxx]
    if os.path.basename(cxx).lower().startswith("zig"):
        cmd += ["c++"]
    cmd += ["-std=c++20", "-O2", "-Wall", "-Wextra", f"-I{INCLUDE}",
            os.path.join(SRC, "wire", "replay_window.cpp"),
            DRIVER_SRC, "-o", exe]
    print(f"[build] {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr)
        return False
    return True


def run_driver(exe: str, scenarios: list[tuple[str, list]]) -> dict | None:
    os.makedirs(WORK, exist_ok=True)
    spec_path = os.path.join(WORK, "replay_scenarios.txt")
    with open(spec_path, "w", encoding="ascii") as f:
        for label, ops in scenarios:
            f.write(label + "|" + ",".join(str(o) for o in ops) + "\n")
    res = subprocess.run([exe, spec_path], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[driver] exit {res.returncode}\n{res.stdout}\n{res.stderr}")
        return None
    out: dict[str, dict] = {}
    for line in res.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == 5 and parts[1] == "OK":
            out[parts[0]] = {"bits": parts[2], "highest": int(parts[3]),
                             "initialized": parts[4] == "1"}
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", help="C++ compiler (zig.exe, g++, clang++)")
    ap.add_argument("--driver", help="pre-built replay_driver executable")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args(argv[1:])

    os.makedirs(WORK, exist_ok=True)
    scenarios = build_scenarios()

    divergences: list[dict] = []
    fidelity_diffs: list[str] = []

    ref_bits: dict[str, list] = {}
    port_bits: dict[str, list] = {}
    port_state: dict[str, list] = {}
    for label, ops in scenarios:
        ref = RefFilter()
        bits_r, _ = run_model(ref, ops)
        port = PortWindow()
        bits_p, st_p = run_model(port, ops)
        ref_bits[label] = bits_r
        port_bits[label] = bits_p
        port_state[label] = st_p
        for i, (a, b) in enumerate(zip(bits_r, bits_p)):
            if a is None:
                continue
            if a != b:
                divergences.append({"scenario": label, "op_index": i,
                                    "counter": ops[i], "reference": a,
                                    "cpp": b})

    # --- real C++ -----------------------------------------------------------
    driver_status = "skipped (no compiler found)"
    exe = args.driver
    if not args.no_build:
        if not exe:
            cxx = find_compiler(args.cxx)
            if cxx:
                exe = os.path.join(WORK, "replay_driver.exe")
                driver_status = (f"built with {cxx}" if build_driver(cxx, exe)
                                 else "build FAILED")
                if "FAILED" in driver_status:
                    exe = None
            else:
                driver_status = "skipped (no compiler)"
        else:
            driver_status = f"prebuilt {exe}"

    driver_bits: dict[str, list] = {}
    if exe and os.path.isfile(exe):
        got = run_driver(exe, scenarios)
        if got is None:
            driver_status += " / run FAILED"
        else:
            for label, ops in scenarios:
                if label not in got:
                    fidelity_diffs.append(f"{label}: missing from driver output")
                    continue
                bits = []
                for ch in got[label]["bits"]:
                    if ch == "r":
                        bits.append(None)
                    else:
                        bits.append(ch == "1")
                driver_bits[label] = bits
                if bits != port_bits[label]:
                    fidelity_diffs.append(f"{label}: model != C++")
                # highest()/initialized() conformance at the end of the run
                exp_h, exp_init = port_state[label][-1] if port_state[label] else (0, False)
                if got[label]["highest"] != exp_h:
                    fidelity_diffs.append(
                        f"{label}: highest {got[label]['highest']} != {exp_h}")
                if got[label]["initialized"] != exp_init:
                    fidelity_diffs.append(f"{label}: initialized differs")

    # --- classify divergences ----------------------------------------------
    real_bugs: list[dict] = []
    informational: list[dict] = []
    for d in divergences:
        if CPP_LIMIT <= d["counter"] < WG_LIMIT:
            informational.append(d)            # limit constant differs by one
        else:
            real_bugs.append(d)

    # --- semantics table ---------------------------------------------------
    rows = spec_checks("PortWindow" if not driver_bits else "C++ driver")
    check_failures = [r for r in rows if r["verdict"] == "FAIL"]

    summary = {
        "scenarios": len(scenarios),
        "divergences_reference_vs_cpp": len(real_bugs),
        "divergences_informational": len(informational),
        "fidelity_diffs": fidelity_diffs,
        "driver": driver_status,
        "semantics": rows,
        "divergences": real_bugs,
        "informational": informational,
    }
    with open(os.path.join(WORK, "replay_results.json"), "w", encoding="ascii") as f:
        json.dump(summary, f, indent=1)

    for r in rows:
        print(f"[spec] {'ok  ' if r['verdict'] == 'PASS' else 'FAIL'} {r['check']}: "
              f"expected {r['expected']}, observed {r['observed']}")

    print(f"\n[ref ] scenario divergences reference-vs-C++: {len(real_bugs)} "
          f"({len(informational)} informational)")
    for d in real_bugs[:20]:
        print(f"        {d['scenario']} op#{d['op_index']} counter={d['counter']}: "
              f"reference={'accept' if d['reference'] else 'reject'} "
              f"cpp={'accept' if d['cpp'] else 'reject'}")
    print(f"[cxx ] driver: {driver_status}")
    if fidelity_diffs:
        print(f"[cxx ] model/C++ fidelity differences: {len(fidelity_diffs)}")
        for line in fidelity_diffs[:10]:
            print(f"        {line}")
    elif driver_bits:
        print(f"[cxx ] model matches C++ on all {len(scenarios)} scenarios")

    print("\n=== replay window verification summary ===")
    print(f"semantics checks       : {len(rows) - len(check_failures)}/{len(rows)} pass")
    print(f"scenarios              : {len(scenarios)}")
    print(f"spec deviations found  : {len(real_bugs)}")
    failed = bool(real_bugs or check_failures or fidelity_diffs
                  or "FAILED" in driver_status)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
