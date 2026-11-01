#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Runs every independent verification under server/tests/golden/ and prints one
summary. Exit code 0 == every gate that is expected to pass did pass.

    python run_all_verifications.py                       # Python models only
    python run_all_verifications.py --cxx <zig.exe>       # + builds/runs the C++

`--cxx` accepts "zig.exe" (it is invoked as `zig c++`), g++ or clang++.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", help="C++ compiler (zig.exe, g++, clang++)")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args(argv[1:])

    extra = []
    if args.cxx:
        extra = ["--cxx", args.cxx]
    elif args.no_build:
        extra = ["--no-build"]

    scripts = [
        ("BLAKE2s (hashlib vs port vs RFC 7693 vs C++)", "verify_blake2s.py"),
        ("mac1 / mac2 / cookie + message offsets", "verify_macs.py"),
        ("anti-replay window (vs wireguard-go RFC 6479)", "verify_replay_window.py"),
        ("new C++ replay assertions sanity check", "check_new_replay_assertions.py"),
    ]
    overall = 0
    for title, script in scripts:
        print("=" * 74)
        print(f"== {title}")
        print("=" * 74)
        res = subprocess.run([sys.executable, os.path.join(HERE, script)] + extra,
                             cwd=HERE)
        if res.returncode != 0:
            overall = 1
        print()
    print("=" * 74)
    print("OVERALL:", "PASS" if overall == 0 else "FAILURES PRESENT (see above)")
    return overall


if __name__ == "__main__":
    sys.exit(main(sys.argv))
