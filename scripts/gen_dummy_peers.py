#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Emit N dummy [[peer]] blocks for a vpn-dp config.

Used to measure whether the transport path is O(1) in the number of peers: run
the same client against 1 peer and against thousands, and the packet rate should
barely move. The keys are random (peers that will never handshake), which is
exactly the case a linear scan over the table made expensive.

  python scripts/gen_dummy_peers.py --count 2000
"""
import argparse
import secrets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()
    for i in range(args.count):
        print("")
        print("[[peer]]")
        print(f'name = "dummy{i}"')
        print(f'public_key = "{secrets.token_hex(32)}"')
        print(f'allowed_ips = ["10.99.{(i // 254) % 254}.{i % 254 + 1}/32"]')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
