#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Scratch check: replays every assertion added to tests/unit/test_replay_window.cpp
against the Python port of the C++ so a typo cannot reach the C++ suite.

Run: python check_new_replay_assertions.py     (exit 0 == all expectations hold)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from verify_replay_window import (  # noqa: E402
    CPP_LIMIT,
    PortWindow,
    WINDOW_SIZE,
)

failures = 0


def expect(label: str, observed, expected) -> None:
    global failures
    ok = observed == expected
    if not ok:
        failures += 1
    print(f"{'ok  ' if ok else 'FAIL'} {label}: expected {expected}, observed {observed}")


def main() -> int:
    # window_slides_forward_one_counter_at_a_time
    w = PortWindow()
    expect("accept 0..9000 in order", all(w.accept(c) for c in range(0, 9001)), True)
    expect("highest after 0..9000", w.highest, 9000)
    expect("duplicate 8999", w.accept(8999), False)
    expect("duplicate 2000", w.accept(2000), False)
    expect("out-of-window 0", w.accept(0), False)
    expect("next counter 9001", w.accept(9001), True)
    expect("forward jump 9101", w.accept(9101), True)
    expect("highest after jump", w.highest, 9101)

    # duplicate_does_not_move_the_highest_counter
    w = PortWindow()
    expect("accept 10", w.accept(10), True)
    expect("duplicate 10", w.accept(10), False)
    expect("highest still 10", w.highest, 10)
    expect("accept 5", w.accept(5), True)
    expect("highest still 10 (b)", w.highest, 10)
    expect("accept 11", w.accept(11), True)
    expect("highest 11", w.highest, 11)

    # exact_ring_size_jump_clears_every_stale_bit
    w = PortWindow()
    head = 100 + 8192
    expect("accept 5", w.accept(5), True)
    expect("accept 100", w.accept(100), True)
    expect("accept full-ring jump", w.accept(head), True)
    expect("highest after ring jump", w.highest, head)
    expect("5+8192 fresh (stale bit cleared)", w.accept(5 + 8192), True)
    expect("head-1 fresh", w.accept(head - 1), True)
    expect("5 now too old", w.accept(5), False)

    # partial_ring_wrap_keeps_bits_inside_the_window
    w = PortWindow()
    expect("accept 100", w.accept(100), True)
    expect("accept 164", w.accept(164), True)
    expect("accept 163", w.accept(163), True)
    expect("duplicate 163", w.accept(163), False)
    expect("100 still marked", w.accept(100), False)
    expect("accept 162", w.accept(162), True)

    # initialized_flag_lifecycle
    w = PortWindow()
    expect("fresh: not initialized", w.initialized(), False)
    expect("fresh: highest 0", w.highest, 0)
    expect("accept 0", w.accept(0), True)
    expect("now initialized", w.initialized(), True)
    w.reset()
    expect("after reset: not initialized", w.initialized(), False)
    expect("after reset: accept 0", w.accept(0), True)
    expect("after reset: duplicate 0", w.accept(0), False)

    # large_counters_do_not_overflow_the_window_arithmetic
    w = PortWindow()
    big = 1 << 63
    expect("accept 2^63", w.accept(big), True)
    expect("accept 2^63-1", w.accept(big - 1), True)
    expect("accept 2^63+1", w.accept(big + 1), True)
    expect("highest 2^63+1", w.highest, big + 1)
    expect("reject 0", w.accept(0), False)
    expect("reject 2^62", w.accept(big >> 1), False)
    expect("accept exactly 8127 behind",
           w.accept(big + 1 - (WINDOW_SIZE - 1)), True)

    o = PortWindow()
    expect("other: accept 0", o.accept(0), True)
    expect("other: accept ceiling-1", o.accept(CPP_LIMIT - 1), True)
    expect("other: reject 1", o.accept(1), False)
    expect("other: reject ceiling", o.accept(CPP_LIMIT), False)

    # forward_jump_inside_one_word_keeps_the_bits_already_set
    # (added by the round-2 pass: the ring-clearing loop must never clear the
    # word it is standing on, or it forgets replays inside the current word)
    w = PortWindow()
    expect("fwd-in-word: accept 0", w.accept(0), True)
    expect("fwd-in-word: accept 5 (same word)", w.accept(5), True)
    expect("fwd-in-word: accept 64 (moves to word 1)", w.accept(64), True)
    expect("fwd-in-word: 5 still marked", w.accept(5), False)
    expect("fwd-in-word: 0 still marked", w.accept(0), False)
    expect("fwd-in-word: accept 63 (gap in word 0)", w.accept(63), True)
    expect("fwd-in-word: accept 70 (same word as 64)", w.accept(70), True)
    expect("fwd-in-word: 63 duplicate", w.accept(63), False)
    expect("fwd-in-word: highest 70", w.highest, 70)

    # known-bug probe (documents the deviation, must be False today)
    w = PortWindow()
    w.accept(100000)
    expect("KNOWN BUG: exactly 8128 behind is rejected (should be accepted)",
           w.accept(100000 - WINDOW_SIZE), False)

    print(f"\n{failures} unexpected result(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
