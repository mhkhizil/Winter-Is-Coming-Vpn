// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Replay-window gates. These encode the exact semantics the data plane relies
// on: in-order acceptance, duplicate rejection, bounded out-of-order tolerance,
// and never trusting a counter that arrived before the window.
#include <cstdint>

#include "test_support.hpp"
#include "vpn/wire/constants.hpp"
#include "vpn/wire/replay_window.hpp"

namespace {
using vpn::wire::ReplayWindow;
}  // namespace

TEST(replay, accepts_in_order_from_zero) {
  ReplayWindow window;
  for (std::uint64_t counter = 0; counter < 1000; ++counter) {
    CHECK_MSG(window.accept(counter), "in-order counter must be accepted");
  }
  CHECK_EQ(window.highest(), std::uint64_t{999});
}

TEST(replay, rejects_duplicates) {
  ReplayWindow window;
  CHECK(window.accept(0));
  CHECK(!window.accept(0));
  CHECK(window.accept(1));
  CHECK(!window.accept(1));
  CHECK(window.accept(5));
  CHECK(!window.accept(5));
  CHECK(window.accept(6));
}

TEST(replay, accepts_out_of_order_within_window) {
  ReplayWindow window;
  CHECK(window.accept(1000));
  CHECK(window.accept(990));
  CHECK(window.accept(500));
  CHECK(window.accept(1));
  CHECK(!window.accept(990));  // already seen
  CHECK(window.accept(999));
}

TEST(replay, rejects_counters_older_than_the_window) {
  ReplayWindow window;
  CHECK(window.accept(100000));
  // RFC 6479: a counter exactly `window` behind the head is still inside it.
  const std::uint64_t oldest_inside = 100000 - vpn::wire::kCounterWindowSize;
  CHECK(window.accept(oldest_inside));
  // One further back is outside.
  CHECK(!window.accept(100000 - vpn::wire::kCounterWindowSize - 1));
  CHECK(!window.accept(0));
}

TEST(replay, big_forward_jump_clears_stale_bits) {
  ReplayWindow window;
  CHECK(window.accept(10));
  // Jump far enough forward to wrap the ring more than once.
  const std::uint64_t far = 10 + 3 * vpn::wire::kCounterBitsTotal;
  CHECK(window.accept(far));
  CHECK_EQ(window.highest(), far);
  // Everything below the window is now rejected, including the old bits.
  CHECK(!window.accept(10));
  // Counters inside the new window are still accepted.
  CHECK(window.accept(far - 1));
  CHECK(window.accept(far + 1));
}

TEST(replay, refuses_counters_at_or_above_the_protocol_ceiling) {
  ReplayWindow window;
  CHECK(!window.accept(vpn::wire::kRejectAfterMessages));
  CHECK(!window.accept(vpn::wire::kRejectAfterMessages + 1));
  CHECK(!window.accept(static_cast<std::uint64_t>(-1)));
}

TEST(replay, reset_restores_a_fresh_window) {
  ReplayWindow window;
  CHECK(window.accept(1));
  CHECK(window.accept(2));
  window.reset();
  CHECK(!window.initialized());
  CHECK_EQ(window.highest(), std::uint64_t{0});
  CHECK(window.accept(1));  // a brand-new keypair starts from scratch
}

TEST(replay, first_counter_can_be_any_value) {
  ReplayWindow window;
  CHECK(window.accept(123456789));
  CHECK_EQ(window.highest(), std::uint64_t{123456789});
  CHECK(!window.accept(123456789));
  CHECK(window.accept(123456790));
}

// ---------------------------------------------------------------------------
// Added by the crypto verification pass, 2026-02.
//
// The gates above pin the happy paths; these pin the ring bookkeeping that
// RFC 6479 gets wrong most often (window sliding, exact-ring jumps, stale bits
// after a wrap) and the 64-bit arithmetic. They were derived from, and are
// cross-checked against, an independent Python model:
//     python server/tests/golden/verify_replay_window.py
// which compares 319 scenarios against wireguard-go's replay.Filter.
// ---------------------------------------------------------------------------
TEST(replay, window_slides_forward_one_counter_at_a_time) {
  ReplayWindow window;
  // Strictly increasing: the window slides forward one word at a time and every
  // counter must be accepted exactly once (0..8191 is one full ring).
  for (std::uint64_t counter = 0; counter <= 9000; ++counter) {
    CHECK(window.accept(counter));
  }
  CHECK_EQ(window.highest(), std::uint64_t{9000});
  CHECK(!window.accept(8999));  // duplicate, right behind the head
  CHECK(!window.accept(2000));  // duplicate, still inside the window
  CHECK(!window.accept(0));     // fallen out of the window entirely
  CHECK(window.accept(9001));   // the next expected counter
  CHECK(window.accept(9101));   // forward jump across word boundaries
  CHECK_EQ(window.highest(), std::uint64_t{9101});
}

TEST(replay, duplicate_does_not_move_the_highest_counter) {
  ReplayWindow window;
  CHECK(window.accept(10));
  CHECK(!window.accept(10));
  CHECK_EQ(window.highest(), std::uint64_t{10});
  CHECK(window.accept(5));
  CHECK_EQ(window.highest(), std::uint64_t{10});
  CHECK(window.accept(11));
  CHECK_EQ(window.highest(), std::uint64_t{11});
}

TEST(replay, exact_ring_size_jump_clears_every_stale_bit) {
  ReplayWindow window;
  CHECK(window.accept(5));
  CHECK(window.accept(100));
  // Jumping by a full ring (128 words) must clear the whole bitmap.
  const std::uint64_t head = 100 + vpn::wire::kCounterBitsTotal;
  CHECK(window.accept(head));
  CHECK_EQ(window.highest(), head);
  // The counter whose ring slot/bit collides with 5 (5 + 8192) is inside the
  // new window and its bit must have been cleared - a stale bit here would be
  // a false replay rejection.
  CHECK(window.accept(5 + vpn::wire::kCounterBitsTotal));
  CHECK(window.accept(head - 1));
  CHECK(!window.accept(5));
}

TEST(replay, partial_ring_wrap_keeps_bits_inside_the_window) {
  ReplayWindow window;
  CHECK(window.accept(100));   // word 1
  CHECK(window.accept(164));   // word 2: clears word 2 only
  CHECK(window.accept(163));
  CHECK(!window.accept(163));  // duplicate in the current window
  CHECK(!window.accept(100));  // still marked: inside the window, already seen
  CHECK(window.accept(162));   // never seen, inside the window
}

TEST(replay, initialized_flag_lifecycle) {
  ReplayWindow window;
  CHECK(!window.initialized());
  CHECK_EQ(window.highest(), std::uint64_t{0});
  CHECK(window.accept(0));
  CHECK(window.initialized());
  window.reset();
  CHECK(!window.initialized());
  CHECK(window.accept(0));  // a fresh keypair accepts counter 0 again
  CHECK(!window.accept(0));
}

TEST(replay, large_counters_do_not_overflow_the_window_arithmetic) {
  // highest - counter is computed on uint64; the subtraction form must not wrap
  // for counters on either side of 2^63.
  ReplayWindow window;
  const std::uint64_t big = 1ULL << 63U;
  CHECK(window.accept(big));
  CHECK(window.accept(big - 1));
  CHECK(window.accept(big + 1));
  CHECK_EQ(window.highest(), big + 1);
  CHECK(!window.accept(0));  // astronomically behind -> rejected, no wrap
  CHECK(!window.accept(big >> 1U));
  // Exactly `window` behind the head is still accepted (RFC 6479 boundary).
  CHECK(window.accept(big + 1 - vpn::wire::kCounterWindowSize));

  ReplayWindow other;
  CHECK(other.accept(0));
  CHECK(other.accept(vpn::wire::kRejectAfterMessages - 1));
  // Everything that used to be in the window is now far behind it.
  CHECK(!other.accept(1));
  CHECK(!other.accept(vpn::wire::kRejectAfterMessages));
}

// ---------------------------------------------------------------------------
// Window boundary (FINDING R-1, fixed in src/wire/replay_window.cpp).
// RFC 6479 and wireguard-go reject only when `highest - counter > window`, so a
// counter exactly 8128 behind the head is inside the window. This is asserted
// unconditionally now; a regression fails the default gate.
// ---------------------------------------------------------------------------
TEST(replay, boundary_at_exactly_the_window_size) {
  ReplayWindow window;
  CHECK(window.accept(100000));
  CHECK(window.accept(100000 - vpn::wire::kCounterWindowSize));       // 91872: inside
  CHECK(!window.accept(100000 - vpn::wire::kCounterWindowSize - 1));  // 91871: outside
}

// ---------------------------------------------------------------------------
// Added by the 2026-02 verification pass, round 2: the ring-clearing loop must
// never clear the word it is currently standing on. Clearing the current word
// would forget every counter already seen in it, i.e. admit replays.
// ---------------------------------------------------------------------------
TEST(replay, forward_jump_inside_one_word_keeps_the_bits_already_set) {
  ReplayWindow window;
  CHECK(window.accept(0));
  CHECK(window.accept(5));    // same 64-counter word: nothing is cleared
  CHECK(window.accept(64));   // moves to word 1: only word 1 may be cleared
  CHECK(!window.accept(5));   // word 0 survived: still marked, still a replay
  CHECK(!window.accept(0));
  CHECK(window.accept(63));   // never seen, word 0, still inside the window
  CHECK(window.accept(70));   // same word as 64: bit 70 was clear
  CHECK(!window.accept(63));
  CHECK_EQ(window.highest(), std::uint64_t{70});
}

