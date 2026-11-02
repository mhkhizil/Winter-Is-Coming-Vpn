// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/wire/replay_window.hpp"

namespace vpn::wire {
namespace {
constexpr std::uint64_t kWordShift = 6;      // log2(64)
constexpr std::uint64_t kWordMask = 63;      // 64 - 1
constexpr std::uint64_t kRingMask = static_cast<std::uint64_t>(kCounterWords) - 1;
}  // namespace

void ReplayWindow::reset() noexcept {
  backtrack_.fill(0);
  highest_ = 0;
  initialized_ = false;
}

void ReplayWindow::set_bit(std::uint64_t counter) noexcept {
  const std::uint64_t word = (counter >> kWordShift) & kRingMask;
  backtrack_[static_cast<std::size_t>(word)] |= (1ULL << (counter & kWordMask));
}

bool ReplayWindow::accept(std::uint64_t counter) noexcept {
  // Hard protocol ceiling: never accept a counter we could not safely AEAD.
  if (counter >= kRejectAfterMessages) return false;

  if (!initialized_) {
    initialized_ = true;
    highest_ = counter;
    set_bit(counter);
    return true;
  }

  // Older than the whole window -> reject. RFC 6479 (and wireguard-go) reject
  // only when `highest - counter > window`, so a counter exactly 8128 behind the
  // head is still inside the window and MUST be accepted. Subtraction form
  // avoids unsigned overflow.
  if (counter < highest_ && (highest_ - counter) > kCounterWindowSize) return false;

  const std::uint64_t index = counter >> kWordShift;

  if (counter > highest_) {
    const std::uint64_t index_current = highest_ >> kWordShift;
    const std::uint64_t words_to_clear = (index - index_current) < kCounterWords
                                             ? (index - index_current)
                                             : kCounterWords;
    // Clear exactly the ring slots we are moving past, so stale bits from
    // counters a full ring ago cannot be mistaken for recent ones.
    for (std::uint64_t i = 1; i <= words_to_clear; ++i) {
      backtrack_[static_cast<std::size_t>((i + index_current) & kRingMask)] = 0;
    }
    highest_ = counter;
  }

  const std::uint64_t word = index & kRingMask;
  const std::uint64_t mask = 1ULL << (counter & kWordMask);
  std::uint64_t& slot = backtrack_[static_cast<std::size_t>(word)];
  if ((slot & mask) != 0) return false;  // replay
  slot |= mask;
  return true;
}

}  // namespace vpn::wire
