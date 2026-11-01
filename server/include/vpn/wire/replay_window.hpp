// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Anti-replay window (RFC 6479 "IPsec Anti-Replay Algorithm without Bit
// Shifting", the same shape WireGuard uses: 8192-bit ring of 64-bit words with
// an 8128-bit usable window).
//
// Contract:
//   * One instance per receive keypair, owned by exactly one worker thread.
//   * Not internally synchronised - no atomics on the packet path. The data
//     plane keeps these in worker-private session slots (see docs/ARCHITECTURE.md).
//   * `accept()` both validates and marks: it must be called only after
//     decryption succeeded, so that forged counters cannot poison the window.
#pragma once

#include <array>
#include <cstdint>

#include "vpn/wire/constants.hpp"

namespace vpn::wire {

class ReplayWindow {
 public:
  // Returns true if `counter` is fresh and marks it seen; false if it is a
  // duplicate, too old, or beyond the protocol's hard message limit.
  [[nodiscard]] bool accept(std::uint64_t counter) noexcept;

  [[nodiscard]] std::uint64_t highest() const noexcept { return highest_; }
  [[nodiscard]] bool initialized() const noexcept { return initialized_; }

  // Used when a keypair is replaced (never mid-keypair).
  void reset() noexcept;

 private:
  void set_bit(std::uint64_t counter) noexcept;

  std::array<std::uint64_t, kCounterWords> backtrack_{};
  std::uint64_t highest_{0};
  bool initialized_{false};
};

}  // namespace vpn::wire
