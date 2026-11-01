// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/crypto/ct.hpp"

#include <cstdint>

namespace vpn::ct {
namespace {
// Volatile access prevents the optimiser from turning the loop into a memset
// or dropping it entirely.
void volatile_fill(Byte* p, Byte value, std::size_t n) noexcept {
  volatile Byte* vp = p;
  for (std::size_t i = 0; i < n; ++i) vp[i] = value;
}
}  // namespace

bool equal(ByteSpan a, ByteSpan b) noexcept {
  if (a.size() != b.size()) return false;
  std::uint32_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<std::uint32_t>(a[i] ^ b[i]);
  }
  // Fold to a single bit and invert: the result is branch-free.
  return (diff - 1U) >> 31 != 0;
}

std::uint8_t is_nonzero_u8(std::uint32_t x) noexcept {
  // Equivalent to (x != 0) ? 0xFF : 0x00 without a branch.
  const std::uint32_t folded = (x | (~x + 1U)) >> 31;  // sign of x, 0 or 1
  return static_cast<std::uint8_t>(0U - folded);
}

void select(MutableByteSpan dst, ByteSpan a, ByteSpan b, bool cond) noexcept {
  const std::size_t n = dst.size() < a.size() ? dst.size() : a.size();
  const std::size_t m = n < b.size() ? n : b.size();
  // mask = 0xFF (all ones) when cond, 0x00 otherwise.
  // dst = b ^ (mask & (a ^ b))  ==>  cond ? a : b  (branch-free).
  const Byte mask = static_cast<Byte>(0U - static_cast<unsigned>(cond ? 1 : 0));
  for (std::size_t i = 0; i < m; ++i) {
    dst[i] = static_cast<Byte>(b[i] ^ (mask & (a[i] ^ b[i])));
  }
}

void cleanse(MutableByteSpan span) noexcept { volatile_fill(span.data(), 0, span.size()); }

}  // namespace vpn::ct
