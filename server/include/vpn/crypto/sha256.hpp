// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// SHA-256 (FIPS 180-4) and HMAC-SHA-256.
//
// WireGuard itself does not need SHA-256, but three integration points do:
//   * Stripe webhook signatures (HMAC-SHA-256 over timestamp + payload)
//   * PostgreSQL SCRAM-SHA-256 authentication
//   * JWT HS256, should the control plane ever emit them
// Implemented here so the server keeps its zero-dependency property.
#pragma once

#include <cstddef>
#include <cstdint>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

constexpr std::size_t kSha256DigestSize = 32;
constexpr std::size_t kSha256BlockSize = 64;

class Sha256 {
 public:
  Sha256() noexcept;

  void update(ByteSpan data) noexcept;

  // Writes exactly 32 bytes; returns 32, or 0 if `out` is too small.
  std::size_t final(MutableByteSpan out) noexcept;

 private:
  void compress(const Byte* block) noexcept;

  std::uint32_t h_[8];
  std::uint64_t total_bytes_;
  Byte buffer_[kSha256BlockSize];
  std::size_t buffered_;
};

[[nodiscard]] Bytes<32> sha256(ByteSpan data) noexcept;

// HMAC-SHA-256 over the concatenation of `parts`.
[[nodiscard]] Bytes<32> hmac_sha256(ByteSpan key, ByteSpan data) noexcept;

// Constant-time comparison of a computed MAC with a received one.
[[nodiscard]] bool mac_equal(ByteSpan expected_hex, ByteSpan received_hex) noexcept;

}  // namespace vpn::crypto
