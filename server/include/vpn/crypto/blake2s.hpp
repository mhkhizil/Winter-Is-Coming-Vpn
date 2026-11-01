// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// BLAKE2s (RFC 7693) with keyed mode - the hash inside the WireGuard handshake.
//
// Why we implement it ourselves: BoringSSL exposes no keyed BLAKE2s-128 through
// EVP, and libsodium ships only BLAKE2b. We need all three WireGuard shapes:
//   * BLAKE2s-256(data)                         - transcript hashing, KDF PRK
//   * keyed BLAKE2s-256(key, data)              - KDF expansion, handshake hash
//   * keyed BLAKE2s-128(key, data)              - mac1, mac2, cookie
//
// Validation (blocking, see docs/PROTOCOL.md "Acceptance gates"):
//   * RFC 7693 Appendix B vectors  ("abc", empty)
//   * differential test vs the reference implementation in tests/golden
//   * streaming == one-shot for every split point
#pragma once

#include <cstddef>
#include <cstdint>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

constexpr std::size_t kBlake2sBlockSize = 64;
constexpr std::size_t kBlake2sMaxOut = 32;
constexpr std::size_t kBlake2sMaxKey = 32;

class Blake2s {
 public:
  // out_len in [1, 32]; key may be empty (unkeyed) or up to 32 bytes (keyed).
  // Preconditions are enforced by the two factory helpers below, not by
  // exceptions: this type lives on the packet path where exceptions are banned.
  Blake2s(std::size_t out_len, ByteSpan key) noexcept;

  void update(ByteSpan data) noexcept;

  // Writes exactly out_len() bytes into `out`. `out` must be at least that big;
  // returns the number of bytes written. The state is wiped afterwards.
  std::size_t final(MutableByteSpan out) noexcept;

  [[nodiscard]] std::size_t out_len() const noexcept { return out_len_; }

 private:
  void compress(const Byte* block, bool last) noexcept;

  std::uint32_t h_[8];
  std::uint64_t t_;       // total bytes hashed (64-bit counter, RFC 7693 §2.5)
  Byte buf_[kBlake2sBlockSize];
  std::size_t buflen_;
  std::size_t out_len_;
};

// One-shot helpers. Return zero-initialised data only if preconditions fail,
// which callers guarantee by construction (fixed-size WireGuard constants).
[[nodiscard]] Bytes<32> blake2s_256(ByteSpan data) noexcept;
[[nodiscard]] Bytes<32> blake2s_256(ByteSpan data, ByteSpan key) noexcept;
[[nodiscard]] Bytes<16> blake2s_128(ByteSpan data, ByteSpan key) noexcept;

// Fills any output length in [1,32] (used by the KDF's variable-length steps).
[[nodiscard]] bool blake2s(ByteSpan data, ByteSpan key, MutableByteSpan out) noexcept;

}  // namespace vpn::crypto
