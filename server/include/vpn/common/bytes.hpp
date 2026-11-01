// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Byte vocabulary shared by the wire codec, the crypto core and the config
// layer. Everything is a span: no hidden copies, no ownership ambiguity.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace vpn {

using Byte = std::uint8_t;
using ByteSpan = std::span<const Byte>;
using MutableByteSpan = std::span<Byte>;

template <std::size_t N>
using Bytes = std::array<Byte, N>;

template <std::size_t N>
[[nodiscard]] constexpr ByteSpan as_span(const Bytes<N>& b) noexcept {
  return ByteSpan{b.data(), b.size()};
}

template <std::size_t N>
[[nodiscard]] constexpr MutableByteSpan as_span(Bytes<N>& b) noexcept {
  return MutableByteSpan{b.data(), b.size()};
}

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] inline std::string to_hex(ByteSpan bytes) {
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const Byte b = bytes[i];
    out[2 * i] = kHexDigits[(b >> 4) & 0x0FU];
    out[2 * i + 1] = kHexDigits[b & 0x0FU];
  }
  return out;
}

[[nodiscard]] constexpr int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Strict: requires out.size()*2 == hex.size() and no separators.
[[nodiscard]] inline bool from_hex(std::string_view hex, MutableByteSpan out) noexcept {
  if (hex.size() != out.size() * 2) return false;
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = hex_value(hex[2 * i]);
    const int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<Byte>((hi << 4) | lo);
  }
  return true;
}

// Wipes secrets without the compiler being allowed to elide the stores.
// Never use std::memset for key material (see docs/THREAT_MODEL.md, key hygiene).
inline void secure_zero(MutableByteSpan span) noexcept {
  volatile Byte* p = span.data();
  for (std::size_t i = 0; i < span.size(); ++i) {
    p[i] = 0;
  }
}

[[nodiscard]] constexpr bool is_zero(ByteSpan span) noexcept {
  Byte acc = 0;
  for (const Byte b : span) {
    acc = static_cast<Byte>(acc | b);
  }
  return acc == 0;
}

[[nodiscard]] constexpr bool equals(ByteSpan a, ByteSpan b) noexcept {
  if (a.size() != b.size()) return false;
  Byte acc = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    acc = static_cast<Byte>(acc | static_cast<Byte>(a[i] ^ b[i]));
  }
  return acc == 0;
}

// Copies min(dst,src) bytes; returns the number of bytes copied.
inline std::size_t copy_bytes(MutableByteSpan dst, ByteSpan src) noexcept {
  const std::size_t n = dst.size() < src.size() ? dst.size() : src.size();
  for (std::size_t i = 0; i < n; ++i) dst[i] = src[i];
  return n;
}

}  // namespace vpn
