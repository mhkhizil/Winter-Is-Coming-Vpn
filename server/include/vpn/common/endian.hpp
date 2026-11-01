// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Explicit, dependency-free little/big endian access.
//
// We never reinterpret_cast a buffer to a struct: WireGuard messages are
// parsed field by field so that alignment, padding and strict-aliasing rules
// can never bite us, and so that every read is bounds-checked by construction.
#pragma once

#include <cstdint>

#include "vpn/common/bytes.hpp"

namespace vpn {

[[nodiscard]] constexpr std::uint16_t load_le16(const Byte* p) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}

[[nodiscard]] constexpr std::uint32_t load_le32(const Byte* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

[[nodiscard]] constexpr std::uint64_t load_le64(const Byte* p) noexcept {
  const std::uint64_t lo = load_le32(p);
  const std::uint64_t hi = load_le32(p + 4);
  return lo | (hi << 32);
}

[[nodiscard]] constexpr std::uint16_t load_be16(const Byte* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                    static_cast<std::uint16_t>(p[1]));
}

[[nodiscard]] constexpr std::uint32_t load_be32(const Byte* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

[[nodiscard]] constexpr std::uint64_t load_be64(const Byte* p) noexcept {
  const std::uint64_t hi = load_be32(p);
  const std::uint64_t lo = load_be32(p + 4);
  return (hi << 32) | lo;
}

constexpr void store_le16(Byte* p, std::uint16_t v) noexcept {
  p[0] = static_cast<Byte>(v & 0xFFU);
  p[1] = static_cast<Byte>((v >> 8) & 0xFFU);
}

constexpr void store_le32(Byte* p, std::uint32_t v) noexcept {
  p[0] = static_cast<Byte>(v & 0xFFU);
  p[1] = static_cast<Byte>((v >> 8) & 0xFFU);
  p[2] = static_cast<Byte>((v >> 16) & 0xFFU);
  p[3] = static_cast<Byte>((v >> 24) & 0xFFU);
}

constexpr void store_le64(Byte* p, std::uint64_t v) noexcept {
  store_le32(p, static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
  store_le32(p + 4, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFULL));
}

constexpr void store_be16(Byte* p, std::uint16_t v) noexcept {
  p[0] = static_cast<Byte>((v >> 8) & 0xFFU);
  p[1] = static_cast<Byte>(v & 0xFFU);
}

constexpr void store_be32(Byte* p, std::uint32_t v) noexcept {
  p[0] = static_cast<Byte>((v >> 24) & 0xFFU);
  p[1] = static_cast<Byte>((v >> 16) & 0xFFU);
  p[2] = static_cast<Byte>((v >> 8) & 0xFFU);
  p[3] = static_cast<Byte>(v & 0xFFU);
}

constexpr void store_be64(Byte* p, std::uint64_t v) noexcept {
  store_be32(p, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFULL));
  store_be32(p + 4, static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
}

}  // namespace vpn
