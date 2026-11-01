// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// A transport address, kept deliberately OS-free.
//
// The data plane needs an address type in three places that must not know about
// sockets: the anti-DoS cookie derivation (binds a cookie to IP||port), the peer
// table (endpoint + roaming), and the peers' stats output. If those used
// sockaddr_storage they would drag <winsock2.h> ordering rules and 16 vs 28 byte
// address lengths into the packet path; instead everything speaks this POD and
// udp_transport.cpp is the single place that converts.
//
// `address` holds the address bytes in network order (big endian / as on the
// wire), IPv4 occupying the first four bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "vpn/common/bytes.hpp"

namespace vpn::dataplane {

struct SocketAddress {
  enum class Family : std::uint8_t { kNone = 0, kIpv4 = 4, kIpv6 = 6 };

  Family family{Family::kNone};
  std::uint16_t port{0};  // host byte order; converted at the socket boundary
  Bytes<16> address{};

  [[nodiscard]] bool valid() const noexcept { return family != Family::kNone; }

  [[nodiscard]] std::size_t address_size() const noexcept {
    switch (family) {
      case Family::kIpv4: return 4;
      case Family::kIpv6: return 16;
      case Family::kNone: break;
    }
    return 0;
  }

  [[nodiscard]] ByteSpan address_bytes() const noexcept {
    return ByteSpan{address.data(), address_size()};
  }

  // Writes ip||port_be - the exact byte string the cookie MAC covers - into
  // `out` and returns its length, or 0 if the address is unusable.
  [[nodiscard]] std::size_t cookie_material(MutableByteSpan out) const noexcept {
    const std::size_t len = address_size();
    if (len == 0 || out.size() < len + 2) return 0;
    for (std::size_t i = 0; i < len; ++i) out[i] = address[i];
    out[len] = static_cast<Byte>((port >> 8) & 0xFFU);
    out[len + 1] = static_cast<Byte>(port & 0xFFU);
    return len + 2;
  }

  [[nodiscard]] bool operator==(const SocketAddress& other) const noexcept {
    if (family != other.family || port != other.port) return false;
    const std::size_t len = address_size();
    for (std::size_t i = 0; i < len; ++i) {
      if (address[i] != other.address[i]) return false;
    }
    return true;
  }
  [[nodiscard]] bool operator!=(const SocketAddress& other) const noexcept {
    return !(*this == other);
  }

  // "203.0.113.7:51820" / "[2001:db8::1]:51820". IPv6 is rendered in full
  // 8-group hex (no :: compression): this is a log/stats helper, not a
  // round-tripping parser. Parsing lives in udp_transport.
  [[nodiscard]] std::string to_string() const;
};

}  // namespace vpn::dataplane
