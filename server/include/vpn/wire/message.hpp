// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// WireGuard message codec: parse/serialise without ever casting a buffer to a
// struct, and without allocating. See docs/PROTOCOL.md for the field tables.
//
// Decoding is deliberately strict (exact sizes, no trailing bytes) because a
// permissive parser is how VPN servers end up with fingerprintable behaviour
// and parser bugs. Anything that fails validation is dropped silently at the
// socket layer and counted - never logged with packet contents.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result.hpp"
#include "vpn/common/result_helpers.hpp"
#include "vpn/wire/constants.hpp"

namespace vpn::wire {

enum class MessageType : std::uint32_t {
  kHandshakeInitiation = 1,
  kHandshakeResponse = 2,
  kCookieReply = 3,
  kTransportData = 4,
};

[[nodiscard]] constexpr bool is_known_type(std::uint32_t raw) noexcept {
  return raw >= static_cast<std::uint32_t>(MessageType::kHandshakeInitiation) &&
         raw <= static_cast<std::uint32_t>(MessageType::kTransportData);
}

struct HandshakeInitiation {
  std::uint32_t sender_index{0};
  Bytes<kKeySize> ephemeral{};                    // X25519 ephemeral public
  Bytes<kEncryptedStaticSize> encrypted_static{};  // AEAD(initiator static pubkey)
  Bytes<kEncryptedTimestampSize> encrypted_timestamp{};  // AEAD(TAI64N)
  Bytes<kMacSize> mac1{};
  Bytes<kMacSize> mac2{};
};
static_assert(sizeof(HandshakeInitiation::ephemeral) == 32);

struct HandshakeResponse {
  std::uint32_t sender_index{0};
  std::uint32_t receiver_index{0};  // == initiator's sender_index
  Bytes<kKeySize> ephemeral{};
  Bytes<kEncryptedNothingSize> encrypted_nothing{};  // AEAD(empty), proves key
  Bytes<kMacSize> mac1{};
  Bytes<kMacSize> mac2{};
};

struct CookieReply {
  std::uint32_t receiver_index{0};  // == sender_index of the message we refused
  Bytes<kCookieNonceSize> nonce{};
  Bytes<kCookieSize + 16> encrypted_cookie{};  // XChaCha20-Poly1305(secret)
};

struct TransportData {
  std::uint32_t receiver_index{0};
  std::uint64_t counter{0};
  ByteSpan payload{};  // view into the caller's datagram; empty == keepalive
};

// A decoded message. `transport` aliases the input buffer for transport data,
// so the input must outlive this value - enforced by taking a ByteSpan and
// documenting the lifetime instead of copying every packet.
struct DecodedMessage {
  MessageType type{MessageType::kHandshakeInitiation};
  HandshakeInitiation initiation{};
  HandshakeResponse response{};
  CookieReply cookie{};
  TransportData transport{};
};

// Validates framing and copies fixed-size header fields. Payload stays a view.
[[nodiscard]] Result<DecodedMessage> decode(ByteSpan datagram) noexcept;

// Serialisers write into `out` and return the number of bytes WRITTEN, or 0 if
// `out` is too small. No allocation: callers own a stack/ring-buffer slot.
//
// For transport data the returned length covers the 16-byte header plus the
// payload; the 16-byte AEAD tag region is zeroed but not filled, because the
// crypto layer seals into it. The datagram length is therefore
// `encode(...) + kTransportTagSize` once sealing has happened.
[[nodiscard]] std::size_t encode(const HandshakeInitiation& msg, MutableByteSpan out) noexcept;
[[nodiscard]] std::size_t encode(const HandshakeResponse& msg, MutableByteSpan out) noexcept;
[[nodiscard]] std::size_t encode(const CookieReply& msg, MutableByteSpan out) noexcept;
[[nodiscard]] std::size_t encode(const TransportData& msg, ByteSpan payload,
                                 MutableByteSpan out) noexcept;

// --- MAC1 / MAC2 -------------------------------------------------------------
// mac1 = keyed-BLAKE2s-128( BLAKE2s-256("mac1----" || receiver_static_pub),
//                           message_without_mac1_and_mac2 )
// mac2 = keyed-BLAKE2s-128( cookie, message_without_mac2 )
// Both operate on the bytes preceding the MAC they compute, exactly as the
// reference implementation does.
[[nodiscard]] Bytes<32> mac1_key(const Bytes<kKeySize>& receiver_static_public) noexcept;
[[nodiscard]] Bytes<16> compute_mac1(ByteSpan message_before_mac1,
                                     const Bytes<32>& receiver_static_public) noexcept;
[[nodiscard]] Bytes<16> compute_mac2(ByteSpan message_before_mac2,
                                     const Bytes<16>& cookie) noexcept;

// Cookie value bound to a source address, as used in CookieReply:
// keyed-BLAKE2s-128(secret, source_ip_bytes || source_port_be).
[[nodiscard]] Bytes<16> compute_cookie(const Bytes<32>& secret, ByteSpan source_ip,
                                       std::uint16_t source_port) noexcept;

}  // namespace vpn::wire
