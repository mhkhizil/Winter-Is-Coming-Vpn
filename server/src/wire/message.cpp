// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/wire/message.hpp"

#include "vpn/common/endian.hpp"
#include "vpn/crypto/blake2s.hpp"

namespace vpn::wire {
namespace {

[[nodiscard]] Status malformed(const char* what) {
  return Status{ErrorCode::kMalformed, what};
}

void put(MutableByteSpan out, std::size_t offset, ByteSpan src) noexcept {
  for (std::size_t i = 0; i < src.size(); ++i) out[offset + i] = src[i];
}

void get(ByteSpan in, std::size_t offset, MutableByteSpan dst) noexcept {
  for (std::size_t i = 0; i < dst.size(); ++i) dst[i] = in[offset + i];
}

}  // namespace

Result<DecodedMessage> decode(ByteSpan datagram) noexcept {
  if (datagram.size() < kTypePrefixSize) {
    return malformed("datagram shorter than the 4-byte type prefix");
  }

  const std::uint32_t raw_type = load_le32(datagram.data());
  if (!is_known_type(raw_type)) {
    return malformed("unknown message type");
  }

  DecodedMessage msg;
  msg.type = static_cast<MessageType>(raw_type);
  const Byte* p = datagram.data();
  const std::size_t size = datagram.size();

  switch (msg.type) {
    case MessageType::kHandshakeInitiation: {
      if (size != kHandshakeInitiationSize) {
        return malformed("handshake initiation must be exactly 148 bytes");
      }
      msg.initiation.sender_index = load_le32(p + 4);
      get(datagram, 8, as_span(msg.initiation.ephemeral));
      get(datagram, 40, as_span(msg.initiation.encrypted_static));
      get(datagram, 88, as_span(msg.initiation.encrypted_timestamp));
      get(datagram, 116, as_span(msg.initiation.mac1));
      get(datagram, 132, as_span(msg.initiation.mac2));
      // All-zero X25519 point = low order point; reject before the expensive DH
      // so a garbage flood cannot buy CPU time on the crypto pool.
      if (is_zero(as_span(msg.initiation.ephemeral))) {
        return malformed("handshake initiation has an all-zero ephemeral key");
      }
      return msg;
    }
    case MessageType::kHandshakeResponse: {
      if (size != kHandshakeResponseSize) {
        return malformed("handshake response must be exactly 92 bytes");
      }
      msg.response.sender_index = load_le32(p + 4);
      msg.response.receiver_index = load_le32(p + 8);
      get(datagram, 12, as_span(msg.response.ephemeral));
      get(datagram, 44, as_span(msg.response.encrypted_nothing));
      get(datagram, 60, as_span(msg.response.mac1));
      get(datagram, 76, as_span(msg.response.mac2));
      if (is_zero(as_span(msg.response.ephemeral))) {
        return malformed("handshake response has an all-zero ephemeral key");
      }
      return msg;
    }
    case MessageType::kCookieReply: {
      if (size != kCookieReplySize) {
        return malformed("cookie reply must be exactly 64 bytes");
      }
      msg.cookie.receiver_index = load_le32(p + 4);
      get(datagram, 8, as_span(msg.cookie.nonce));
      get(datagram, 32, as_span(msg.cookie.encrypted_cookie));
      return msg;
    }
    case MessageType::kTransportData: {
      if (size < kEmptyKeepaliveSize) {
        return malformed("transport data must be at least 32 bytes");
      }
      const std::size_t payload_size = size - kTransportOverhead;
      if (payload_size % 16 != 0) {
        return malformed("transport payload must be a multiple of 16 bytes");
      }
      msg.transport.receiver_index = load_le32(p + 4);
      msg.transport.counter = load_le64(p + 8);
      msg.transport.payload = datagram.subspan(kTransportHeaderSize, payload_size);
      if (msg.transport.counter >= kRejectAfterMessages) {
        return malformed("transport counter exhausted");
      }
      return msg;
    }
  }
  return malformed("unreachable message type");
}

std::size_t encode(const HandshakeInitiation& msg, MutableByteSpan out) noexcept {
  if (out.size() < kHandshakeInitiationSize) return 0;
  store_le32(out.data(), static_cast<std::uint32_t>(MessageType::kHandshakeInitiation));
  store_le32(out.data() + 4, msg.sender_index);
  put(out, 8, as_span(msg.ephemeral));
  put(out, 40, as_span(msg.encrypted_static));
  put(out, 88, as_span(msg.encrypted_timestamp));
  put(out, 116, as_span(msg.mac1));
  put(out, 132, as_span(msg.mac2));
  return kHandshakeInitiationSize;
}

std::size_t encode(const HandshakeResponse& msg, MutableByteSpan out) noexcept {
  if (out.size() < kHandshakeResponseSize) return 0;
  store_le32(out.data(), static_cast<std::uint32_t>(MessageType::kHandshakeResponse));
  store_le32(out.data() + 4, msg.sender_index);
  store_le32(out.data() + 8, msg.receiver_index);
  put(out, 12, as_span(msg.ephemeral));
  put(out, 44, as_span(msg.encrypted_nothing));
  put(out, 60, as_span(msg.mac1));
  put(out, 76, as_span(msg.mac2));
  return kHandshakeResponseSize;
}

std::size_t encode(const CookieReply& msg, MutableByteSpan out) noexcept {
  if (out.size() < kCookieReplySize) return 0;
  store_le32(out.data(), static_cast<std::uint32_t>(MessageType::kCookieReply));
  store_le32(out.data() + 4, msg.receiver_index);
  put(out, 8, as_span(msg.nonce));
  put(out, 32, as_span(msg.encrypted_cookie));
  return kCookieReplySize;
}

std::size_t encode(const TransportData& msg, ByteSpan payload, MutableByteSpan out) noexcept {
  if (payload.size() > kMaxInnerPacketSize) return 0;
  const std::size_t body = kTransportHeaderSize + payload.size();
  const std::size_t total = body + kTransportTagSize;
  if (out.size() < total) return 0;
  store_le32(out.data(), static_cast<std::uint32_t>(MessageType::kTransportData));
  store_le32(out.data() + 4, msg.receiver_index);
  store_le64(out.data() + 8, msg.counter);
  for (std::size_t i = 0; i < payload.size(); ++i) out[kTransportHeaderSize + i] = payload[i];
  // The 16-byte AEAD tag sits at [body, total). We zero it so the caller can
  // never ship uninitialised memory, and return only the bytes written: the
  // datagram length is `returned + kTransportTagSize` once the crypto layer has
  // sealed in place.
  for (std::size_t i = body; i < total; ++i) out[i] = 0;
  return body;
}

Bytes<32> mac1_key(const Bytes<kKeySize>& receiver_static_public) noexcept {
  constexpr std::size_t label_len = sizeof(kMac1Label) - 1;  // drop the NUL
  Byte buf[label_len + kKeySize] = {};
  for (std::size_t i = 0; i < label_len; ++i) buf[i] = static_cast<Byte>(kMac1Label[i]);
  for (std::size_t i = 0; i < kKeySize; ++i) buf[label_len + i] = receiver_static_public[i];
  return crypto::blake2s_256(ByteSpan{buf, sizeof(buf)});
}

Bytes<16> compute_mac1(ByteSpan message_before_mac1,
                       const Bytes<32>& receiver_static_public) noexcept {
  const Bytes<32> key = mac1_key(receiver_static_public);
  return crypto::blake2s_128(message_before_mac1, as_span(key));
}

Bytes<16> compute_mac2(ByteSpan message_before_mac2, const Bytes<16>& cookie) noexcept {
  return crypto::blake2s_128(message_before_mac2, as_span(cookie));
}

Bytes<16> compute_cookie(const Bytes<32>& secret, ByteSpan source_ip,
                         std::uint16_t source_port) noexcept {
  Byte buf[18] = {};
  const std::size_t ip_len = source_ip.size() < 16 ? source_ip.size() : 16;
  for (std::size_t i = 0; i < ip_len; ++i) buf[i] = source_ip[i];
  // The hashed input is exactly `ip || port_be` - the port must sit immediately
  // after the address bytes. Writing it at a fixed offset 16 would put it
  // outside the hashed span for any address shorter than 16 bytes (i.e. every
  // IPv4 peer), silently dropping the port from the derivation. (BUG W-1)
  store_be16(buf + ip_len, source_port);
  return crypto::blake2s_128(ByteSpan{buf, ip_len + 2}, as_span(secret));
}

}  // namespace vpn::wire
