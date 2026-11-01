// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Wire-format gates: exact sizes, strict validation, no trailing bytes, and
// MAC/cookie derivation. Any change here is a protocol change (docs/PROTOCOL.md).
#include <cstddef>
#include <string>
#include <string_view>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/common/endian.hpp"
#include "vpn/wire/constants.hpp"
#include "vpn/wire/message.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::as_span;
using namespace vpn::wire;

template <std::size_t N>
void fill_pattern(Bytes<N>& out, Byte seed) {
  for (std::size_t i = 0; i < N; ++i) {
    out[i] = static_cast<Byte>((seed + i * 13U) & 0xFFU);
  }
}

}  // namespace

TEST(wire, sizes_match_the_specification) {
  CHECK_EQ(kHandshakeInitiationSize, std::size_t{148});
  CHECK_EQ(kHandshakeResponseSize, std::size_t{92});
  CHECK_EQ(kCookieReplySize, std::size_t{64});
  CHECK_EQ(kTransportHeaderSize, std::size_t{16});
  CHECK_EQ(kTransportOverhead, std::size_t{32});
  CHECK_EQ(kEmptyKeepaliveSize, std::size_t{32});
  CHECK_EQ(kMacSize, std::size_t{16});
  CHECK_EQ(kCounterWindowSize, std::size_t{8128});
  CHECK_EQ(kCounterBitsTotal, std::size_t{8192});
}

TEST(wire, initiation_round_trip) {
  HandshakeInitiation original;
  original.sender_index = 0xDEADBEEFU;
  fill_pattern(original.ephemeral, 1);
  fill_pattern(original.encrypted_static, 2);
  fill_pattern(original.encrypted_timestamp, 3);
  fill_pattern(original.mac1, 4);
  fill_pattern(original.mac2, 5);

  Bytes<kHandshakeInitiationSize> buffer{};
  CHECK_EQ(encode(original, as_span(buffer)), kHandshakeInitiationSize);

  auto decoded = decode(ByteSpan{buffer.data(), buffer.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK(decoded->type == MessageType::kHandshakeInitiation);
  CHECK_EQ(decoded->initiation.sender_index, original.sender_index);
  CHECK(vpn::equals(as_span(decoded->initiation.ephemeral), as_span(original.ephemeral)));
  CHECK(vpn::equals(as_span(decoded->initiation.encrypted_static),
                    as_span(original.encrypted_static)));
  CHECK(vpn::equals(as_span(decoded->initiation.encrypted_timestamp),
                    as_span(original.encrypted_timestamp)));
  CHECK(vpn::equals(as_span(decoded->initiation.mac1), as_span(original.mac1)));
  CHECK(vpn::equals(as_span(decoded->initiation.mac2), as_span(original.mac2)));
}

TEST(wire, response_round_trip) {
  HandshakeResponse original;
  original.sender_index = 7;
  original.receiver_index = 0xAABBCCDDU;
  fill_pattern(original.ephemeral, 9);
  fill_pattern(original.encrypted_nothing, 10);
  fill_pattern(original.mac1, 11);
  fill_pattern(original.mac2, 12);

  Bytes<kHandshakeResponseSize> buffer{};
  CHECK_EQ(encode(original, as_span(buffer)), kHandshakeResponseSize);

  auto decoded = decode(ByteSpan{buffer.data(), buffer.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK(decoded->type == MessageType::kHandshakeResponse);
  CHECK_EQ(decoded->response.sender_index, original.sender_index);
  CHECK_EQ(decoded->response.receiver_index, original.receiver_index);
  CHECK(vpn::equals(as_span(decoded->response.mac2), as_span(original.mac2)));
}

TEST(wire, keepalive_and_transport_payload) {
  // A keepalive is exactly 32 bytes with no payload.
  Bytes<kEmptyKeepaliveSize> keepalive{};
  vpn::store_le32(keepalive.data(), 4);
  vpn::store_le32(keepalive.data() + 4, 99);
  vpn::store_le64(keepalive.data() + 8, 5);

  auto decoded = decode(ByteSpan{keepalive.data(), keepalive.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK(decoded->type == MessageType::kTransportData);
  CHECK_EQ(decoded->transport.receiver_index, 99U);
  CHECK_EQ(decoded->transport.counter, 5U);
  CHECK(decoded->transport.payload.empty());

  // 16 bytes of payload -> 48-byte datagram; the payload view aliases the input.
  Bytes<kTransportHeaderSize + 16 + kTransportTagSize> buffer{};
  vpn::store_le32(buffer.data(), 4);
  vpn::store_le32(buffer.data() + 4, 1234);
  vpn::store_le64(buffer.data() + 8, 77);
  for (std::size_t i = 0; i < 16; ++i) buffer[kTransportHeaderSize + i] = static_cast<Byte>(i);

  auto with_payload = decode(ByteSpan{buffer.data(), buffer.size()});
  CHECK(with_payload.has_value());
  if (!with_payload) return;
  CHECK_EQ(with_payload->transport.payload.size(), std::size_t{16});
  CHECK_EQ(with_payload->transport.payload[0], 0);
  CHECK_EQ(with_payload->transport.payload[15], 15);
}

TEST(wire, rejects_malformed_datagrams) {
  Bytes<kHandshakeInitiationSize> initiation{};
  vpn::store_le32(initiation.data(), 1);
  initiation[8] = 1;  // non-zero ephemeral so only the length rule is exercised

  CHECK(!decode(ByteSpan{initiation.data(), 3}));
  CHECK(!decode(ByteSpan{initiation.data(), kHandshakeInitiationSize - 1}));

  Bytes<kHandshakeInitiationSize + 1> extended{};
  for (std::size_t i = 0; i < initiation.size(); ++i) extended[i] = initiation[i];
  CHECK(!decode(ByteSpan{extended.data(), extended.size()}));

  Bytes<4> unknown{};
  vpn::store_le32(unknown.data(), 9);
  CHECK(!decode(ByteSpan{unknown.data(), unknown.size()}));

  // Transport payload must be a multiple of 16.
  Bytes<33> odd{};
  vpn::store_le32(odd.data(), 4);
  CHECK(!decode(ByteSpan{odd.data(), odd.size()}));

  // Counter at the protocol ceiling is refused before any crypto happens.
  Bytes<kEmptyKeepaliveSize> exhausted{};
  vpn::store_le32(exhausted.data(), 4);
  vpn::store_le64(exhausted.data() + 8, kRejectAfterMessages);
  CHECK(!decode(ByteSpan{exhausted.data(), exhausted.size()}));
}

TEST(wire, encode_refuses_short_buffers) {
  HandshakeInitiation initiation{};
  initiation.ephemeral[0] = 1;
  Bytes<10> tiny{};
  CHECK_EQ(encode(initiation, as_span(tiny)), std::size_t{0});

  HandshakeResponse response{};
  response.ephemeral[0] = 1;
  CHECK_EQ(encode(response, as_span(tiny)), std::size_t{0});

  CookieReply cookie{};
  CHECK_EQ(encode(cookie, as_span(tiny)), std::size_t{0});

  TransportData transport{};
  const Byte payload[16] = {};
  CHECK_EQ(encode(transport, ByteSpan{payload, sizeof(payload)}, as_span(tiny)), std::size_t{0});
}

TEST(wire, mac1_is_deterministic_and_bound_to_the_server_key) {
  Bytes<kKeySize> server_key_a{};
  Bytes<kKeySize> server_key_b{};
  for (std::size_t i = 0; i < kKeySize; ++i) {
    server_key_a[i] = static_cast<Byte>(i);
    server_key_b[i] = static_cast<Byte>(i + 1);
  }

  Bytes<116> prefix{};  // initiation minus mac1 and mac2
  prefix[0] = 1;

  const auto mac_a1 = compute_mac1(ByteSpan{prefix.data(), prefix.size()}, server_key_a);
  const auto mac_a2 = compute_mac1(ByteSpan{prefix.data(), prefix.size()}, server_key_a);
  const auto mac_b = compute_mac1(ByteSpan{prefix.data(), prefix.size()}, server_key_b);

  CHECK(vpn::equals(as_span(mac_a1), as_span(mac_a2)));
  CHECK(!vpn::equals(as_span(mac_a1), as_span(mac_b)));
  CHECK(!vpn::is_zero(as_span(mac_a1)));

  // The mac1 key must not equal the raw server key (label is mixed in).
  const auto key = mac1_key(server_key_a);
  CHECK(!vpn::equals(as_span(key), as_span(server_key_a)));
}

TEST(wire, mac2_is_bound_to_the_cookie) {
  Bytes<128> prefix{};
  prefix[7] = 3;
  Bytes<16> cookie_a{};
  Bytes<16> cookie_b{};
  cookie_a[0] = 1;
  cookie_b[0] = 2;

  const auto mac_a = compute_mac2(ByteSpan{prefix.data(), prefix.size()}, cookie_a);
  const auto mac_b = compute_mac2(ByteSpan{prefix.data(), prefix.size()}, cookie_b);
  CHECK(!vpn::equals(as_span(mac_a), as_span(mac_b)));
  CHECK(!vpn::is_zero(as_span(mac_a)));
}

TEST(wire, cookie_is_bound_to_address_and_port) {
  Bytes<32> secret{};
  secret[0] = 9;
  const Byte ip[4] = {203, 0, 113, 7};

  const auto a = compute_cookie(secret, ByteSpan{ip, sizeof(ip)}, 51820);
  const auto b = compute_cookie(secret, ByteSpan{ip, sizeof(ip)}, 51820);
  const auto other_port = compute_cookie(secret, ByteSpan{ip, sizeof(ip)}, 51821);
  CHECK(vpn::equals(as_span(a), as_span(b)));
  CHECK(!vpn::equals(as_span(a), as_span(other_port)));

  const Byte other_ip[4] = {203, 0, 113, 8};
  const auto other = compute_cookie(secret, ByteSpan{other_ip, sizeof(other_ip)}, 51820);
  CHECK(!vpn::equals(as_span(a), as_span(other)));
}

TEST(wire, cookie_reply_round_trip) {
  CookieReply original;
  original.receiver_index = 42;
  fill_pattern(original.nonce, 20);
  fill_pattern(original.encrypted_cookie, 21);

  Bytes<kCookieReplySize> buffer{};
  CHECK_EQ(encode(original, as_span(buffer)), kCookieReplySize);

  auto decoded = decode(ByteSpan{buffer.data(), buffer.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK(decoded->type == MessageType::kCookieReply);
  CHECK_EQ(decoded->cookie.receiver_index, original.receiver_index);
  CHECK(vpn::equals(as_span(decoded->cookie.nonce), as_span(original.nonce)));
}

// ===========================================================================
// Added by the crypto verification pass, 2026-02.
//
// The round-trip tests above cannot catch a *symmetric* offset error: if encode
// and decode agree on a wrong offset the round-trip still passes. These tests
// pin every field to its absolute offset from the WireGuard protocol document,
// and pin mac1/mac2/cookie to known-answer values produced independently by
// Python's hashlib.blake2s:
//     python server/tests/golden/verify_macs.py
//
// Reference datagram (identical to the one the Python verifier builds):
//   sender_index = 0x11223344, ephemeral[i] = i,
//   encrypted_static[i] = 0x40 + i, encrypted_timestamp[i] = 0x80 + i,
//   receiver static public key  spub[i] = (i * 3 + 1) & 0xFF,
//   cookie[i] = i.
// ===========================================================================
namespace {

template <std::size_t N>
std::string hex_of(const Bytes<N>& value) {
  return vpn::to_hex(ByteSpan{value.data(), value.size()});
}

Bytes<kKeySize> reference_server_pubkey() {
  Bytes<kKeySize> spub{};
  for (std::size_t i = 0; i < spub.size(); ++i) {
    spub[i] = static_cast<Byte>((i * 3U + 1U) & 0xFFU);
  }
  return spub;
}

Bytes<kCookieSize> reference_cookie() {
  Bytes<kCookieSize> cookie{};
  for (std::size_t i = 0; i < cookie.size(); ++i) {
    cookie[i] = static_cast<Byte>(i);
  }
  return cookie;
}

HandshakeInitiation reference_initiation() {
  HandshakeInitiation m;
  m.sender_index = 0x11223344U;
  for (std::size_t i = 0; i < m.ephemeral.size(); ++i) {
    m.ephemeral[i] = static_cast<Byte>(i & 0xFFU);
  }
  for (std::size_t i = 0; i < m.encrypted_static.size(); ++i) {
    m.encrypted_static[i] = static_cast<Byte>((0x40U + i) & 0xFFU);
  }
  for (std::size_t i = 0; i < m.encrypted_timestamp.size(); ++i) {
    m.encrypted_timestamp[i] = static_cast<Byte>((0x80U + i) & 0xFFU);
  }
  return m;
}

HandshakeResponse reference_response() {
  HandshakeResponse m;
  m.sender_index = 0x55667788U;
  m.receiver_index = 0x11223344U;
  for (std::size_t i = 0; i < m.ephemeral.size(); ++i) {
    m.ephemeral[i] = static_cast<Byte>((0xA0U + i) & 0xFFU);
  }
  for (std::size_t i = 0; i < m.encrypted_nothing.size(); ++i) {
    m.encrypted_nothing[i] = static_cast<Byte>((0xC0U + i) & 0xFFU);
  }
  return m;
}

}  // namespace

TEST(wire, initiation_field_offsets_match_the_specification) {
  const HandshakeInitiation m = reference_initiation();
  Bytes<kHandshakeInitiationSize> out{};
  CHECK_EQ(encode(m, as_span(out)), kHandshakeInitiationSize);

  // type | sender | ephemeral@8 | static@40 | timestamp@88 | mac1@116 | mac2@132
  CHECK_EQ(vpn::load_le32(out.data() + 0), 1U);
  CHECK_EQ(vpn::load_le32(out.data() + 4), 0x11223344U);
  CHECK(vpn::equals(ByteSpan{out.data() + 8, kKeySize}, as_span(m.ephemeral)));
  CHECK(vpn::equals(ByteSpan{out.data() + 40, kEncryptedStaticSize},
                    as_span(m.encrypted_static)));
  CHECK(vpn::equals(ByteSpan{out.data() + 88, kEncryptedTimestampSize},
                    as_span(m.encrypted_timestamp)));
  CHECK(vpn::equals(ByteSpan{out.data() + 116, kMacSize}, as_span(m.mac1)));
  CHECK(vpn::equals(ByteSpan{out.data() + 132, kMacSize}, as_span(m.mac2)));

  // decode must use the same offsets: rewrite each field's first byte in the
  // encoded datagram and check it lands in the right decoded field.
  Bytes<kHandshakeInitiationSize> mutated = out;
  mutated[8] = 0x5A;    // ephemeral[0]
  mutated[40] = 0x5B;   // encrypted_static[0]
  mutated[88] = 0x5C;   // encrypted_timestamp[0]
  mutated[116] = 0x5D;  // mac1[0]
  mutated[132] = 0x5E;  // mac2[0]
  auto decoded = decode(ByteSpan{mutated.data(), mutated.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK_EQ(decoded->initiation.ephemeral[0], Byte{0x5A});
  CHECK_EQ(decoded->initiation.encrypted_static[0], Byte{0x5B});
  CHECK_EQ(decoded->initiation.encrypted_timestamp[0], Byte{0x5C});
  CHECK_EQ(decoded->initiation.mac1[0], Byte{0x5D});
  CHECK_EQ(decoded->initiation.mac2[0], Byte{0x5E});
}

TEST(wire, response_field_offsets_match_the_specification) {
  const HandshakeResponse m = reference_response();
  Bytes<kHandshakeResponseSize> out{};
  CHECK_EQ(encode(m, as_span(out)), kHandshakeResponseSize);

  // type | sender@4 | receiver@8 | ephemeral@12 | empty@44 | mac1@60 | mac2@76
  CHECK_EQ(vpn::load_le32(out.data() + 0), 2U);
  CHECK_EQ(vpn::load_le32(out.data() + 4), 0x55667788U);
  CHECK_EQ(vpn::load_le32(out.data() + 8), 0x11223344U);
  CHECK(vpn::equals(ByteSpan{out.data() + 12, kKeySize}, as_span(m.ephemeral)));
  CHECK(vpn::equals(ByteSpan{out.data() + 44, kEncryptedNothingSize},
                    as_span(m.encrypted_nothing)));
  CHECK(vpn::equals(ByteSpan{out.data() + 60, kMacSize}, as_span(m.mac1)));
  CHECK(vpn::equals(ByteSpan{out.data() + 76, kMacSize}, as_span(m.mac2)));
}

TEST(wire, cookie_and_transport_field_offsets_match_the_specification) {
  CookieReply cookie;
  cookie.receiver_index = 0xDEADBEEFU;
  fill_pattern(cookie.nonce, 1);
  fill_pattern(cookie.encrypted_cookie, 2);
  Bytes<kCookieReplySize> cbuf{};
  CHECK_EQ(encode(cookie, as_span(cbuf)), kCookieReplySize);
  CHECK_EQ(vpn::load_le32(cbuf.data() + 0), 3U);
  CHECK_EQ(vpn::load_le32(cbuf.data() + 4), 0xDEADBEEFU);
  CHECK(vpn::equals(ByteSpan{cbuf.data() + 8, kCookieNonceSize},
                    as_span(cookie.nonce)));
  CHECK(vpn::equals(ByteSpan{cbuf.data() + 32, kCookieSize + 16},
                    as_span(cookie.encrypted_cookie)));

  TransportData transport;
  transport.receiver_index = 0x0A0B0C0DU;
  transport.counter = 0x0102030405060708ULL;
  const Byte payload[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  Bytes<kTransportHeaderSize + 16 + kTransportTagSize> tbuf{};
  // encode() returns the bytes it WROTE (header + payload = 32). The 16-byte
  // AEAD tag region is zeroed, not filled; the datagram length is returned + 16.
  CHECK_EQ(encode(transport, ByteSpan{payload, sizeof(payload)}, as_span(tbuf)),
           kTransportHeaderSize + 16);
  CHECK_EQ(vpn::load_le32(tbuf.data() + 0), 4U);
  CHECK_EQ(vpn::load_le32(tbuf.data() + 4), 0x0A0B0C0DU);
  CHECK_EQ(vpn::load_le64(tbuf.data() + 8), 0x0102030405060708ULL);
  CHECK(vpn::equals(ByteSpan{tbuf.data() + kTransportHeaderSize, 16},
                    ByteSpan{payload, sizeof(payload)}));
  // Tag region must be zeroed, never left uninitialised.
  for (std::size_t i = kTransportHeaderSize + 16; i < tbuf.size(); ++i) {
    CHECK_EQ(tbuf[i], static_cast<Byte>(0));
  }
}



TEST(wire, mac1_key_matches_the_reference_vector) {
  const Bytes<kKeySize> spub = reference_server_pubkey();
  CHECK_EQ(hex_of(mac1_key(spub)),
           std::string{
               "d56854762b8d350ea53065eb303dfeeb13ff202430a79188062f5f1851ef12a3"});
}

TEST(wire, mac1_covers_exactly_the_bytes_before_it) {
  const HandshakeInitiation m = reference_initiation();
  Bytes<kHandshakeInitiationSize> datagram{};
  CHECK_EQ(encode(m, as_span(datagram)), kHandshakeInitiationSize);

  const Bytes<kKeySize> spub = reference_server_pubkey();
  const Bytes<16> mac1 = compute_mac1(ByteSpan{datagram.data(), 116}, spub);

  // Known-answer value from hashlib (independent of this implementation).
  CHECK_EQ(hex_of(mac1), std::string{"b688b76eb01d6bc0b8141e5cf0f011f4"});

  // Any other coverage produces a different MAC, so these also prove the test
  // pins the prefix rather than merely "some" prefix.
  CHECK(!vpn::equals(as_span(mac1),
                     as_span(compute_mac1(ByteSpan{datagram.data(), 132}, spub))));
  CHECK(!vpn::equals(as_span(mac1),
                     as_span(compute_mac1(ByteSpan{datagram.data(), 115}, spub))));
  CHECK(!vpn::equals(as_span(mac1),
                     as_span(compute_mac1(ByteSpan{datagram.data(), 148}, spub))));
  // mac1 is bound to the receiver's static public key.
  Bytes<kKeySize> other_spub = spub;
  other_spub[0] = static_cast<Byte>(other_spub[0] ^ 0xFFU);
  CHECK(!vpn::equals(
      as_span(mac1),
      as_span(compute_mac1(ByteSpan{datagram.data(), 116}, other_spub))));
}

TEST(wire, mac2_covers_exactly_the_bytes_before_it_including_mac1) {
  HandshakeInitiation m = reference_initiation();
  const Bytes<kKeySize> spub = reference_server_pubkey();
  const Bytes<kCookieSize> cookie = reference_cookie();

  Bytes<kHandshakeInitiationSize> datagram{};
  CHECK_EQ(encode(m, as_span(datagram)), kHandshakeInitiationSize);
  const Bytes<16> mac1 = compute_mac1(ByteSpan{datagram.data(), 116}, spub);
  m.mac1 = mac1;
  CHECK_EQ(encode(m, as_span(datagram)), kHandshakeInitiationSize);
  CHECK(vpn::equals(ByteSpan{datagram.data() + 116, 16}, as_span(mac1)));

  const Bytes<16> mac2 = compute_mac2(ByteSpan{datagram.data(), 132}, cookie);
  CHECK_EQ(hex_of(mac2), std::string{"502a0161f57d63d9111b59f67d9db569"});

  // mac2 MUST cover mac1 (bytes 116..132): excluding it would let an attacker
  // rewrite mac1 without invalidating mac2.
  CHECK(!vpn::equals(
      as_span(mac2),
      as_span(compute_mac2(ByteSpan{datagram.data(), 116}, cookie))));
  // mac2 must NOT cover itself.
  CHECK(!vpn::equals(
      as_span(mac2),
      as_span(compute_mac2(ByteSpan{datagram.data(), 148}, cookie))));

  // Changing mac1 must change mac2's input.
  HandshakeInitiation tampered = reference_initiation();
  Bytes<16> different_mac1 = mac1;
  different_mac1[0] = static_cast<Byte>(different_mac1[0] ^ 0x01U);
  tampered.mac1 = different_mac1;
  Bytes<kHandshakeInitiationSize> tampered_datagram{};
  CHECK_EQ(encode(tampered, as_span(tampered_datagram)),
           kHandshakeInitiationSize);
  CHECK(!vpn::equals(
      as_span(mac2),
      as_span(compute_mac2(ByteSpan{tampered_datagram.data(), 132}, cookie))));
}

TEST(wire, response_macs_cover_the_right_prefixes) {
  HandshakeResponse m = reference_response();
  const Bytes<kKeySize> spub = reference_server_pubkey();
  const Bytes<kCookieSize> cookie = reference_cookie();

  Bytes<kHandshakeResponseSize> datagram{};
  CHECK_EQ(encode(m, as_span(datagram)), kHandshakeResponseSize);
  const Bytes<16> mac1 = compute_mac1(ByteSpan{datagram.data(), 60}, spub);
  CHECK_EQ(hex_of(mac1), std::string{"4b6c1bedf2f109126c4501d8e710209a"});
  m.mac1 = mac1;
  CHECK_EQ(encode(m, as_span(datagram)), kHandshakeResponseSize);
  const Bytes<16> mac2 = compute_mac2(ByteSpan{datagram.data(), 76}, cookie);
  CHECK_EQ(hex_of(mac2), std::string{"323b95efdd52ee60df1ecf3f39ff3878"});

  CHECK(!vpn::equals(as_span(mac1),
                     as_span(compute_mac1(ByteSpan{datagram.data(), 76}, spub))));
  CHECK(!vpn::equals(
      as_span(mac2),
      as_span(compute_mac2(ByteSpan{datagram.data(), 60}, cookie))));
}

TEST(wire, cookie_matches_reference_vectors) {
  Bytes<32> secret{};
  for (std::size_t i = 0; i < secret.size(); ++i) {
    secret[i] = static_cast<Byte>((i * 11U + 6U) & 0xFFU);
  }

  // IPv6 (16-byte address): the reference derivation is
  // blake2s-128(key=secret, ip16 || port_be), and this implementation matches it.
  const Byte ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                        0,    0,    0,    0,    0, 0, 0, 1};
  CHECK_EQ(hex_of(compute_cookie(secret, ByteSpan{ip6, sizeof(ip6)}, 51820)),
           std::string{"331f0c3143ec814cafaa060030cc3d21"});
  // ...and the port is part of the input.
  CHECK(!vpn::equals(
      as_span(compute_cookie(secret, ByteSpan{ip6, sizeof(ip6)}, 51820)),
      as_span(compute_cookie(secret, ByteSpan{ip6, sizeof(ip6)}, 51821))));

  // Address family is disambiguated by the span length alone: an IPv4 address
  // zero-padded to 16 bytes is a different cookie than the 4-byte form. This
  // records the caller contract that compute_cookie() has no family argument.
  const Byte ip4[4] = {203, 0, 113, 7};
  const Byte padded[16] = {203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK(!vpn::equals(
      as_span(compute_cookie(secret, ByteSpan{ip4, sizeof(ip4)}, 51820)),
      as_span(compute_cookie(secret, ByteSpan{padded, sizeof(padded)}, 51820))));
}

// ---------------------------------------------------------------------------
// FINDING W-1 (compute_cookie wrote the port at buf[16] but hashed only
// ip_len + 2 bytes, so an IPv4 cookie ignored the source port) is FIXED in
// src/wire/message.cpp. The always-on assertions below pin the behaviour with
// digests computed by hashlib (never by this implementation), so a regression
// fails the default gate instead of hiding behind a define.
// Expected values: hashlib.blake2s(key=secret, digest_size=16) over the 6-byte
// string ip4 || port_be - see server/tests/golden/verify_macs.py.
// ===========================================================================

// ===========================================================================
// Added by the 2026-02 verification pass, round 2: the IPv4 cookie path and
// the wire labels, which had no always-on assertion.
//
// FINDING W-1 (compute_cookie() wrote the port at buf[16] but hashed only
// ip_len + 2 bytes, so every IPv4 peer's cookie ignored its source port) is
// fixed in src/wire/message.cpp:173 - the port now sits immediately after the
// address bytes. The `known_bug_ipv4_cookie_...` block above only reproduces
// the old defect and is compiled out; these assertions are always on, so a
// regression fails the default gate instead of hiding behind a define.
//
// Expected values are from hashlib.blake2s(key=secret, digest_size=16) over
// the 6-byte string ip4 || port_be - see server/tests/golden/verify_macs.py
// (cases cookie/v4/port*), i.e. never from this implementation.
// ===========================================================================
TEST(wire, cookie_for_ipv4_binds_the_source_port) {
  Bytes<32> secret{};
  for (std::size_t i = 0; i < secret.size(); ++i) {
    secret[i] = static_cast<Byte>((i * 11U + 6U) & 0xFFU);
  }
  const Byte ip4[4] = {203, 0, 113, 7};

  // hashlib: keyed-BLAKE2s-128(key=secret, 203.0.113.7 || 0xCA 0x9C).
  CHECK_EQ(hex_of(compute_cookie(secret, ByteSpan{ip4, sizeof(ip4)}, 51820)),
           std::string{"cc89a9a4bd8caf06adfb546a8a2d8c29"});
  // hashlib: keyed-BLAKE2s-128(key=secret, 203.0.113.7 || 0x00 0x01).
  CHECK_EQ(hex_of(compute_cookie(secret, ByteSpan{ip4, sizeof(ip4)}, 1)),
           std::string{"cac84086cd45a25f7dbcaefce3322378"});
  // ...and the two ports really do give different cookies (the W-1 defect).
  CHECK(!vpn::equals(
      as_span(compute_cookie(secret, ByteSpan{ip4, sizeof(ip4)}, 51820)),
      as_span(compute_cookie(secret, ByteSpan{ip4, sizeof(ip4)}, 51821))));
}

TEST(wire, wire_labels_are_the_specification_bytes) {
  // A typo in either label silently breaks interop: mac1/mac2 never verify and
  // the cookie encryption key differs. Both are 8 significant bytes + NUL.
  CHECK_EQ(sizeof(kMac1Label), std::size_t{9});
  CHECK_EQ(sizeof(kCookieLabel), std::size_t{9});
  CHECK_EQ(std::string_view{kMac1Label}, std::string_view{"mac1----"});
  CHECK_EQ(std::string_view{kCookieLabel}, std::string_view{"cookie--"});
}

