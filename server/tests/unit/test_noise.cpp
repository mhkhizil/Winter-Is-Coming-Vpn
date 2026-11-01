// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// The handshake and transport session: a full in-process handshake between an
// initiator and a responder, key agreement, rejection of tampered messages, and
// the transport data path including replay protection.
#include <cstddef>
#include <cstdio>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/x25519.hpp"
#include "vpn/wire/noise.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;
using vpn::wire::MessageType;
using vpn::wire::NoiseIk;
using vpn::wire::TunnelKeys;

struct Pair {
  vpn::crypto::X25519KeyPair a{};
  vpn::crypto::X25519KeyPair b{};
  Bytes<148> msg1{};
  Bytes<92> msg2{};
};

// Runs a complete handshake and returns both sides' keys.
bool complete_handshake(Pair& p, TunnelKeys& a_keys, TunnelKeys& b_keys) {
  if (!vpn::crypto::x25519_generate(p.a) || !vpn::crypto::x25519_generate(p.b)) return false;

  auto initiator = NoiseIk::initiator(p.a, p.b.public_key);
  auto responder = NoiseIk::responder(p.b);
  if (!initiator || !responder) return false;

  vpn::Status st = initiator->create_initiation(vpn::as_span(p.msg1));
  if (!st) { std::fprintf(stderr, "  step create_initiation: %s\n", st.to_string().c_str()); return false; }
  vpn::crypto::X25519PublicKey learned{};
  st = responder->consume_initiation(ByteSpan{p.msg1.data(), p.msg1.size()}, learned);
  if (!st) { std::fprintf(stderr, "  step consume_initiation: %s\n", st.to_string().c_str()); return false; }
  if (!vpn::equals(vpn::as_span(learned), vpn::as_span(p.a.public_key))) return false;

  st = responder->create_response(vpn::as_span(p.msg2));
  if (!st) { std::fprintf(stderr, "  step create_response: %s\n", st.to_string().c_str()); return false; }
  st = initiator->consume_response(ByteSpan{p.msg2.data(), p.msg2.size()});
  if (!st) { std::fprintf(stderr, "  step consume_response: %s\n", st.to_string().c_str()); return false; }

  a_keys = initiator->keys();
  b_keys = responder->keys();
  return initiator->has_keys() && responder->has_keys();
}

}  // namespace

TEST(noise, handshake_completes_and_agrees_on_keys) {
  Pair p;
  TunnelKeys a{};
  TunnelKeys b{};
  CHECK(complete_handshake(p, a, b));
  CHECK(vpn::equals(vpn::as_span(a.send_key), vpn::as_span(b.recv_key)));
  CHECK(vpn::equals(vpn::as_span(a.recv_key), vpn::as_span(b.send_key)));
  CHECK(!vpn::equals(vpn::as_span(a.send_key), vpn::as_span(a.recv_key)));
  CHECK_EQ(a.local_index, b.remote_index);
  CHECK_EQ(b.local_index, a.remote_index);
  CHECK(!vpn::is_zero(vpn::as_span(a.send_key)));
}

TEST(noise, initiation_has_the_right_shape) {
  Pair p;
  TunnelKeys a{};
  TunnelKeys b{};
  CHECK(complete_handshake(p, a, b));
  auto decoded = vpn::wire::decode(ByteSpan{p.msg1.data(), p.msg1.size()});
  CHECK(decoded.has_value());
  if (!decoded) return;
  CHECK(decoded->type == MessageType::kHandshakeInitiation);
  CHECK_EQ(decoded->initiation.sender_index, a.local_index);
  CHECK(!vpn::is_zero(vpn::as_span(decoded->initiation.mac1)));
  CHECK(vpn::is_zero(vpn::as_span(decoded->initiation.mac2)));
}

TEST(noise, tampered_initiation_is_rejected) {
  for (const std::size_t offset : {std::size_t{8}, std::size_t{40}, std::size_t{100}}) {
    Pair fresh;
    if (!vpn::crypto::x25519_generate(fresh.a) || !vpn::crypto::x25519_generate(fresh.b)) return;
    auto initiator = NoiseIk::initiator(fresh.a, fresh.b.public_key);
    auto responder = NoiseIk::responder(fresh.b);
    CHECK(initiator.has_value());
    CHECK(responder.has_value());
    if (!initiator || !responder) return;
    CHECK(initiator->create_initiation(vpn::as_span(fresh.msg1)));
    fresh.msg1[offset] ^= 0x01U;
    vpn::crypto::X25519PublicKey learned{};
    CHECK(!responder->consume_initiation(ByteSpan{fresh.msg1.data(), fresh.msg1.size()}, learned));
  }
}

TEST(noise, wrong_responder_key_is_rejected) {
  Pair p;
  vpn::crypto::X25519KeyPair mallory{};
  if (!vpn::crypto::x25519_generate(p.a) || !vpn::crypto::x25519_generate(p.b) ||
      !vpn::crypto::x25519_generate(mallory)) {
    return;
  }
  auto initiator = NoiseIk::initiator(p.a, p.b.public_key);
  auto impostor = NoiseIk::responder(mallory);
  CHECK(initiator.has_value());
  CHECK(impostor.has_value());
  if (!initiator || !impostor) return;
  CHECK(initiator->create_initiation(vpn::as_span(p.msg1)));
  vpn::crypto::X25519PublicKey learned{};
  // mac1 was computed for the real responder, so the impostor must reject it.
  CHECK(!impostor->consume_initiation(ByteSpan{p.msg1.data(), p.msg1.size()}, learned));
}

TEST(noise, out_of_order_calls_are_refused) {
  vpn::crypto::X25519KeyPair keys{};
  if (!vpn::crypto::x25519_generate(keys)) return;
  auto initiator = NoiseIk::initiator(keys, keys.public_key);
  CHECK(initiator.has_value());
  if (!initiator) return;
  Bytes<92> response{};
  CHECK(!initiator->consume_response(ByteSpan{response.data(), response.size()}));
  CHECK(!initiator->has_keys());

  auto responder = NoiseIk::responder(keys);
  CHECK(responder.has_value());
  if (!responder) return;
  Bytes<148> initiation{};
  CHECK(!responder->create_response(vpn::as_span(response)));
  CHECK(!responder->create_initiation(vpn::as_span(initiation)));
}

TEST(noise, transport_round_trip_and_replay_protection) {
  Pair p;
  TunnelKeys a_keys{};
  TunnelKeys b_keys{};
  CHECK(complete_handshake(p, a_keys, b_keys));

  vpn::wire::TransportSession from_a;
  vpn::wire::TransportSession to_b;
  CHECK(from_a.init(a_keys).ok());
  CHECK(to_b.init(b_keys).ok());

  for (std::size_t i = 0; i < 100; ++i) {
    Byte inner[64] = {};
    for (std::size_t j = 0; j < sizeof(inner); ++j) {
      inner[j] = static_cast<Byte>((i + j) & 0xFFU);
    }
    Byte datagram[128] = {};
    const std::size_t size = from_a.seal(MutableByteSpan{datagram, sizeof(datagram)},
                                         ByteSpan{inner, sizeof(inner)});
    CHECK_EQ(size, sizeof(inner) + vpn::wire::kTransportOverhead);
    auto opened = to_b.open(MutableByteSpan{datagram, size});
    CHECK(opened.has_value());
    if (!opened) return;
    CHECK_EQ(opened->size(), sizeof(inner));
    CHECK(vpn::equals(*opened, ByteSpan{inner, sizeof(inner)}));
  }

  // Replay the same datagram: the AEAD succeeds but the counter is stale, so the
  // replay window must reject it.
  Byte inner[16] = {};
  Byte datagram[64] = {};
  const std::size_t size =
      from_a.seal(MutableByteSpan{datagram, sizeof(datagram)}, ByteSpan{inner, sizeof(inner)});
  CHECK(size > 0);
  CHECK(to_b.open(MutableByteSpan{datagram, size}).has_value());
  CHECK(!to_b.open(MutableByteSpan{datagram, size}).has_value());
}

TEST(noise, transport_rejects_tampered_and_foreign_packets) {
  Pair p;
  TunnelKeys a_keys{};
  TunnelKeys b_keys{};
  CHECK(complete_handshake(p, a_keys, b_keys));

  vpn::wire::TransportSession from_a;
  vpn::wire::TransportSession to_b;
  CHECK(from_a.init(a_keys).ok());
  CHECK(to_b.init(b_keys).ok());

  Byte inner[32] = {};
  for (std::size_t i = 0; i < sizeof(inner); ++i) inner[i] = static_cast<Byte>(i);
  Byte datagram[96] = {};
  const std::size_t size =
      from_a.seal(MutableByteSpan{datagram, sizeof(datagram)}, ByteSpan{inner, sizeof(inner)});
  CHECK(size > 0);

  Byte copy[96] = {};
  for (std::size_t i = 0; i < size; ++i) copy[i] = datagram[i];
  copy[20] ^= 0x01U;  // ciphertext bit flip
  CHECK(!to_b.open(MutableByteSpan{copy, size}).has_value());

  Byte copy2[96] = {};
  for (std::size_t i = 0; i < size; ++i) copy2[i] = datagram[i];
  copy2[4] ^= 0xFFU;  // receiver index
  CHECK(!to_b.open(MutableByteSpan{copy2, size}).has_value());

  CHECK(!to_b.open(MutableByteSpan{datagram, 20}).has_value());
}

TEST(noise, keepalive_is_an_empty_payload) {
  Pair p;
  TunnelKeys a_keys{};
  TunnelKeys b_keys{};
  CHECK(complete_handshake(p, a_keys, b_keys));

  vpn::wire::TransportSession from_a;
  vpn::wire::TransportSession to_b;
  CHECK(from_a.init(a_keys).ok());
  CHECK(to_b.init(b_keys).ok());

  Byte datagram[64] = {};
  const std::size_t size = from_a.seal(MutableByteSpan{datagram, sizeof(datagram)}, ByteSpan{});
  CHECK_EQ(size, vpn::wire::kEmptyKeepaliveSize);
  auto opened = to_b.open(MutableByteSpan{datagram, size});
  CHECK(opened.has_value());
  if (!opened) return;
  CHECK(opened->empty());
}

TEST(noise, a_new_handshake_changes_the_keys) {
  Pair p1;
  TunnelKeys a1{};
  TunnelKeys b1{};
  CHECK(complete_handshake(p1, a1, b1));

  Pair p2;
  TunnelKeys a2{};
  TunnelKeys b2{};
  CHECK(complete_handshake(p2, a2, b2));

  // Different ephemerals and keys must yield different transport keys.
  CHECK(!vpn::equals(vpn::as_span(a1.send_key), vpn::as_span(a2.send_key)));
}

