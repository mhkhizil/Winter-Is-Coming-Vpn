// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// ChaCha20-Poly1305 gates: the RFC 8439 section 2.8.2 vector (AEAD with AAD),
// round-trips, and tamper resistance on both ciphertext and tag.
#include <cstddef>
#include <string>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/aead.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;

ByteSpan span_of(const std::string& s) {
  return ByteSpan{reinterpret_cast<const Byte*>(s.data()), s.size()};
}

std::size_t parse_hex(const std::string& hex, Byte* out, std::size_t capacity) {
  const std::size_t n = hex.size() / 2;
  if (n > capacity) return 0;
  if (!vpn::from_hex(hex, MutableByteSpan{out, n})) return 0;
  return n;
}

std::string hex_of(ByteSpan bytes) { return vpn::to_hex(bytes); }

}  // namespace

TEST(aead, rfc8439_2_8_2_known_answer) {
  const std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
      "future, sunscreen would be it.";

  vpn::crypto::AeadKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<Byte>(0x80U + i);

  // Nonce = 07 00 00 00 40 41 42 43 44 45 46 47
  vpn::crypto::AeadNonce nonce{0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                               0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

  Byte aad[12] = {};
  CHECK_EQ(parse_hex("50515253c0c1c2c3c4c5c6c7", aad, sizeof(aad)), std::size_t{12});

  const std::string expected =
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116"
      "1ae10b594f09e26a7e902ecbd0600691";

  Byte sealed[256] = {};
  CHECK(vpn::crypto::chacha20poly1305_seal(MutableByteSpan{sealed, sizeof(sealed)},
                                           span_of(plaintext), key, nonce,
                                           ByteSpan{aad, sizeof(aad)}));
  const std::size_t total = plaintext.size() + vpn::crypto::kAeadTagSize;
  CHECK_EQ(hex_of(ByteSpan{sealed, total}), expected);

  Byte opened[256] = {};
  CHECK(vpn::crypto::chacha20poly1305_open(MutableByteSpan{opened, sizeof(opened)},
                                           ByteSpan{sealed, total}, key, nonce,
                                           ByteSpan{aad, sizeof(aad)}));
  CHECK_EQ(hex_of(ByteSpan{opened, plaintext.size()}), hex_of(span_of(plaintext)));
}

TEST(aead, round_trip_at_every_length_boundary) {
  vpn::crypto::AeadKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<Byte>(i * 7U + 1U);
  const auto nonce = vpn::crypto::transport_nonce(42);

  for (const std::size_t length : {std::size_t{0}, std::size_t{1}, std::size_t{15},
                                   std::size_t{16}, std::size_t{17}, std::size_t{63},
                                   std::size_t{64}, std::size_t{65}, std::size_t{1420}}) {
    Byte plain[1500] = {};
    for (std::size_t i = 0; i < length; ++i) plain[i] = static_cast<Byte>((i * 13U) & 0xFFU);
    Byte sealed[1600] = {};
    Byte opened[1600] = {};
    CHECK(vpn::crypto::chacha20poly1305_seal(MutableByteSpan{sealed, sizeof(sealed)},
                                             ByteSpan{plain, length}, key, nonce, ByteSpan{}));
    CHECK(vpn::crypto::chacha20poly1305_open(MutableByteSpan{opened, sizeof(opened)},
                                             ByteSpan{sealed, length + vpn::crypto::kAeadTagSize},
                                             key, nonce, ByteSpan{}));
    CHECK(vpn::equals(ByteSpan{plain, length}, ByteSpan{opened, length}));
  }
}

TEST(aead, rejects_every_single_bit_flip_in_the_tag) {
  vpn::crypto::AeadKey key{};
  const auto nonce = vpn::crypto::transport_nonce(7);
  const std::string plaintext = "keepalive";

  Byte sealed[64] = {};
  CHECK(vpn::crypto::chacha20poly1305_seal(MutableByteSpan{sealed, sizeof(sealed)},
                                           span_of(plaintext), key, nonce, ByteSpan{}));
  const std::size_t total = plaintext.size() + vpn::crypto::kAeadTagSize;

  for (std::size_t bit = 0; bit < 128; ++bit) {
    sealed[plaintext.size() + bit / 8] ^= static_cast<Byte>(1U << (bit % 8));
    Byte out[64] = {};
    const bool accepted = vpn::crypto::chacha20poly1305_open(
        MutableByteSpan{out, sizeof(out)}, ByteSpan{sealed, total}, key, nonce, ByteSpan{});
    CHECK(!accepted);
    sealed[plaintext.size() + bit / 8] ^= static_cast<Byte>(1U << (bit % 8));
  }
}

TEST(aead, rejects_ciphertext_and_aad_tampering) {
  vpn::crypto::AeadKey key{};
  const auto nonce = vpn::crypto::transport_nonce(0);
  const std::string plaintext = "packet payload";
  const std::string aad = "header";

  Byte sealed[64] = {};
  CHECK(vpn::crypto::chacha20poly1305_seal(MutableByteSpan{sealed, sizeof(sealed)},
                                           span_of(plaintext), key, nonce, span_of(aad)));

  Byte out[64] = {};
  const std::size_t total = plaintext.size() + vpn::crypto::kAeadTagSize;

  // Same data, wrong AAD -> rejected.
  CHECK(!vpn::crypto::chacha20poly1305_open(MutableByteSpan{out, sizeof(out)},
                                            ByteSpan{sealed, total}, key, nonce,
                                            span_of(std::string{"headeR"})));

  // Flip one ciphertext byte -> rejected.
  sealed[0] ^= 0x01U;
  CHECK(!vpn::crypto::chacha20poly1305_open(MutableByteSpan{out, sizeof(out)},
                                            ByteSpan{sealed, total}, key, nonce, span_of(aad)));
  sealed[0] ^= 0x01U;

  // Sanity: the untampered packet still opens.
  CHECK(vpn::crypto::chacha20poly1305_open(MutableByteSpan{out, sizeof(out)},
                                           ByteSpan{sealed, total}, key, nonce, span_of(aad)));
}

TEST(aead, refuses_short_output_buffers) {
  vpn::crypto::AeadKey key{};
  const auto nonce = vpn::crypto::transport_nonce(1);
  const std::string plaintext = "0123456789";

  Byte small[16] = {};  // needs 10 + 16 = 26
  CHECK(!vpn::crypto::chacha20poly1305_seal(MutableByteSpan{small, sizeof(small)},
                                            span_of(plaintext), key, nonce, ByteSpan{}));
}

TEST(aead, transport_nonce_layout_matches_the_protocol) {
  const auto nonce = vpn::crypto::transport_nonce(0x0102030405060708ULL);
  CHECK_EQ(nonce[0], static_cast<Byte>(0));
  CHECK_EQ(nonce[3], static_cast<Byte>(0));
  CHECK_EQ(nonce[4], static_cast<Byte>(0x08));
  CHECK_EQ(nonce[11], static_cast<Byte>(0x01));
}

TEST(aead, xchacha_round_trip_with_a_24_byte_nonce) {
  vpn::crypto::AeadKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<Byte>(0xA0U + i);
  vpn::crypto::XNonce nonce{};
  for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<Byte>(i * 3U + 1U);

  const std::string plaintext = "cookie reply payload";
  Byte sealed[128] = {};
  Byte opened[128] = {};
  CHECK(vpn::crypto::xchacha20poly1305_seal(MutableByteSpan{sealed, sizeof(sealed)},
                                            span_of(plaintext), key, nonce, ByteSpan{}));
  const std::size_t total = plaintext.size() + vpn::crypto::kAeadTagSize;
  CHECK(vpn::crypto::xchacha20poly1305_open(MutableByteSpan{opened, sizeof(opened)},
                                            ByteSpan{sealed, total}, key, nonce, ByteSpan{}));
  CHECK_EQ(hex_of(ByteSpan{opened, plaintext.size()}), hex_of(span_of(plaintext)));

  // A different nonce must not authenticate.
  nonce[23] ^= 0x80U;
  CHECK(!vpn::crypto::xchacha20poly1305_open(MutableByteSpan{opened, sizeof(opened)},
                                             ByteSpan{sealed, total}, key, nonce, ByteSpan{}));
}

