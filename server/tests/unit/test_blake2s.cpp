// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// BLAKE2s correctness gates. RFC 7693 Appendix B vectors are mandatory before
// any handshake code may depend on this implementation (docs/PROTOCOL.md).
#include <cstddef>
#include <string>
#include <vector>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/blake2s.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::as_span;

template <std::size_t N>
std::string hex_of(const Bytes<N>& value) {
  return vpn::to_hex(ByteSpan{value.data(), value.size()});
}

ByteSpan span_of(const std::string& s) {
  return ByteSpan{reinterpret_cast<const Byte*>(s.data()), s.size()};
}

}  // namespace

TEST(blake2s, empty_input_rfc_vector) {
  const auto digest = vpn::crypto::blake2s_256(ByteSpan{});
  CHECK_EQ(hex_of(digest),
           std::string{"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"});
}

TEST(blake2s, abc_rfc_vector) {
  const std::string input = "abc";
  const auto digest = vpn::crypto::blake2s_256(span_of(input));
  CHECK_EQ(hex_of(digest),
           std::string{"508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"});
}

TEST(blake2s, streaming_matches_one_shot_for_every_split) {
  std::vector<Byte> data(1000);
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<Byte>((i * 31U + 7U) & 0xFFU);
  }
  const ByteSpan whole{data.data(), data.size()};
  const auto one_shot = vpn::crypto::blake2s_256(whole);

  // Byte at a time.
  {
    vpn::crypto::Blake2s h{32, ByteSpan{}};
    for (const Byte b : data) h.update(ByteSpan{&b, 1});
    Bytes<32> out{};
    CHECK_EQ(h.final(as_span(out)), std::size_t{32});
    CHECK_EQ(hex_of(out), hex_of(one_shot));
  }

  // Odd chunk sizes, including multiples of the 64-byte block.
  for (const std::size_t chunk : {std::size_t{1}, std::size_t{7}, std::size_t{64},
                                  std::size_t{65}, std::size_t{128}, std::size_t{999}}) {
    vpn::crypto::Blake2s h{32, ByteSpan{}};
    std::size_t offset = 0;
    while (offset < data.size()) {
      const std::size_t n = (data.size() - offset) < chunk ? (data.size() - offset) : chunk;
      h.update(ByteSpan{data.data() + offset, n});
      offset += n;
    }
    Bytes<32> out{};
    CHECK_EQ(h.final(as_span(out)), std::size_t{32});
    CHECK_EQ(hex_of(out), hex_of(one_shot));
  }
}

TEST(blake2s, keyed_differs_from_unkeyed) {
  const std::string message = "wireguard";
  const Bytes<32> key{};
  const auto unkeyed = vpn::crypto::blake2s_256(span_of(message));
  const auto keyed = vpn::crypto::blake2s_256(span_of(message), as_span(key));
  CHECK(!vpn::equals(as_span(unkeyed), as_span(keyed)));
}

TEST(blake2s, keyed_is_deterministic_and_key_sensitive) {
  const std::string message = "wireguard";
  Bytes<32> key_a{};
  Bytes<32> key_b{};
  key_a[0] = 1;
  key_b[0] = 2;

  const auto first = vpn::crypto::blake2s_256(span_of(message), as_span(key_a));
  const auto again = vpn::crypto::blake2s_256(span_of(message), as_span(key_a));
  const auto other = vpn::crypto::blake2s_256(span_of(message), as_span(key_b));
  CHECK(vpn::equals(as_span(first), as_span(again)));
  CHECK(!vpn::equals(as_span(first), as_span(other)));
}

TEST(blake2s, mac_shape_is_128_bits) {
  const std::string message = "mac-input";
  const Bytes<16> key{};
  const auto mac = vpn::crypto::blake2s_128(span_of(message), as_span(key));
  CHECK_EQ(mac.size(), std::size_t{16});
  CHECK(!vpn::is_zero(as_span(mac)));
}

TEST(blake2s, rejects_invalid_output_and_key_sizes) {
  const std::string message = "x";
  Bytes<33> too_big{};
  Bytes<16> ok{};
  Bytes<32> key{};
  Bytes<33> long_key{};
  CHECK(!vpn::crypto::blake2s(span_of(message), ByteSpan{}, as_span(too_big)));
  CHECK(!vpn::crypto::blake2s(span_of(message), as_span(long_key), as_span(ok)));
  CHECK(vpn::crypto::blake2s(span_of(message), as_span(key), as_span(ok)));
}

TEST(blake2s, output_length_parameter_changes_digest) {
  const std::string message = "len";
  Bytes<32> full{};
  Bytes<16> half{};
  CHECK(vpn::crypto::blake2s(span_of(message), ByteSpan{}, as_span(full)));
  CHECK(vpn::crypto::blake2s(span_of(message), ByteSpan{}, as_span(half)));
  // The 128-bit digest is NOT a truncation of the 256-bit one (different
  // parameter block), which is exactly what WireGuard's mac1/mac2 rely on.
  CHECK(!vpn::equals(ByteSpan{full.data(), 16}, ByteSpan{half.data(), 16}));
}

// ---------------------------------------------------------------------------
// Golden vectors (added by the crypto verification pass, 2026-02).
//
// Generated independently with Python's hashlib.blake2s - NOT with this
// implementation - and reproducible with:
//     python server/tests/golden/verify_blake2s.py
// which also cross-checks 560 cases (fixed + 200 randomised inputs) against two
// independent Python models.
//
// Why these exist: the two RFC vectors above cover only the unkeyed 256-bit
// path, yet every MAC WireGuard uses (mac1, mac2, cookie) rides the *keyed
// 128-bit* path, and the KDF rides keyed 256-bit with variable output lengths.
// Neither the keyed mode, the key-block-as-final-block case (keyed empty
// message), nor any non-32-byte output length was pinned to a known-answer
// value before.
//
// Conventions: data = pattern(n) with byte[i] = (i * 31 + 7) & 0xFF,
//              key  = pattern_key(n) with byte[i] = (i * 7 + 1) & 0xFF.
// ---------------------------------------------------------------------------
namespace {

std::vector<Byte> pattern_bytes(std::size_t n) {
  std::vector<Byte> out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<Byte>((i * 31U + 7U) & 0xFFU);
  }
  return out;
}

std::vector<Byte> pattern_key(std::size_t n) {
  std::vector<Byte> out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<Byte>((i * 7U + 1U) & 0xFFU);
  }
  return out;
}

struct GoldenVector {
  const char* label;
  std::size_t data_len;
  std::size_t key_len;
  std::size_t out_len;
  const char* expected_hex;
};

constexpr GoldenVector kGolden[] = {
    {"empty", 0, 0, 32,
     "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
    {"len63", 63, 0, 32,
     "09b00532b122d13b57d7ac541ad072bdf2811eefa4b092c881f8d550ddc18d41"},
    {"len65", 65, 0, 32,
     "d6d4450df251e3801775ffeebb90f8c6b7652c3baec55a1afdfa0d7c1e017d99"},
    {"len127", 127, 0, 32,
     "370dc4bbc49201a0dba43845aef3fb76ac8eb4f9bbf88fe3bd4c7d7d3754c09f"},
    {"len128", 128, 0, 32,
     "9d311d9173e3948ddf703fe64e1b2d365135991fff447f0b956f4c13e5eadd02"},
    {"len129", 129, 0, 32,
     "ebbe2e900b7750ea0ab601a5fe6d07f0b4d6c6ce223fc9cf3e3961d0bde0cfb0"},
    {"len1000", 1000, 0, 32,
     "400e7b648d8b7ba5ce67eda5c471f2dcc0c88319b081817fe158a1953183dfaf"},
    // keyed: the key block is a full 64-byte block even when the message is empty
    {"keyed_empty_k32", 0, 32, 32,
     "6a958176362dad638086db55f0e4820201b6c45f351ebba538df3b613d2b47c0"},
    {"keyed_empty_k16_out16", 0, 16, 16, "173486e44796d18ec2049d864e93c022"},
    {"keyed_pat64_k32", 64, 32, 32,
     "48fc0f38c989078b3ba6daf891e0fb87674e94980e29360fec6a62ad771a3489"},
    {"keyed_pat64_k32_out16", 64, 32, 16, "cb7fa76df92d42e7ad861a7ac1618f41"},
    // the shapes WireGuard actually uses for mac1/mac2/cookie
    {"keyed_pat116_k16_out16", 116, 16, 16, "e7a8ecfb0c6fa936dac0705e1c0b982a"},
    // variable output length (KDF steps)
    {"keyed_pat32_k1_out20", 32, 1, 20, "86d76440a2d19ae43698b955ffb29ce54aaec396"},
};

}  // namespace

TEST(blake2s, golden_vectors_match_the_reference_implementation) {
  for (const auto& v : kGolden) {
    const std::vector<Byte> data = pattern_bytes(v.data_len);
    const std::vector<Byte> key = pattern_key(v.key_len);
    std::vector<Byte> out(v.out_len, 0);
    const bool ok =
        vpn::crypto::blake2s(ByteSpan{data.data(), data.size()},
                             ByteSpan{key.data(), key.size()},
                             vpn::MutableByteSpan{out.data(), out.size()});
    CHECK_MSG(ok, v.label);
    if (!ok) continue;
    const std::string got = vpn::to_hex(ByteSpan{out.data(), out.size()});
    CHECK_MSG(got == std::string{v.expected_hex},
              std::string{"golden mismatch for "} + v.label + ": got " + got +
                  ", want " + v.expected_hex);
  }
}

TEST(blake2s, keyed_streaming_matches_one_shot_at_every_split) {
  // The existing streaming test only covers the unkeyed path. In keyed mode the
  // first block is the zero-padded key block, so update() takes a different
  // branch (buflen_ == 64 and fill == 0); a bug there would corrupt every
  // mac1/mac2 while leaving all unkeyed tests green.
  const std::vector<Byte> data = pattern_bytes(300);
  const std::vector<Byte> key = pattern_key(32);
  const ByteSpan data_span{data.data(), data.size()};
  const ByteSpan key_span{key.data(), key.size()};

  Bytes<16> one_shot{};
  CHECK(vpn::crypto::blake2s(data_span, key_span, as_span(one_shot)));

  for (const std::size_t chunk : {std::size_t{1}, std::size_t{2}, std::size_t{32},
                                  std::size_t{63}, std::size_t{64}, std::size_t{65},
                                  std::size_t{128}, std::size_t{256},
                                  std::size_t{299}}) {
    vpn::crypto::Blake2s h{16, key_span};
    std::size_t offset = 0;
    while (offset < data.size()) {
      const std::size_t n =
          (data.size() - offset) < chunk ? (data.size() - offset) : chunk;
      h.update(ByteSpan{data.data() + offset, n});
      offset += n;
    }
    Bytes<16> out{};
    CHECK_EQ(h.final(as_span(out)), std::size_t{16});
    CHECK_MSG(vpn::equals(as_span(out), as_span(one_shot)),
              "keyed streaming must equal the one-shot digest for every split");
  }

  // A 32-byte message delivered in two halves must match the one-shot result:
  // this is the "key block is full, message is short" shape mac1 uses.
  const std::vector<Byte> short_msg = pattern_bytes(32);
  Bytes<16> a{};
  CHECK(vpn::crypto::blake2s(ByteSpan{short_msg.data(), short_msg.size()}, key_span,
                             as_span(a)));
  vpn::crypto::Blake2s h{16, key_span};
  h.update(ByteSpan{short_msg.data(), 16});
  h.update(ByteSpan{short_msg.data() + 16, 16});
  Bytes<16> b{};
  CHECK_EQ(h.final(as_span(b)), std::size_t{16});
  CHECK(vpn::equals(as_span(a), as_span(b)));
}

TEST(blake2s, every_output_length_from_1_to_32_is_supported) {
  const std::string message = "wireguard-kdf";
  for (std::size_t n = 1; n <= 32; ++n) {
    std::vector<Byte> out(n, 0);
    CHECK_MSG(vpn::crypto::blake2s(span_of(message), ByteSpan{},
                                   vpn::MutableByteSpan{out.data(), out.size()}),
              "every out_len in [1,32] must be accepted");
    CHECK(!vpn::is_zero(ByteSpan{out.data(), out.size()}));
  }
}

// ---------------------------------------------------------------------------
// Added by the 2026-02 verification pass, round 2: two API-contract edges the
// vectors above cannot reach.
// ---------------------------------------------------------------------------
TEST(blake2s, final_refuses_a_short_output_buffer_and_can_be_retried) {
  // Documented contract: final() returns 0 (and writes nothing) when `out` is
  // smaller than out_len(). Returning a partial digest instead would be a
  // silent truncation bug in every caller that mis-sizes a buffer.
  const std::string input = "abc";
  vpn::crypto::Blake2s h{32, ByteSpan{}};
  h.update(span_of(input));

  Bytes<16> small{};
  CHECK_EQ(h.final(as_span(small)), std::size_t{0});

  // A refused final() must not consume state: the retry has to produce the
  // RFC 7693 "abc" digest.
  Bytes<32> out{};
  CHECK_EQ(h.final(as_span(out)), std::size_t{32});
  CHECK_EQ(hex_of(out),
           std::string{"508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"});
}

TEST(blake2s, zero_length_output_is_refused) {
  // RFC 7693 allows out_len in [1,32]; 0 is not a valid parameter block.
  const std::string message = "x";
  CHECK(!vpn::crypto::blake2s(span_of(message), ByteSpan{}, vpn::MutableByteSpan{}));
}

