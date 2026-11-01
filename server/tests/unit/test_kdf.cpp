// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// HMAC-BLAKE2s and the WireGuard KDF. Every expected value here was produced by
// an independent Python implementation (hmac + hashlib.blake2s), never by this
// code - see the commands recorded in server/tests/golden/VERIFICATION_REPORT.md.
#include <cstddef>
#include <string>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/kdf.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;

ByteSpan span_of(const std::string& s) {
  return ByteSpan{reinterpret_cast<const Byte*>(s.data()), s.size()};
}

std::string hex_of(ByteSpan bytes) { return vpn::to_hex(bytes); }

}  // namespace

TEST(kdf, hmac_blake2s_256_matches_python_hmac) {
  // hmac.new(b"key", b"The quick brown fox jumps over the lazy dog",
  //          hashlib.blake2s).hexdigest()
  const auto mac = vpn::crypto::hmac_blake2s_256(span_of(std::string{"key"}),
                                                 {span_of(std::string{
                                                     "The quick brown fox jumps over the lazy dog"})});
  CHECK_EQ(hex_of(vpn::as_span(mac)),
           std::string{"f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0"});
}

TEST(kdf, hmac_blake2s_256_with_a_32_byte_key) {
  Bytes<32> key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<Byte>(i);
  const auto mac = vpn::crypto::hmac_blake2s_256(vpn::as_span(key),
                                                 {span_of(std::string{"wireguard-kdf-selfcheck"})});
  CHECK_EQ(hex_of(vpn::as_span(mac)),
           std::string{"e284b512eed5f4d76fc89e54208d95e1cda15f015829404bdb4fe2deb90dad9c"});
}

TEST(kdf, wireguard_kdf2_matches_the_reference_construction) {
  // T0 = HMAC(ck, input); T1 = HMAC(T0, 0x01); T2 = HMAC(T0, T1 || 0x02)
  Bytes<32> chaining_key{};  // all zero
  Bytes<64> out{};
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), span_of(std::string{"input"}),
                         vpn::as_span(out)));
  CHECK_EQ(hex_of(ByteSpan{out.data(), 32}),
           std::string{"fbff6119f265251560576e82518f61aeb420cff55b5dcf649475b758a01f3951"});
  CHECK_EQ(hex_of(ByteSpan{out.data() + 32, 32}),
           std::string{"a534dd2f7d3e7e614508dba7c675d5cf1008b383670cd8fd46231aa38bbfb618"});
  // The two blocks must differ (that is what makes it a KDF, not a copy).
  CHECK(!vpn::equals(ByteSpan{out.data(), 32}, ByteSpan{out.data() + 32, 32}));
}

TEST(kdf, kdf1_and_kdf3_shapes) {
  Bytes<32> chaining_key{};
  Bytes<32> one{};
  Bytes<96> three{};
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), span_of(std::string{"x"}),
                         vpn::as_span(one)));
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), span_of(std::string{"x"}),
                         vpn::as_span(three)));
  // KDF1 is the first block of KDF3 for the same inputs.
  CHECK(vpn::equals(vpn::as_span(one), ByteSpan{three.data(), 32}));
  // All three blocks differ.
  CHECK(!vpn::equals(ByteSpan{three.data(), 32}, ByteSpan{three.data() + 32, 32}));
  CHECK(!vpn::equals(ByteSpan{three.data() + 32, 32}, ByteSpan{three.data() + 64, 32}));
}

TEST(kdf, rejects_invalid_output_sizes) {
  Bytes<32> chaining_key{};
  Bytes<16> sixteen{};
  Bytes<96> ok{};
  CHECK(!vpn::crypto::kdf(vpn::as_span(chaining_key), ByteSpan{}, vpn::as_span(sixteen)));
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), ByteSpan{}, vpn::as_span(ok)));
}

TEST(kdf, hmac_rejects_a_wrong_output_size) {
  Bytes<31> bad{};
  CHECK(!vpn::crypto::hmac_blake2s_256(ByteSpan{}, ByteSpan{}, vpn::as_span(bad)));
}

TEST(kdf, different_inputs_give_different_keys) {
  Bytes<32> chaining_key{};
  Bytes<32> a{};
  Bytes<32> b{};
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), span_of(std::string{"input-a"}),
                         vpn::as_span(a)));
  CHECK(vpn::crypto::kdf(vpn::as_span(chaining_key), span_of(std::string{"input-b"}),
                         vpn::as_span(b)));
  CHECK(!vpn::equals(vpn::as_span(a), vpn::as_span(b)));
}
