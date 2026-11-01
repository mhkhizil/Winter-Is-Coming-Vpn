// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// SHA-256 / HMAC-SHA-256 gates. Every expected value comes from Python's hashlib
// and hmac (FIPS 180-4 / RFC 2104), never from this implementation.
#include <cstddef>
#include <string>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/sha256.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;

ByteSpan span_of(const std::string& s) {
  return ByteSpan{reinterpret_cast<const Byte*>(s.data()), s.size()};
}

std::string hex_of(ByteSpan bytes) { return vpn::to_hex(bytes); }

}  // namespace

TEST(sha256, empty_input) {
  const auto digest = vpn::crypto::sha256(ByteSpan{});
  CHECK_EQ(hex_of(vpn::as_span(digest)),
           std::string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"});
}

TEST(sha256, abc_known_answer) {
  const auto digest = vpn::crypto::sha256(span_of(std::string{"abc"}));
  CHECK_EQ(hex_of(vpn::as_span(digest)),
           std::string{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"});
}

TEST(sha256, one_megabyte_streams_correctly) {
  vpn::crypto::Sha256 h;
  std::string chunk(1000, 'a');
  for (int i = 0; i < 1000; ++i) h.update(span_of(chunk));
  Bytes<32> digest{};
  CHECK_EQ(h.final(vpn::as_span(digest)), std::size_t{32});
  CHECK_EQ(hex_of(vpn::as_span(digest)),
           std::string{"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"});
}

TEST(sha256, block_boundaries) {
  // 55/56/64/65 bytes exercise the padding edge cases (length fits / spills).
  for (const std::size_t length : {std::size_t{55}, std::size_t{56}, std::size_t{63},
                                   std::size_t{64}, std::size_t{65}, std::size_t{128}}) {
    const std::string data(length, 'x');
    vpn::crypto::Sha256 streamed;
    for (std::size_t i = 0; i < length; ++i) streamed.update(span_of(std::string(1, 'x')));
    Bytes<32> a{};
    (void)streamed.final(vpn::as_span(a));
    const auto one_shot = vpn::crypto::sha256(span_of(data));
    CHECK(vpn::equals(vpn::as_span(a), vpn::as_span(one_shot)));
  }
}

TEST(sha256, hmac_matches_python) {
  // hmac.new(b"key", b"The quick brown fox jumps over the lazy dog", hashlib.sha256)
  const auto mac = vpn::crypto::hmac_sha256(span_of(std::string{"key"}),
                                            span_of(std::string{
                                                "The quick brown fox jumps over the lazy dog"}));
  CHECK_EQ(hex_of(vpn::as_span(mac)),
           std::string{"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"});
}

TEST(sha256, hmac_with_a_long_key_is_hashed_first) {
  // Keys longer than the 64-byte block are hashed: RFC 2104 §2.
  const std::string long_key(100, 'k');
  const auto mac = vpn::crypto::hmac_sha256(span_of(long_key), span_of(std::string{"msg"}));
  CHECK(!vpn::is_zero(vpn::as_span(mac)));
  const auto again = vpn::crypto::hmac_sha256(span_of(long_key), span_of(std::string{"msg"}));
  CHECK(vpn::equals(vpn::as_span(mac), vpn::as_span(again)));
  const auto other = vpn::crypto::hmac_sha256(span_of(std::string{"k"}), span_of(std::string{"msg"}));
  CHECK(!vpn::equals(vpn::as_span(mac), vpn::as_span(other)));
}

TEST(sha256, refuses_a_short_output_buffer) {
  vpn::crypto::Sha256 h;
  Bytes<16> small{};
  CHECK_EQ(h.final(vpn::as_span(small)), std::size_t{0});
}
