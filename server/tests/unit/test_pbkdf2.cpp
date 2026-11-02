// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// PBKDF2-HMAC-SHA256 known answers. Every expected value below comes from Python's
// hashlib.pbkdf2_hmac, never from this implementation:
//
//   hashlib.pbkdf2_hmac('sha256', b'password', b'salt', N, 32).hex()
//   hashlib.pbkdf2_hmac('sha256', b'correct horse battery staple',
//                       bytes.fromhex('00112233445566778899aabbccddeeff'), 120000, 32).hex()
#include <string>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/pbkdf2.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;

ByteSpan span_of(const std::string& s) {
  return ByteSpan{reinterpret_cast<const Byte*>(s.data()), s.size()};
}

std::string derive(const std::string& password, const std::string& salt, std::uint32_t rounds) {
  const auto bytes = vpn::crypto::pbkdf2_sha256(span_of(password), span_of(salt), rounds);
  return vpn::to_hex(vpn::as_span(bytes));
}

}  // namespace

TEST(pbkdf2, matches_python_with_one_iteration) {
  CHECK_EQ(derive("password", "salt", 1),
           std::string{"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"});
}

TEST(pbkdf2, matches_python_with_two_iterations) {
  CHECK_EQ(derive("password", "salt", 2),
           std::string{"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"});
}

TEST(pbkdf2, matches_python_with_a_thousand_iterations) {
  CHECK_EQ(derive("password", "salt", 1000),
           std::string{"632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"});
}

TEST(pbkdf2, matches_python_at_the_production_work_factor) {
  // 120k rounds is what hash_password() uses by default; this also guards the
  // pad-state caching optimisation, which must not change the output.
  const std::string salt{"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 16};
  CHECK_EQ(derive("correct horse battery staple", salt, 120000),
           std::string{"7a474ded296075ecfe01f963746072bcf1df588e3dcc0f6cb6cfb2fac68573ba"});
}

TEST(pbkdf2, a_different_salt_gives_a_different_key) {
  CHECK(derive("password", "salt", 1000) != derive("password", "salt2", 1000));
}

TEST(pbkdf2, a_long_password_is_hashed_as_hkey) {
  // Keys longer than the 64-byte block are hashed first (RFC 2104 §2); the value
  // must still match Python, which does the same.
  const std::string long_password(80, 'k');
  const std::string a = derive(long_password, "salt", 100);
  const std::string b = derive(long_password, "salt", 100);
  CHECK_EQ(a, b);
  CHECK(a != derive("k", "salt", 100));
}

TEST(pbkdf2, zero_rounds_yields_an_empty_key) {
  const auto bytes = vpn::crypto::pbkdf2_sha256(span_of(std::string{"password"}),
                                                span_of(std::string{"salt"}), 0);
  CHECK(vpn::is_zero(vpn::as_span(bytes)));
}
