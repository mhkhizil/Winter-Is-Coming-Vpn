// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// X25519 gates: RFC 7748 section 5.2 (scalar multiplication), section 6.1
// (Alice/Bob key agreement), the iterated test, low-order rejection, and the
// properties the handshake relies on.
#include <cstddef>
#include <string>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/x25519.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;

std::string hex_of(ByteSpan bytes) { return vpn::to_hex(bytes); }

bool parse32(const std::string& hex, Bytes<32>& out) {
  return vpn::from_hex(hex, MutableByteSpan{out.data(), out.size()});
}

}  // namespace

TEST(x25519, rfc7748_section_5_2_vector_1) {
  Bytes<32> scalar{};
  Bytes<32> point{};
  Bytes<32> expected{};
  CHECK(parse32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar));
  CHECK(parse32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point));
  CHECK(parse32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", expected));

  vpn::crypto::X25519PublicKey out{};
  CHECK(vpn::crypto::x25519(out, scalar, point));
  CHECK_EQ(hex_of(vpn::as_span(out)), hex_of(vpn::as_span(expected)));
}

TEST(x25519, rfc7748_section_5_2_vector_2) {
  Bytes<32> scalar{};
  Bytes<32> point{};
  Bytes<32> expected{};
  CHECK(parse32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar));
  CHECK(parse32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", point));
  CHECK(parse32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", expected));

  vpn::crypto::X25519PublicKey out{};
  CHECK(vpn::crypto::x25519(out, scalar, point));
  CHECK_EQ(hex_of(vpn::as_span(out)), hex_of(vpn::as_span(expected)));
}

TEST(x25519, rfc7748_section_6_1_key_agreement) {
  Bytes<32> alice_priv{};
  Bytes<32> alice_pub{};
  Bytes<32> bob_priv{};
  Bytes<32> bob_pub{};
  Bytes<32> shared{};
  CHECK(parse32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice_priv));
  CHECK(parse32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alice_pub));
  CHECK(parse32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob_priv));
  CHECK(parse32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bob_pub));
  CHECK(parse32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared));

  vpn::crypto::X25519PublicKey derived_alice{};
  CHECK(vpn::crypto::x25519_base(derived_alice, alice_priv));
  CHECK_EQ(hex_of(vpn::as_span(derived_alice)), hex_of(vpn::as_span(alice_pub)));

  vpn::crypto::X25519PublicKey derived_bob{};
  CHECK(vpn::crypto::x25519_base(derived_bob, bob_priv));
  CHECK_EQ(hex_of(vpn::as_span(derived_bob)), hex_of(vpn::as_span(bob_pub)));

  vpn::crypto::X25519PublicKey a_shared{};
  vpn::crypto::X25519PublicKey b_shared{};
  CHECK(vpn::crypto::x25519(a_shared, alice_priv, bob_pub));
  CHECK(vpn::crypto::x25519(b_shared, bob_priv, alice_pub));
  CHECK_EQ(hex_of(vpn::as_span(a_shared)), hex_of(vpn::as_span(shared)));
  CHECK(vpn::equals(vpn::as_span(a_shared), vpn::as_span(b_shared)));
}

TEST(x25519, rfc7748_iterated_1000_times) {
  // Section 5.2: start with k = u = 9, then k,u = X25519(k,u), k for 1000 rounds.
  Bytes<32> k{};
  Bytes<32> u{};
  k[0] = 9;
  u[0] = 9;
  for (int i = 0; i < 1000; ++i) {
    vpn::crypto::X25519PublicKey out{};
    CHECK(vpn::crypto::x25519(out, k, u));
    u = k;
    k = out;
  }
  CHECK_EQ(hex_of(vpn::as_span(k)),
           std::string{"684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"});
}

TEST(x25519, rejects_low_order_points) {
  // The eight low-order points; every DH with them is all-zero.
  const char* low_order[] = {
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  };
  std::size_t checked = 0;
  for (const char* hex : low_order) {
    Bytes<32> point{};
    if (!parse32(hex, point)) continue;
    vpn::crypto::X25519PrivateKey scalar{};
    for (std::size_t i = 0; i < scalar.size(); ++i) scalar[i] = static_cast<Byte>(i + 1);
    vpn::crypto::X25519PublicKey out{};
    CHECK(!vpn::crypto::x25519(out, scalar, point));
    CHECK(vpn::crypto::x25519_is_low_order(point));
    ++checked;
  }
  // The seven canonical small-order points (0, 1, the two order-8/order-4
  // points, and p-1, p, p+1 which decode to 0 and 1).
  CHECK_EQ(checked, std::size_t{7});
}

TEST(x25519, generated_keys_agree) {
  vpn::crypto::X25519KeyPair alice{};
  vpn::crypto::X25519KeyPair bob{};
  CHECK(vpn::crypto::x25519_generate(alice));
  CHECK(vpn::crypto::x25519_generate(bob));
  CHECK(!vpn::equals(vpn::as_span(alice.public_key), vpn::as_span(bob.public_key)));

  vpn::crypto::X25519PublicKey ab{};
  vpn::crypto::X25519PublicKey ba{};
  CHECK(vpn::crypto::x25519(ab, alice.private_key, bob.public_key));
  CHECK(vpn::crypto::x25519(ba, bob.private_key, alice.public_key));
  CHECK(vpn::equals(vpn::as_span(ab), vpn::as_span(ba)));
  CHECK(!vpn::is_zero(vpn::as_span(ab)));
}
