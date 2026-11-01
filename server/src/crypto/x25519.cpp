// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// X25519 (RFC 7748) - Curve25519 scalar multiplication.
//
// Field arithmetic uses 16 limbs of 16 bits in int64 (the TweetNaCl shape): it is
// compact, constant-time by construction (no secret-dependent branches or
// indices, conditional swaps are masked), and easy to audit. Validation:
// RFC 7748 section 5.2 and 6.1 vectors in tests/unit/test_x25519.cpp.
#include "vpn/crypto/x25519.hpp"

#include <cstdint>

#include "vpn/crypto/ct.hpp"
#include "vpn/crypto/random.hpp"

namespace vpn::crypto {
namespace {

using Gf = std::int64_t[16];

constexpr std::int64_t kA24 = 121665;

void car25519(Gf o) noexcept {
  for (int i = 0; i < 16; ++i) {
    o[i] += (1LL << 16);
    const std::int64_t c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c << 16;
  }
}

// Constant-time conditional swap: b == 1 swaps, b == 0 does not.
void sel25519(Gf p, Gf q, int b) noexcept {
  const std::int64_t c = ~(static_cast<std::int64_t>(b) - 1);
  for (int i = 0; i < 16; ++i) {
    const std::int64_t t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

void pack25519(Byte* o, const Gf n) noexcept {
  Gf m{};
  Gf t{};
  for (int i = 0; i < 16; ++i) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (int j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    const int b = static_cast<int>((m[15] >> 16) & 1);
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (int i = 0; i < 16; ++i) {
    o[2 * i] = static_cast<Byte>(t[i] & 0xff);
    o[2 * i + 1] = static_cast<Byte>((t[i] >> 8) & 0xff);
  }
}

void unpack25519(Gf o, const Byte* n) noexcept {
  for (int i = 0; i < 16; ++i) {
    o[i] = static_cast<std::int64_t>(n[2 * i]) + (static_cast<std::int64_t>(n[2 * i + 1]) << 8);
  }
  o[15] &= 0x7fff;
}

void add(Gf o, const Gf a, const Gf b) noexcept {
  for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

void sub(Gf o, const Gf a, const Gf b) noexcept {
  for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

void mul(Gf o, const Gf a, const Gf b) noexcept {
  std::int64_t t[31] = {};
  for (int i = 0; i < 16; ++i) {
    for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
  }
  for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; ++i) o[i] = t[i];
  car25519(o);
  car25519(o);
}

void square(Gf o, const Gf a) noexcept { mul(o, a, a); }

// o = i^(2^255 - 21) = i^-1 for non-zero i (Fermat).
void invert25519(Gf o, const Gf i) noexcept {
  Gf c{};
  for (int a = 0; a < 16; ++a) c[a] = i[a];
  for (int a = 253; a >= 0; --a) {
    square(c, c);
    if (a != 2 && a != 4) mul(c, c, i);
  }
  for (int a = 0; a < 16; ++a) o[a] = c[a];
}

}  // namespace

namespace {

// Constant-time scalar multiplication; `q` receives the u-coordinate.
void scalarmult(Byte* q, const Byte* scalar, const Byte* point) noexcept {
  Byte z[32];
  std::int64_t x[80] = {};
  Gf a{}, b{}, c{}, d{}, e{}, f{};

  for (int i = 0; i < 31; ++i) z[i] = scalar[i];
  z[31] = static_cast<Byte>((scalar[31] & 127) | 64);  // clamp
  z[0] = static_cast<Byte>(scalar[0] & 248);

  unpack25519(x, point);
  for (int i = 0; i < 16; ++i) {
    b[i] = x[i];
    c[i] = 0;
    d[i] = 0;
    a[i] = 0;
  }
  a[0] = 1;
  d[0] = 1;

  for (int i = 254; i >= 0; --i) {
    const int r = (z[i >> 3] >> (i & 7)) & 1;
    sel25519(a, b, r);
    sel25519(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    square(d, e);
    square(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    square(b, a);
    sub(c, d, f);
    Gf a24{};
    a24[0] = kA24;
    mul(a, c, a24);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    square(b, e);
    sel25519(a, b, r);
    sel25519(c, d, r);
  }

  for (int i = 0; i < 16; ++i) {
    x[i + 16] = a[i];
    x[i + 32] = c[i];
    x[i + 48] = b[i];
    x[i + 64] = d[i];
  }
  invert25519(x + 32, x + 32);
  mul(x + 16, x + 16, x + 32);
  pack25519(q, x + 16);

  ct::cleanse(MutableByteSpan{z, sizeof(z)});
  ct::cleanse(MutableByteSpan{reinterpret_cast<Byte*>(x), sizeof(x)});
}

}  // namespace

bool x25519_generate(X25519KeyPair& out) noexcept {
  if (!fill_random(as_span(out.private_key))) return false;
  return x25519_base(out.public_key, out.private_key);
}

bool x25519(X25519PublicKey& out, const X25519PrivateKey& scalar,
            const X25519PublicKey& point) noexcept {
  scalarmult(out.data(), scalar.data(), point.data());
  // An all-zero result means a low-order point: RFC 7748 section 6.1 requires
  // the caller to reject the exchange.
  if (is_zero(as_span(out))) {
    ct::cleanse(as_span(out));
    return false;
  }
  return true;
}

bool x25519_base(X25519PublicKey& out, const X25519PrivateKey& scalar) noexcept {
  X25519PublicKey base{};
  base[0] = 9;  // the standard generator u-coordinate
  scalarmult(out.data(), scalar.data(), base.data());
  return !is_zero(as_span(out));
}

bool x25519_is_low_order(const X25519PublicKey& point) noexcept {
  // Multiply by a fixed non-zero scalar: every low-order point maps to zero.
  X25519PrivateKey probe{};
  for (std::size_t i = 0; i < probe.size(); ++i) probe[i] = static_cast<Byte>(0x42U + i);
  X25519PublicKey result{};
  scalarmult(result.data(), probe.data(), point.data());
  const bool zero = is_zero(as_span(result));
  ct::cleanse(as_span(result));
  ct::cleanse(as_span(probe));
  return zero;
}

}  // namespace vpn::crypto
