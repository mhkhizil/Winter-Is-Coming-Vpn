// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/crypto/pbkdf2.hpp"

#include <cstring>
#include <vector>

#include "vpn/crypto/ct.hpp"
#include "vpn/crypto/sha256.hpp"

namespace vpn::crypto {

Bytes<32> pbkdf2_sha256(ByteSpan password, ByteSpan salt,
                        std::uint32_t iterations) noexcept {
  Bytes<32> out{};
  if (iterations == 0) return out;

  // PBKDF2 calls HMAC thousands of times with the *same* key, so the two key-pad
  // blocks (and the SHA-256 states after them) are invariant. Caching them is the
  // standard optimisation and it matters: passing the password to hmac_sha256()
  // every iteration took ~1 s per login at 120k iterations on this machine, which
  // is both a terrible user experience and free CPU for anyone who can post to
  // /auth/login. Note the security of PBKDF2 comes from the iteration count, not
  // from our implementation being slow - an attacker uses an optimised one.
  Byte key_block[kSha256BlockSize] = {};
  if (password.size() > kSha256BlockSize) {
    const Bytes<32> hashed = sha256(password);
    std::memcpy(key_block, hashed.data(), hashed.size());
  } else if (!password.empty()) {
    std::memcpy(key_block, password.data(), password.size());
  }
  Byte ipad[kSha256BlockSize] = {};
  Byte opad[kSha256BlockSize] = {};
  for (std::size_t i = 0; i < kSha256BlockSize; ++i) {
    ipad[i] = static_cast<Byte>(key_block[i] ^ 0x36U);
    opad[i] = static_cast<Byte>(key_block[i] ^ 0x5cU);
  }
  Sha256 inner_base;
  inner_base.update(ByteSpan{ipad, sizeof(ipad)});
  Sha256 outer_base;
  outer_base.update(ByteSpan{opad, sizeof(opad)});

  const auto hmac_fixed_key = [&inner_base, &outer_base](ByteSpan data) {
    Bytes<32> inner_md{};
    Sha256 inner = inner_base;  // cheap: 8 words of state + 64-byte buffer
    inner.update(data);
    (void)inner.final(as_span(inner_md));
    Bytes<32> result{};
    Sha256 outer = outer_base;
    outer.update(as_span(inner_md));
    (void)outer.final(as_span(result));
    return result;
  };

  // RFC 8018 §5.2: T_1 = F(P, S, c, 1); only the first block is needed because the
  // derived key is exactly one SHA-256 output.
  std::vector<Byte> seed(salt.begin(), salt.end());
  seed.push_back(0);
  seed.push_back(0);
  seed.push_back(0);
  seed.push_back(1);  // INT_32_BE(1)

  Bytes<32> u = hmac_fixed_key(ByteSpan{seed.data(), seed.size()});
  out = u;
  for (std::uint32_t i = 1; i < iterations; ++i) {
    u = hmac_fixed_key(as_span(u));
    for (std::size_t k = 0; k < out.size(); ++k) out[k] = static_cast<Byte>(out[k] ^ u[k]);
  }
  ct::cleanse(as_span(u));
  ct::cleanse(MutableByteSpan{key_block, sizeof(key_block)});
  ct::cleanse(MutableByteSpan{ipad, sizeof(ipad)});
  ct::cleanse(MutableByteSpan{opad, sizeof(opad)});
  ct::cleanse(MutableByteSpan{seed.data(), seed.size()});
  return out;
}

}  // namespace vpn::crypto
