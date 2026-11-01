// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// HMAC-BLAKE2s-256 and the WireGuard KDF steps.
#include "vpn/crypto/kdf.hpp"

#include <cstddef>

#include "vpn/crypto/blake2s.hpp"
#include "vpn/crypto/ct.hpp"

namespace vpn::crypto {
namespace {

constexpr std::size_t kBlockSize = 64;  // BLAKE2s block size, also the HMAC pad size

// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
// For BLAKE2s we use unkeyed hashing (HMAC is defined over the plain hash).
void hmac_into(ByteSpan key, ByteSpan data, MutableByteSpan out) noexcept {
  Byte k_prime[kBlockSize] = {};
  if (key.size() > kBlockSize) {
    Bytes<32> hashed{};
    Blake2s h{32, ByteSpan{}};
    h.update(key);
    (void)h.final(as_span(hashed));
    for (std::size_t i = 0; i < hashed.size(); ++i) k_prime[i] = hashed[i];
    ct::cleanse(as_span(hashed));
  } else {
    for (std::size_t i = 0; i < key.size(); ++i) k_prime[i] = key[i];
  }

  Byte pad[kBlockSize] = {};
  Bytes<32> inner{};

  // inner = H((K' ^ ipad) || data)
  {
    for (std::size_t i = 0; i < kBlockSize; ++i) {
      pad[i] = static_cast<Byte>(k_prime[i] ^ 0x36U);
    }
    Blake2s h{32, ByteSpan{}};
    h.update(ByteSpan{pad, kBlockSize});
    h.update(data);
    (void)h.final(as_span(inner));
  }

  // out = H((K' ^ opad) || inner)
  {
    for (std::size_t i = 0; i < kBlockSize; ++i) {
      pad[i] = static_cast<Byte>(k_prime[i] ^ 0x5cU);
    }
    Blake2s h{32, ByteSpan{}};
    h.update(ByteSpan{pad, kBlockSize});
    h.update(as_span(inner));
    (void)h.final(out);
  }

  ct::cleanse(MutableByteSpan{k_prime, sizeof(k_prime)});
  ct::cleanse(MutableByteSpan{pad, sizeof(pad)});
  ct::cleanse(as_span(inner));
}

}  // namespace

bool hmac_blake2s_256(ByteSpan key, ByteSpan data, MutableByteSpan out) noexcept {
  if (out.size() != 32) return false;
  hmac_into(key, data, out);
  return true;
}

Bytes<32> hmac_blake2s_256(ByteSpan key, std::initializer_list<ByteSpan> parts) noexcept {
  // Concatenate the parts in a stack buffer; every caller in the handshake uses
  // small, fixed-size inputs (<= 96 bytes total).
  Byte buffer[136] = {};
  std::size_t used = 0;
  for (const ByteSpan part : parts) {
    if (part.empty()) continue;
    if (used + part.size() > sizeof(buffer)) break;  // caller error: truncate
    for (std::size_t i = 0; i < part.size(); ++i) buffer[used + i] = part[i];
    used += part.size();
  }
  Bytes<32> out{};
  hmac_into(key, ByteSpan{buffer, used}, as_span(out));
  ct::cleanse(MutableByteSpan{buffer, sizeof(buffer)});
  return out;
}

bool kdf(ByteSpan chaining_key, ByteSpan input, MutableByteSpan out) noexcept {
  if (out.empty() || out.size() % 32 != 0 || out.size() > 96) return false;

  const Bytes<32> t0 = hmac_blake2s_256(chaining_key, {input});
  Bytes<32> previous{};
  Byte counter = 1;

  for (std::size_t block = 0; block < out.size() / 32; ++block) {
    Bytes<32> ti{};
    if (block == 0) {
      ti = hmac_blake2s_256(as_span(t0), {ByteSpan{&counter, 1}});
    } else {
      ti = hmac_blake2s_256(as_span(t0), {as_span(previous), ByteSpan{&counter, 1}});
    }
    for (std::size_t i = 0; i < 32; ++i) out[block * 32 + i] = ti[i];
    previous = ti;
    ++counter;
    ct::cleanse(as_span(ti));
  }

  ct::cleanse(as_span(previous));
  return true;
}

}  // namespace vpn::crypto
