// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/crypto/sha256.hpp"

#include <cstring>

#include "vpn/common/endian.hpp"
#include "vpn/crypto/ct.hpp"

namespace vpn::crypto {
namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

}  // namespace

Sha256::Sha256() noexcept
    : h_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU,
        0x5be0cd19U},
      total_bytes_(0),
      buffer_{},
      buffered_(0) {}

void Sha256::compress(const Byte* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) w[i] = load_be32(block + 4 * i);
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3U);
    const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = hh + s1 + ch + kK[i] + w[i];
    const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    hh = g; g = f; f = e;
    e = d + temp1;
    d = c; c = b; b = a;
    a = temp1 + temp2;
  }

  h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
  h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Sha256::update(ByteSpan data) noexcept {
  if (data.empty()) return;
  total_bytes_ += data.size();
  const Byte* p = data.data();
  std::size_t remaining = data.size();

  if (buffered_ > 0) {
    const std::size_t take = (kSha256BlockSize - buffered_) < remaining
                                 ? (kSha256BlockSize - buffered_)
                                 : remaining;
    std::memcpy(buffer_ + buffered_, p, take);
    buffered_ += take;
    p += take;
    remaining -= take;
    if (buffered_ == kSha256BlockSize) {
      compress(buffer_);
      buffered_ = 0;
    }
  }
  while (remaining >= kSha256BlockSize) {
    compress(p);
    p += kSha256BlockSize;
    remaining -= kSha256BlockSize;
  }
  if (remaining > 0) {
    std::memcpy(buffer_, p, remaining);
    buffered_ = remaining;
  }
}

std::size_t Sha256::final(MutableByteSpan out) noexcept {
  if (out.size() < kSha256DigestSize) return 0;

  const std::uint64_t bits = total_bytes_ * 8U;
  Byte pad = static_cast<Byte>(0x80);
  update(ByteSpan{&pad, 1});
  const Byte zero = 0;
  while (buffered_ != 56) {
    update(ByteSpan{&zero, 1});
  }
  Byte length_be[8] = {};
  store_be64(length_be, bits);
  update(ByteSpan{length_be, sizeof(length_be)});

  for (std::size_t i = 0; i < 8; ++i) store_be32(out.data() + 4 * i, h_[i]);
  ct::cleanse(MutableByteSpan{reinterpret_cast<Byte*>(h_), sizeof(h_)});
  ct::cleanse(MutableByteSpan{buffer_, sizeof(buffer_)});
  buffered_ = 0;
  total_bytes_ = 0;
  return kSha256DigestSize;
}

Bytes<32> sha256(ByteSpan data) noexcept {
  Sha256 h;
  h.update(data);
  Bytes<32> out{};
  (void)h.final(as_span(out));
  return out;
}

Bytes<32> hmac_sha256(ByteSpan key, ByteSpan data) noexcept {
  Byte k_prime[kSha256BlockSize] = {};
  if (key.size() > kSha256BlockSize) {
    const Bytes<32> hashed = sha256(key);
    std::memcpy(k_prime, hashed.data(), hashed.size());
  } else {
    std::memcpy(k_prime, key.data(), key.size());
  }

  Byte pad[kSha256BlockSize] = {};
  for (std::size_t i = 0; i < kSha256BlockSize; ++i) pad[i] = static_cast<Byte>(k_prime[i] ^ 0x36U);
  Bytes<32> inner{};
  {
    Sha256 h;
    h.update(ByteSpan{pad, sizeof(pad)});
    h.update(data);
    (void)h.final(as_span(inner));
  }
  for (std::size_t i = 0; i < kSha256BlockSize; ++i) pad[i] = static_cast<Byte>(k_prime[i] ^ 0x5cU);
  Bytes<32> out{};
  {
    Sha256 h;
    h.update(ByteSpan{pad, sizeof(pad)});
    h.update(as_span(inner));
    (void)h.final(as_span(out));
  }
  ct::cleanse(MutableByteSpan{k_prime, sizeof(k_prime)});
  ct::cleanse(MutableByteSpan{pad, sizeof(pad)});
  ct::cleanse(as_span(inner));
  return out;
}

bool mac_equal(ByteSpan expected_hex, ByteSpan received_hex) noexcept {
  return ct::equal(expected_hex, received_hex);
}

}  // namespace vpn::crypto
