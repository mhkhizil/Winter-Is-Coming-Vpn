// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// BLAKE2s per RFC 7693, including keyed mode and streaming.
// Straightforward, branch-free-on-secrets reference shape: the compression
// function is the only hot loop and is written so a compiler can vectorise the
// G mixing rounds later (see docs/PROTOCOL.md, "Performance envelope").
#include "vpn/crypto/blake2s.hpp"

#include <cstring>

#include "vpn/common/endian.hpp"
#include "vpn/crypto/ct.hpp"

namespace vpn::crypto {
namespace {

constexpr std::uint32_t kIv[8] = {0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
                                  0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};

constexpr Byte kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

void mix(std::uint32_t v[16], int a, int b, int c, int d, std::uint32_t x,
         std::uint32_t y) noexcept {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr32(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr32(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr32(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = rotr32(v[b] ^ v[c], 7);
}

}  // namespace

Blake2s::Blake2s(std::size_t out_len, ByteSpan key) noexcept
    : t_(0), buflen_(0), out_len_(out_len) {
  for (std::size_t i = 0; i < 8; ++i) h_[i] = kIv[i];
  // Keyed mode is only defined for 0 <= keylen <= 32; anything longer would
  // overflow buf_ (64 bytes) on the memcpy below. The one-shot helpers reject
  // such keys, and this clamp makes the class itself memory-safe regardless.
  const std::size_t key_size = key.size() < kBlake2sMaxKey ? key.size() : kBlake2sMaxKey;
  // Parameter block: digest length, key length, fanout=1, depth=1.
  const auto key_len = static_cast<std::uint32_t>(key_size);
  h_[0] ^= 0x01010000U ^ (key_len << 8) ^ static_cast<std::uint32_t>(out_len);

  std::memset(buf_, 0, sizeof(buf_));
  if (key_size > 0) {
    // The key block is a full 64-byte block, zero padded, compressed *after*
    // the first message bytes arrive (or as the final block if none do).
    std::memcpy(buf_, key.data(), key_size);
    buflen_ = kBlake2sBlockSize;
  }
}

void Blake2s::compress(const Byte* block, bool last) noexcept {
  std::uint32_t m[16];
  std::uint32_t v[16];
  for (std::size_t i = 0; i < 16; ++i) m[i] = load_le32(block + 4 * i);
  for (std::size_t i = 0; i < 8; ++i) {
    v[i] = h_[i];
    v[i + 8] = kIv[i];
  }
  v[12] ^= static_cast<std::uint32_t>(t_ & 0xFFFFFFFFULL);
  v[13] ^= static_cast<std::uint32_t>((t_ >> 32) & 0xFFFFFFFFULL);
  if (last) v[14] = ~v[14];

  for (std::size_t r = 0; r < 10; ++r) {
    const Byte* s = kSigma[r];
    mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (std::size_t i = 0; i < 8; ++i) h_[i] ^= v[i] ^ v[i + 8];
}

void Blake2s::update(ByteSpan data) noexcept {
  if (data.empty()) return;
  const Byte* p = data.data();
  std::size_t len = data.size();

  const std::size_t left = buflen_;
  const std::size_t fill = kBlake2sBlockSize - left;

  if (len > fill) {
    if (fill > 0) {
      std::memcpy(buf_ + left, p, fill);
    }
    buflen_ = 0;
    t_ += kBlake2sBlockSize;
    compress(buf_, false);
    p += fill;
    len -= fill;

    // Keep at least one byte (and the whole last block) buffered for `final`.
    while (len > kBlake2sBlockSize) {
      t_ += kBlake2sBlockSize;
      compress(p, false);
      p += kBlake2sBlockSize;
      len -= kBlake2sBlockSize;
    }
    std::memcpy(buf_, p, len);
    buflen_ = len;
  } else {
    std::memcpy(buf_ + left, p, len);
    buflen_ = left + len;
  }
}

std::size_t Blake2s::final(MutableByteSpan out) noexcept {
  if (out.size() < out_len_) return 0;

  t_ += buflen_;
  std::memset(buf_ + buflen_, 0, kBlake2sBlockSize - buflen_);
  compress(buf_, true);

  Byte full[kBlake2sMaxOut] = {};
  for (std::size_t i = 0; i < 8; ++i) store_le32(full + 4 * i, h_[i]);
  std::memcpy(out.data(), full, out_len_);

  ct::cleanse(MutableByteSpan{full, sizeof(full)});
  ct::cleanse(MutableByteSpan{reinterpret_cast<Byte*>(h_), sizeof(h_)});
  ct::cleanse(MutableByteSpan{buf_, sizeof(buf_)});
  buflen_ = 0;
  return out_len_;
}

bool blake2s(ByteSpan data, ByteSpan key, MutableByteSpan out) noexcept {
  if (out.empty() || out.size() > kBlake2sMaxOut) return false;
  if (key.size() > kBlake2sMaxKey) return false;
  Blake2s h(out.size(), key);
  h.update(data);
  return h.final(out) == out.size();
}

Bytes<32> blake2s_256(ByteSpan data) noexcept {
  Bytes<32> out{};
  (void)blake2s(data, ByteSpan{}, as_span(out));
  return out;
}

Bytes<32> blake2s_256(ByteSpan data, ByteSpan key) noexcept {
  Bytes<32> out{};
  (void)blake2s(data, key, as_span(out));
  return out;
}

Bytes<16> blake2s_128(ByteSpan data, ByteSpan key) noexcept {
  Bytes<16> out{};
  (void)blake2s(data, key, as_span(out));
  return out;
}

}  // namespace vpn::crypto
