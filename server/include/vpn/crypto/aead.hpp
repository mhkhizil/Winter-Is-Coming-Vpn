// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// ChaCha20-Poly1305 AEAD (RFC 8439) and XChaCha20-Poly1305, the only AEADs in
// the WireGuard protocol:
//   * handshake payloads: ChaCha20-Poly1305 with an all-zero 12-byte nonce
//   * transport data    : ChaCha20-Poly1305, nonce = 00000000 || counter_le64
//   * cookie replies    : XChaCha20-Poly1305 with a random 24-byte nonce
//
// Seal/open operate in place wherever possible; the tag lives in the last 16
// bytes of the destination buffer. Comparisons of the tag are constant-time.
#pragma once

#include <cstddef>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

inline constexpr std::size_t kAeadKeySize = 32;
inline constexpr std::size_t kAeadNonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kXNonceSize = 24;

using AeadKey = Bytes<kAeadKeySize>;
using AeadNonce = Bytes<kAeadNonceSize>;
using XNonce = Bytes<kXNonceSize>;

// dst must hold plaintext.size() + kAeadTagSize bytes.
// Returns false if the buffer is too small.
[[nodiscard]] bool chacha20poly1305_seal(MutableByteSpan dst, ByteSpan plaintext,
                                         const AeadKey& key, const AeadNonce& nonce,
                                         ByteSpan aad = {}) noexcept;

// ciphertext_and_tag must be at least kAeadTagSize bytes.
// dst must hold ciphertext_and_tag.size() - kAeadTagSize bytes.
// Returns false on authentication failure; `dst` contents are then undefined and
// must not be used.
[[nodiscard]] bool chacha20poly1305_open(MutableByteSpan dst, ByteSpan ciphertext_and_tag,
                                         const AeadKey& key, const AeadNonce& nonce,
                                         ByteSpan aad = {}) noexcept;

[[nodiscard]] bool xchacha20poly1305_seal(MutableByteSpan dst, ByteSpan plaintext,
                                          const AeadKey& key, const XNonce& nonce,
                                          ByteSpan aad = {}) noexcept;

[[nodiscard]] bool xchacha20poly1305_open(MutableByteSpan dst, ByteSpan ciphertext_and_tag,
                                          const AeadKey& key, const XNonce& nonce,
                                          ByteSpan aad = {}) noexcept;

// Builds the WireGuard transport nonce: 4 zero bytes || counter (little endian).
[[nodiscard]] AeadNonce transport_nonce(std::uint64_t counter) noexcept;

}  // namespace vpn::crypto
