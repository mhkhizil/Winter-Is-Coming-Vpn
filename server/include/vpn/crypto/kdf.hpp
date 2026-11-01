// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Key derivation for the WireGuard handshake: HMAC-BLAKE2s-256 and the three
// KDF steps from the protocol (a HKDF-shaped expansion with the counter byte
// appended to the previous output).
//
//   T0 = HMAC-BLAKE2s(key, input)
//   T1 = HMAC-BLAKE2s(T0, 0x01)
//   T2 = HMAC-BLAKE2s(T0, T1 || 0x02)
//   T3 = HMAC-BLAKE2s(T0, T2 || 0x03)
//
// Validated against an independent Python implementation (hmac + hashlib.blake2s)
// in server/tests/golden/verify_kdf.py.
#pragma once

#include <cstddef>
#include <initializer_list>
#include <span>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

// HMAC-BLAKE2s-256 over the concatenation of `parts`.
[[nodiscard]] Bytes<32> hmac_blake2s_256(ByteSpan key,
                                         std::initializer_list<ByteSpan> parts) noexcept;

// Out-parameter form for the variable-length steps below.
[[nodiscard]] bool hmac_blake2s_256(ByteSpan key, ByteSpan data,
                                    MutableByteSpan out) noexcept;

// WireGuard KDF1/KDF2/KDF3. `out` selects how many 32-byte blocks are produced
// (out.size() must be a multiple of 32, at most 96). Returns false on bad sizes.
[[nodiscard]] bool kdf(ByteSpan chaining_key, ByteSpan input, MutableByteSpan out) noexcept;

}  // namespace vpn::crypto
