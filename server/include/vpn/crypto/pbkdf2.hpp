// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// PBKDF2-HMAC-SHA256 (RFC 8018 / RFC 2898).
//
// Passwords used to be stored as a single HMAC-BLAKE2s, which is a fast MAC: fine
// for verifying a login, useless as a defence if the store file leaks, because an
// attacker can test billions of candidates per second. A password hash has to be
// deliberately slow, and PBKDF2 over the SHA-256 we already ship is the smallest
// dependency-free way to get that (no new code to trust for Argon2/scrypt, which
// would need a large, security-critical implementation).
#pragma once

#include <cstdint>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

// Derives a 32-byte key. `iterations` is the work factor; callers should not go
// below ~50k. The salt should be 16 random bytes per password.
[[nodiscard]] Bytes<32> pbkdf2_sha256(ByteSpan password, ByteSpan salt,
                                      std::uint32_t iterations) noexcept;

}  // namespace vpn::crypto
