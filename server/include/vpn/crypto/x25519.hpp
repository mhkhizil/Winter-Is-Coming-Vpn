// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// X25519 (RFC 7748) - the Diffie-Hellman primitive inside the WireGuard
// handshake. Implemented here (rather than pulled from BoringSSL) so the server
// builds with zero external dependencies; validated against the RFC 7748 test
// vectors and against Python's `cryptography`/`nacl` in tests/golden.
//
// Constant-time: the scalar multiplication is a fixed-window Montgomery ladder
// with no secret-dependent branches or memory indexing.
#pragma once

#include <cstddef>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

inline constexpr std::size_t kX25519KeySize = 32;

using X25519PrivateKey = Bytes<kX25519KeySize>;
using X25519PublicKey = Bytes<kX25519KeySize>;

struct X25519KeyPair {
  X25519PrivateKey private_key{};
  X25519PublicKey public_key{};
};

// Generates a clamped private key and its public key. Returns false if the OS
// RNG failed.
[[nodiscard]] bool x25519_generate(X25519KeyPair& out) noexcept;

// out = X25519(scalar, point). Returns false when the result is all-zero, i.e.
// the peer sent a low-order point - RFC 7748 §6.1 requires callers to reject it.
[[nodiscard]] bool x25519(X25519PublicKey& out, const X25519PrivateKey& scalar,
                          const X25519PublicKey& point) noexcept;

// out = X25519(scalar, 9) - derives a public key from a private key.
[[nodiscard]] bool x25519_base(X25519PublicKey& out, const X25519PrivateKey& scalar) noexcept;

// True if `point` is one of the eight low-order points (all-zero DH output).
[[nodiscard]] bool x25519_is_low_order(const X25519PublicKey& point) noexcept;

}  // namespace vpn::crypto
