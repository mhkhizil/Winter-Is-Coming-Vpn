// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// CSPRNG wrapper. Every key, index, cookie secret and nonce in the server comes
// from here; there is no fallback to std::random_device.
//
// Sources: BCryptGenRandom (Windows), getrandom(2) (Linux >=3.17), /dev/urandom
// (last resort). The functions fail closed: if the OS RNG cannot be reached we
// return false and the caller must refuse to start or refuse the handshake.
#pragma once

#include <cstdint>

#include "vpn/common/bytes.hpp"

namespace vpn::crypto {

// Fills `out` completely. Returns false only if the OS RNG failed.
[[nodiscard]] bool fill_random(MutableByteSpan out) noexcept;

// Uniform value in [0, bound). Uses rejection sampling, never modulo bias.
// `bound` must be > 0 and <= 2^31.
[[nodiscard]] bool random_below(std::uint32_t bound, std::uint32_t& out) noexcept;

// A non-zero 32-bit session index (0 is never used as a live index).
[[nodiscard]] bool random_index(std::uint32_t& out) noexcept;

}  // namespace vpn::crypto
