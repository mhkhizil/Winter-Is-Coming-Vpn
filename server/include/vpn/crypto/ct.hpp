// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Constant-time primitives. Every secret-dependent comparison or selection in
// the server MUST go through this header; plain ==/memcmp on key material is a
// CI-blocking offence (see the grep gate in .github/workflows/ci-server.yml).
#pragma once

#include <cstddef>

#include "vpn/common/bytes.hpp"

namespace vpn::ct {

// Compares without early exit. Length mismatch is not secret-dependent, so it
// is reported directly.
[[nodiscard]] bool equal(ByteSpan a, ByteSpan b) noexcept;

// 0xFF if x is non-zero, 0x00 otherwise, without branching.
[[nodiscard]] std::uint8_t is_nonzero_u8(std::uint32_t x) noexcept;

// dst = cond ? a : b, byte-wise, for equally sized spans.
void select(MutableByteSpan dst, ByteSpan a, ByteSpan b, bool cond) noexcept;

// Unconditional, non-elidable wipe of secrets (OPENSSL_cleanse semantics).
void cleanse(MutableByteSpan span) noexcept;

}  // namespace vpn::ct
