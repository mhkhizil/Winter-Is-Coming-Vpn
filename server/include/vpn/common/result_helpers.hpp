// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Construction helpers. Kept in a separate header so that result.hpp (which is
// included almost everywhere) stays free of <string> traffic and macros.
#pragma once

#include <string>
#include <type_traits>
#include <utility>

#include "vpn/common/result.hpp"

namespace vpn {

[[nodiscard]] inline VoidResult ok() noexcept { return VoidResult{}; }

template <class T>
[[nodiscard]] inline Result<std::decay_t<T>> make_ok(T&& value) {
  return Result<std::decay_t<T>>(std::forward<T>(value));
}

[[nodiscard]] inline Status make_error(ErrorCode code, std::string message = {}) {
  return Status{code, std::move(message)};
}

}  // namespace vpn

// Propagates an error out of a function that returns vpn::Result<T>:
//   VPN_TRY(auto cfg, load_config(path));
#define VPN_TRY_CONCAT_INNER(a, b) a##b
#define VPN_TRY_CONCAT(a, b) VPN_TRY_CONCAT_INNER(a, b)
#define VPN_TRY(lhs, expr)                                                 \
  auto VPN_TRY_CONCAT(vpn_try_, __LINE__) = (expr);                        \
  if (!VPN_TRY_CONCAT(vpn_try_, __LINE__)) {                               \
    return VPN_TRY_CONCAT(vpn_try_, __LINE__).error();                     \
  }                                                                        \
  lhs = *std::move(VPN_TRY_CONCAT(vpn_try_, __LINE__))
