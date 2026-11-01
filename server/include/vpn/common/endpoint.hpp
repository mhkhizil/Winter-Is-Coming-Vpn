// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// host:port parsing shared by config and the socket layer.
// Accepted forms: "127.0.0.1:8080", "0.0.0.0:8080", "[::]:8080", ":8080",
// "localhost:8080". A bare ":8080" means "all interfaces".
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "vpn/common/result.hpp"

namespace vpn {

struct Endpoint {
  std::string host{};
  std::uint16_t port{0};

  [[nodiscard]] bool is_wildcard() const noexcept { return host.empty() || host == "*"; }
  [[nodiscard]] std::string to_string() const;
};

// Returns kInvalidArgument with a message that names the offending input.
[[nodiscard]] Result<Endpoint> parse_endpoint(std::string_view text);

// Validates an IP literal or DNS name without resolving it. Used by config
// validation so that a typo fails at startup instead of on first accept.
[[nodiscard]] Status validate_host(std::string_view host);

}  // namespace vpn
