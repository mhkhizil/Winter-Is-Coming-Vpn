// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/common/endpoint.hpp"

#include <charconv>
#include <cstddef>

// make_error() lives here, not in result.hpp (see result_helpers.hpp).
#include "vpn/common/result_helpers.hpp"

namespace vpn {
namespace {

[[nodiscard]] bool parse_port(std::string_view text, std::uint16_t& out) noexcept {
  if (text.empty() || text.size() > 5) return false;
  unsigned value = 0;
  const auto* first = text.data();
  const auto* last = text.data() + text.size();
  const auto res = std::from_chars(first, last, value);
  if (res.ec != std::errc{} || res.ptr != last) return false;
  if (value == 0 || value > 65535U) return false;
  out = static_cast<std::uint16_t>(value);
  return true;
}

[[nodiscard]] bool is_alnum_host_char(char c) noexcept {
  const bool digit = c >= '0' && c <= '9';
  const bool lower = c >= 'a' && c <= 'z';
  const bool upper = c >= 'A' && c <= 'Z';
  return digit || lower || upper || c == '-' || c == '.' || c == '_';
}

}  // namespace

std::string Endpoint::to_string() const {
  std::string out;
  const bool needs_brackets = host.find(':') != std::string::npos;
  if (needs_brackets) {
    out += '[';
    out += host;
    out += ']';
  } else {
    out += host;
  }
  out += ':';
  out += std::to_string(port);
  return out;
}

Status validate_host(std::string_view host) {
  if (host.empty()) return Status{ErrorCode::kInvalidArgument, "host is empty"};
  if (host == "*") return Status{};
  if (host.size() > 253) {
    return Status{ErrorCode::kInvalidArgument, "host is longer than 253 characters"};
  }
  // IPv6 literal, e.g. "::1" or "fe80::1"
  if (host.find(':') != std::string_view::npos) {
    for (const char c : host) {
      const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!hex && c != ':' && c != '.' && c != '%') {
        return Status{ErrorCode::kInvalidArgument, "invalid IPv6 literal"};
      }
    }
    return Status{};
  }
  for (const char c : host) {
    if (!is_alnum_host_char(c)) {
      return Status{ErrorCode::kInvalidArgument,
                    std::string{"invalid character in host: '"} + c + "'"};
    }
  }
  if (host.front() == '.' || host.back() == '.') {
    return Status{ErrorCode::kInvalidArgument, "host must not start or end with '.'"};
  }
  return Status{};
}

Result<Endpoint> parse_endpoint(std::string_view text) {
  if (text.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "endpoint is empty");
  }

  std::string_view host_part;
  std::string_view port_part;

  if (text.front() == '[') {
    const std::size_t close = text.find(']');
    if (close == std::string_view::npos) {
      return make_error(ErrorCode::kInvalidArgument, "missing ']' in IPv6 endpoint");
    }
    host_part = text.substr(1, close - 1);
    if (close + 1 >= text.size() || text[close + 1] != ':') {
      return make_error(ErrorCode::kInvalidArgument, "missing ':port' after IPv6 literal");
    }
    port_part = text.substr(close + 2);
  } else {
    const std::size_t colon = text.rfind(':');
    if (colon == std::string_view::npos) {
      return make_error(ErrorCode::kInvalidArgument,
                        "endpoint must be host:port (got '" + std::string{text} + "')");
    }
    host_part = text.substr(0, colon);
    port_part = text.substr(colon + 1);
    if (host_part.find(':') != std::string_view::npos) {
      return make_error(ErrorCode::kInvalidArgument, "IPv6 addresses must be wrapped in []");
    }
  }

  Endpoint endpoint;
  // An empty host (":8080", documented in endpoint.hpp as "all interfaces") is
  // the wildcard form, not an invalid host: Endpoint::is_wildcard() and
  // HttpServer::listen() both treat an empty host as "bind every address".
  // Only a non-empty host is a DNS name / IP literal that needs validating.
  if (!host_part.empty()) {
    if (const Status st = validate_host(host_part); !st.ok()) return st;
    endpoint.host.assign(host_part);
  }

  if (!parse_port(port_part, endpoint.port)) {
    return make_error(ErrorCode::kInvalidArgument,
                      "invalid port '" + std::string{port_part} + "' (expected 1-65535)");
  }
  return endpoint;
}

}  // namespace vpn
