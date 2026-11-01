// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Runtime configuration for vpnd.
//
// Format: a deliberately tiny TOML subset - `key = value`, `[section]` headers,
// `#` comments - so that M0 has zero dependencies. Values may be overridden by
// environment variables (12-factor; see .env.example). At M3 this file is parsed
// by toml++ behind the same struct, and unknown keys become errors.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "vpn/common/endpoint.hpp"
#include "vpn/common/result.hpp"

namespace vpn::config {

struct TlsConfig {
  std::string cert_file{};
  std::string key_file{};
  std::string client_ca_file{};  // set => require and verify client certs (mTLS)
};

struct RateLimitConfig {
  std::uint32_t requests_per_second{100};
  std::uint32_t burst{200};
};

struct LogConfig {
  std::string level{"info"};
  std::string format{"json"};  // json | text
};

struct HttpConfig {
  Endpoint bind{"127.0.0.1", 8080};
  std::uint32_t request_timeout_secs{10};
  std::uint32_t max_connections{64};
  std::size_t max_header_bytes{8192};
};

struct ServerConfig {
  std::string environment{"development"};  // development | staging | production
  bool dev_mode{false};
  LogConfig log{};
  HttpConfig http{};
  Endpoint metrics_bind{"127.0.0.1", 9100};
  TlsConfig tls{};
  RateLimitConfig rate_limit{};
  std::string admin_token{};
};

// Parses `text` into a ServerConfig. Unknown keys are an error so that a typo
// in a production config fails the deploy instead of silently defaulting.
[[nodiscard]] Result<ServerConfig> parse(std::string_view text);

[[nodiscard]] Result<ServerConfig> load_file(const std::filesystem::path& path);

// Applies VPN_* environment overrides on top of `cfg` (mutates and returns it).
[[nodiscard]] Status apply_environment(ServerConfig& cfg);

// Cross-field validation applied after parsing and env overrides: production
// without TLS, dev_mode in production, empty admin token, etc.
[[nodiscard]] Status validate(const ServerConfig& cfg);

// Renders the effective config with secrets redacted (for `--print-config`).
[[nodiscard]] std::string to_string(const ServerConfig& cfg);

}  // namespace vpn::config
