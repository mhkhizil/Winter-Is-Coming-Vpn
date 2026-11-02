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
#include <vector>

#include "vpn/common/endpoint.hpp"
#include "vpn/common/result.hpp"

namespace vpn::config {

struct TlsConfig {
  // Option A (default in production): TLS is terminated by a reverse proxy
  // (nginx/Caddy/ALB) and vpnd speaks HTTP/1.1 on a private interface. This is the
  // most compatible and the fastest option: every client sees a normal TLS 1.3
  // endpoint (browsers, curl, official SDKs, HTTP/2 and HTTP/3 offload), the
  // handshake is done by code that is far better audited than anything we would
  // write, and the app keeps zero crypto dependencies. See ADR-0009.
  bool terminated_by_proxy{false};

  // Reject any request that did not arrive over TLS. Requires
  // `terminated_by_proxy` (we cannot detect TLS ourselves) and makes a
  // misconfigured proxy a loud 403 instead of a silent cleartext API.
  bool require_https{false};

  // CIDRs allowed to assert `X-Forwarded-Proto`. Anything outside this list is
  // treated as a direct client: its `X-Forwarded-Proto` header is ignored, so a
  // direct attacker cannot claim to be HTTPS.
  std::vector<std::string> trusted_proxies{"127.0.0.1/32", "::1/128"};

  // Emit Strict-Transport-Security on responses that did arrive over TLS.
  bool hsts{false};
  std::uint32_t hsts_max_age_secs{31536000};

  // Option B (single binary, no proxy): certificate material. Parsed and
  // validated, but TLS is not terminated in-process - see ADR-0009 for why an
  // in-tree TLS stack is not the compatible choice.
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

// Renewal reminders (ADR-0011). Empty host disables them; see
// vpn/include/vpn/notify/smtp.hpp for why this speaks plain SMTP to a local relay
// rather than doing TLS itself.
struct SmtpConfig {
  std::string host{};
  std::uint16_t port{25};
  std::string from{};
  std::string username{};
  std::string password{};
  bool dry_run{false};
  // Days before expiry at which a reminder is sent. One run per bucket, then the
  // account is marked so a daily job never repeats itself.
  std::vector<std::uint32_t> reminder_days{7, 1};
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
  SmtpConfig smtp{};
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
