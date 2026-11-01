// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/config/config.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "vpn/common/result_helpers.hpp"

namespace vpn::config {
namespace {

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
  const auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
  return s;
}

[[nodiscard]] std::string unquote(std::string_view raw) {
  if (raw.size() >= 2 && ((raw.front() == '"' && raw.back() == '"') ||
                          (raw.front() == '\'' && raw.back() == '\''))) {
    return std::string{raw.substr(1, raw.size() - 2)};
  }
  return std::string{raw};
}

[[nodiscard]] bool parse_bool(std::string_view raw, bool& out) noexcept {
  if (raw == "true" || raw == "yes" || raw == "1" || raw == "on") {
    out = true;
    return true;
  }
  if (raw == "false" || raw == "no" || raw == "0" || raw == "off") {
    out = false;
    return true;
  }
  return false;
}

[[nodiscard]] bool parse_u32(std::string_view raw, std::uint32_t& out) noexcept {
  if (raw.empty()) return false;
  std::uint64_t acc = 0;
  for (const char c : raw) {
    if (c < '0' || c > '9') return false;
    acc = acc * 10U + static_cast<std::uint64_t>(c - '0');
    if (acc > 0xFFFFFFFFULL) return false;
  }
  out = static_cast<std::uint32_t>(acc);
  return true;
}

// vpnd reads its environment once, before any thread is started.
[[nodiscard]] const char* env(const char* name) noexcept {
#if defined(_WIN32)
  char* buf = nullptr;
  std::size_t len = 0;
  if (_dupenv_s(&buf, &len, name) != 0 || buf == nullptr) return nullptr;
  return buf;  // one small startup allocation per variable; freed at exit
#else
  return std::getenv(name);
#endif
}

}  // namespace

Result<ServerConfig> parse(std::string_view text) {
  ServerConfig cfg;
  std::string section;

  std::size_t line_no = 0;
  std::size_t pos = 0;
  while (pos <= text.size()) {
    const std::size_t nl = text.find('\n', pos);
    const std::string_view raw_line =
        nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
    pos = (nl == std::string_view::npos) ? text.size() + 1 : nl + 1;
    ++line_no;

    std::string_view line = raw_line;
    const std::size_t hash = line.find('#');
    if (hash != std::string_view::npos) line = line.substr(0, hash);
    line = trim(line);
    if (line.empty()) continue;

    if (line.front() == '[' && line.back() == ']') {
      section = std::string{trim(line.substr(1, line.size() - 2))};
      continue;
    }

    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) {
      return make_error(ErrorCode::kInvalidArgument,
                        "line " + std::to_string(line_no) + ": expected key = value");
    }
    const std::string key{trim(line.substr(0, eq))};
    const std::string value = unquote(trim(line.substr(eq + 1)));
    const std::string qualified = section.empty() ? key : section + "." + key;

    const auto fail = [&](const char* why) {
      return make_error(ErrorCode::kInvalidArgument,
                        "line " + std::to_string(line_no) + " (" + qualified + "): " + why);
    };

    if (qualified == "environment") {
      cfg.environment = value;
    } else if (qualified == "dev_mode") {
      if (!parse_bool(value, cfg.dev_mode)) return fail("expected a boolean");
    } else if (qualified == "log.level") {
      cfg.log.level = value;
    } else if (qualified == "log.format") {
      cfg.log.format = value;
    } else if (qualified == "http.bind") {
      VPN_TRY(auto parsed, parse_endpoint(value));
      cfg.http.bind = parsed;
    } else if (qualified == "http.request_timeout_secs") {
      if (!parse_u32(value, cfg.http.request_timeout_secs)) return fail("expected a number");
    } else if (qualified == "http.max_connections") {
      if (!parse_u32(value, cfg.http.max_connections)) return fail("expected a number");
    } else if (qualified == "http.max_header_bytes") {
      std::uint32_t v = 0;
      if (!parse_u32(value, v)) return fail("expected a number");
      cfg.http.max_header_bytes = v;
    } else if (qualified == "metrics.bind") {
      VPN_TRY(auto parsed, parse_endpoint(value));
      cfg.metrics_bind = parsed;
    } else if (qualified == "tls.cert_file") {
      cfg.tls.cert_file = value;
    } else if (qualified == "tls.key_file") {
      cfg.tls.key_file = value;
    } else if (qualified == "tls.client_ca_file") {
      cfg.tls.client_ca_file = value;
    } else if (qualified == "rate_limit.requests_per_second") {
      if (!parse_u32(value, cfg.rate_limit.requests_per_second)) return fail("expected a number");
    } else if (qualified == "rate_limit.burst") {
      if (!parse_u32(value, cfg.rate_limit.burst)) return fail("expected a number");
    } else if (qualified == "admin_token") {
      cfg.admin_token = value;
    } else {
      return fail("unknown configuration key");
    }
  }
  return cfg;
}

Result<ServerConfig> load_file(const std::filesystem::path& path) {
  std::ifstream in{path, std::ios::binary};
  if (!in) {
    return make_error(ErrorCode::kNotFound, "cannot open config file: " + path.string());
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return parse(buffer.str());
}

Status apply_environment(ServerConfig& cfg) {
  if (const char* v = env("VPN_ENV")) cfg.environment = v;
  if (const char* v = env("VPN_HTTP_BIND")) {
    VPN_TRY(auto parsed, parse_endpoint(v));
    cfg.http.bind = parsed;
  }
  if (const char* v = env("VPN_METRICS_BIND")) {
    VPN_TRY(auto parsed, parse_endpoint(v));
    cfg.metrics_bind = parsed;
  }
  if (const char* v = env("VPN_LOG_LEVEL")) cfg.log.level = v;
  if (const char* v = env("VPN_ADMIN_TOKEN")) cfg.admin_token = v;
  if (const char* v = env("VPN_DEV_MODE")) {
    if (!parse_bool(v, cfg.dev_mode)) {
      return Status{ErrorCode::kInvalidArgument, "VPN_DEV_MODE must be true or false"};
    }
  }
  if (const char* v = env("VPN_TLS_CERT_FILE")) cfg.tls.cert_file = v;
  if (const char* v = env("VPN_TLS_KEY_FILE")) cfg.tls.key_file = v;
  if (const char* v = env("VPN_TLS_CLIENT_CA_FILE")) cfg.tls.client_ca_file = v;
  return Status{};
}

Status validate(const ServerConfig& cfg) {
  if (cfg.environment != "development" && cfg.environment != "staging" &&
      cfg.environment != "production") {
    return Status{ErrorCode::kInvalidArgument,
                  "environment must be development, staging or production"};
  }
  if (cfg.environment == "production" && cfg.dev_mode) {
    return Status{ErrorCode::kInvalidArgument, "dev_mode must be false in production"};
  }
  if (cfg.http.max_header_bytes < 1024 || cfg.http.max_header_bytes > (1U << 20U)) {
    return Status{ErrorCode::kInvalidArgument, "http.max_header_bytes must be 1 KiB..1 MiB"};
  }
  if (cfg.http.request_timeout_secs == 0 || cfg.http.request_timeout_secs > 300) {
    return Status{ErrorCode::kInvalidArgument, "http.request_timeout_secs must be 1..300"};
  }
  if (cfg.http.max_connections < 1 || cfg.http.max_connections > 1024) {
    return Status{ErrorCode::kInvalidArgument, "http.max_connections must be 1..1024"};
  }
  if ((!cfg.tls.cert_file.empty()) != (!cfg.tls.key_file.empty())) {
    return Status{ErrorCode::kInvalidArgument,
                  "tls.cert_file and tls.key_file must be set together"};
  }
  if (cfg.environment == "production" && cfg.tls.cert_file.empty()) {
    return Status{ErrorCode::kInvalidArgument, "TLS is required in production"};
  }
  // The dev bootstrap token must never be a short, guessable string; empty means
  // "unset", which is the normal production state (JWT/OIDC only).
  if (!cfg.admin_token.empty() && cfg.admin_token.size() < 32) {
    return Status{ErrorCode::kInvalidArgument,
                  "admin_token must be at least 32 characters, or empty when unused"};
  }
  return Status{};
}

std::string to_string(const ServerConfig& cfg) {
  std::ostringstream out;
  out << "environment = \"" << cfg.environment << "\"\n"
      << "dev_mode = " << (cfg.dev_mode ? "true" : "false") << "\n"
      << "[log]\nlevel = \"" << cfg.log.level << "\"\nformat = \"" << cfg.log.format << "\"\n"
      << "[http]\nbind = \"" << cfg.http.bind.to_string() << "\"\n"
      << "request_timeout_secs = " << cfg.http.request_timeout_secs << "\n"
      << "max_header_bytes = " << cfg.http.max_header_bytes << "\n"
      << "[metrics]\nbind = \"" << cfg.metrics_bind.to_string() << "\"\n"
      << "[tls]\ncert_file = \"" << cfg.tls.cert_file << "\"\n"
      << "key_file = \"" << (cfg.tls.key_file.empty() ? "" : "<redacted>") << "\"\n"
      << "client_ca_file = \"" << cfg.tls.client_ca_file << "\"\n"
      << "admin_token = \"" << (cfg.admin_token.empty() ? "" : "<redacted>") << "\"\n";
  return out.str();
}

}  // namespace vpn::config
