// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// REST router for the control plane. It is mounted into HttpServer with
// set_router(), so the HTTP layer stays free of business logic and the API can be
// unit tested without a socket.
//
// Contract: every response is either JSON with the documented shape or an
// RFC 9457 problem+json document carrying a stable `code`.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "vpn/api/store.hpp"
#include "vpn/controlplane/http_server.hpp"

namespace vpn::api {

struct RouterOptions {
  Store* store{nullptr};
  std::uint32_t token_ttl_seconds{3600};
  std::uint32_t rate_limit_per_second{20};
  std::uint32_t rate_limit_burst{40};
  // Renewal reminders (ADR-0011). Empty host means the endpoint reports that
  // email is not configured instead of pretending to send.
  std::string smtp_host{};
  std::uint16_t smtp_port{25};
  std::string smtp_from{};
  std::string smtp_username{};
  std::string smtp_password{};
  bool smtp_dry_run{false};
};

class Router {
 public:
  explicit Router(RouterOptions options);

  [[nodiscard]] controlplane::HttpResponse handle(const controlplane::HttpRequest& request);

 private:
  // --- login throttling (per account) ---------------------------------------
  // Counted per email, not per IP: the attacker rotates addresses, the account
  // they are attacking does not. Locking happens BEFORE the password hash is
  // computed, so a locked account costs no CPU at all.
  struct LoginState {
    std::uint32_t failures{0};
    std::int64_t window_start_ms{0};
    std::int64_t locked_until_ms{0};
  };
  [[nodiscard]] bool login_locked(const std::string& email) const;
  void login_failed(const std::string& email);
  void login_succeeded(const std::string& email);
  mutable std::mutex login_mutex_;
  std::unordered_map<std::string, LoginState> login_attempts_;
  struct Bucket {
    double tokens{0};
    std::int64_t last_refill_ms{0};
  };

  [[nodiscard]] bool allow(const std::string& client_ip);
  [[nodiscard]] Result<Principal> authenticate(const controlplane::HttpRequest& request) const;

  static controlplane::HttpResponse json(int status, const std::string& body);
  static controlplane::HttpResponse problem(int status, const char* title, const char* code,
                                            const std::string& detail = {});
  static controlplane::HttpResponse text(int status, const std::string& body);
  [[nodiscard]] static bool field(const std::string& json_body, const char* name,
                                  std::string& out);

  RouterOptions options_{};
  std::mutex buckets_mutex_;
  std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace vpn::api
