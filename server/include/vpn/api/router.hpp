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
};

class Router {
 public:
  explicit Router(RouterOptions options);

  [[nodiscard]] controlplane::HttpResponse handle(const controlplane::HttpRequest& request);

 private:
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
