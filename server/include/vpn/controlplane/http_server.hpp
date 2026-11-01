// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Minimal, dependency-free HTTP/1.1 server used by M0 for liveness, readiness
// and metrics. It is intentionally single-threaded and closes every connection:
// the control-plane API is replaced by Drogon at M3 behind this same interface
// (see docs/ARCHITECTURE.md "Ports and adapters").
//
// Hardening baked in from day one (because health endpoints are internet-facing
// on some deployments): bounded request header size, an absolute deadline for
// receiving the header block, no request body parsing, method allow-list, no
// server banner beyond the product name, and a per-route counter whose label
// values come from the router's own vocabulary (never from the raw request).
//
// Known limit, stated plainly: the accept loop is single-threaded, so a client
// that sends a partial request delays *every* other request for up to
// `request_timeout_secs`. That is acceptable for M0 only because the listener is
// expected to sit behind a loopback/reverse-proxy boundary; it is not a
// public-internet posture. See docs/ARCHITECTURE.md section 7.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "vpn/common/endpoint.hpp"
#include "vpn/common/result.hpp"
#include "vpn/obs/metrics.hpp"

namespace vpn::controlplane {

struct HttpRequest {
  std::string method{};
  std::string path{};      // without query string
  std::string query{};     // without the leading '?'
  std::string client_ip{};
};

struct HttpResponse {
  int status{200};
  std::string content_type{"application/json; charset=utf-8"};
  std::string body{};
  bool keep_alive{false};
};

using Handler = std::function<HttpResponse(const HttpRequest&)>;

// Snapshot of process state exposed to /readyz. Set by main() so that the HTTP
// layer never reaches into globals.
struct HealthState {
  std::atomic<bool> accepting_connections{false};
  std::atomic<bool> shutting_down{false};
  std::atomic<std::uint64_t> started_at_unix{0};
  std::atomic<std::uint64_t> requests_total{0};
  std::atomic<std::uint64_t> requests_rejected{0};
};

class HttpServer {
 public:
  struct Options {
    Endpoint bind{};
    std::uint32_t request_timeout_secs{10};
    std::size_t max_header_bytes{8192};
  };

  HttpServer(Options options, HealthState& health, obs::Metrics& metrics);
  ~HttpServer();

  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  // Binds and listens. Must be called before serve().
  [[nodiscard]] Status listen();

  // Blocking accept loop; returns when stop() is called or on fatal error.
  [[nodiscard]] Status serve();

  // Safe to call from a signal handler or another thread.
  void stop() noexcept;

  [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }

 private:
  void handle_connection(std::intptr_t client_fd);
  [[nodiscard]] HttpResponse route(const HttpRequest& request);

  [[nodiscard]] static std::string json_escape(std::string_view value);

  Options options_;
  HealthState& health_;
  obs::Metrics& metrics_;
  std::string route_table_;  // reserved for M3's OpenAPI-driven router

  int listen_fd_;
  std::uint16_t bound_port_{0};
  std::atomic<bool> stopping_{false};
  // The connection currently being served (or -1). stop() shuts it down so that
  // a shutdown request does not have to wait for the request timeout.
  std::atomic<std::intptr_t> active_client_{-1};
};

}  // namespace vpn::controlplane
