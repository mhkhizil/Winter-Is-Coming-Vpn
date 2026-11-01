// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Dependency-free HTTP/1.1 server. Two instances are started by vpnd:
//   * the API listener (http.bind)   - health, readiness, /debug, /api/v1
//   * the metrics listener (metrics.bind) - /metrics + health only, so scrape
//     traffic never shares a socket with the public API (and can be firewalled
//     separately).
//
// Concurrency model: one accept loop hands each accepted socket to a worker
// thread, bounded by `max_concurrent_connections`. A slow client can therefore
// only occupy its own worker, never the accept loop - the starvation the M0
// single-threaded loop had is gone. Everything is closed after one request
// (Connection: close), which keeps the state machine small enough to audit.
//
// Hardening: bounded header size, absolute header deadline (408), method
// allow-list, no request-body parsing, no banner beyond the product name, and
// metric labels come from the router's own vocabulary, never from the raw path.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "vpn/common/endpoint.hpp"
#include "vpn/common/result.hpp"
#include "vpn/obs/metrics.hpp"

namespace vpn::controlplane {

struct HttpRequest {
  std::string method{};
  std::string path{};      // without query string
  std::string query{};     // without the leading '?'
  std::string client_ip{};
  std::string client_port{};  // as text, for rate limiting / logging
  std::string body{};         // bounded request body (max 8 KiB), for the REST layer
  std::string authorization{};  // raw Authorization header value, if present
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
  // Refreshed by the reload thread after a SIGHUP so /readyz can show it.
  std::atomic<std::uint64_t> config_generation{1};
};

class HttpServer {
 public:
  struct Options {
    Endpoint bind{};
    std::uint32_t request_timeout_secs{10};
    std::size_t max_header_bytes{8192};
    // true => only /metrics, /healthz, /readyz are served (metrics listener).
    bool metrics_only{false};
    // Enables /debug/* endpoints (never in production).
    bool dev_mode{false};
    std::uint32_t max_concurrent_connections{64};
    std::string service_name{"vpnd"};
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

  // Mounts the REST API. Anything that is not a built-in route is delegated to
  // this hook; nullptr restores the built-in 404 behaviour. The hook must be
  // thread-safe: it is called from several worker threads.
  void set_router(Handler hook) { router_ = std::move(hook); }

  [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }
  [[nodiscard]] std::uint32_t active_connections() const noexcept {
    return active_connections_.load(std::memory_order_relaxed);
  }

 private:
  void handle_connection(std::intptr_t client_fd);
  [[nodiscard]] HttpResponse route(const HttpRequest& request);
  [[nodiscard]] HttpResponse debug_route(const HttpRequest& request);

  [[nodiscard]] static std::string json_escape(std::string_view value);

  Options options_;
  HealthState& health_;
  obs::Metrics& metrics_;
  Handler router_{};

  int listen_fd_;
  std::uint16_t bound_port_{0};
  std::atomic<bool> stopping_{false};
  std::atomic<std::uint32_t> active_connections_{0};

  // Fixed worker pool created by serve() and joined by serve() on exit. The
  // accept loop only enqueues, so a slow client occupies one worker at most.
  struct PendingConnection {
    std::intptr_t fd{-1};
  };
  void run_worker() noexcept;

  mutable std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::deque<PendingConnection> queue_;
  bool pool_stop_{false};
  std::vector<std::thread> workers_;

  // The connection currently being served (or -1). stop() shuts it down so that
  // a shutdown request does not have to wait for the request timeout.
  std::atomic<std::intptr_t> active_client_{-1};
};

}  // namespace vpn::controlplane

