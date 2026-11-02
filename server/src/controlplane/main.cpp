// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// vpnd - control-plane daemon.
//
// M0 responsibility: prove the process contract that every later milestone
// depends on - config resolution (file -> env -> flags), structured logging,
// signal handling, /healthz + /readyz + /metrics, and clean exit codes.
//
// Exit codes (stable, part of the CLI contract; see docs/RUNBOOK.md):
//   0 success   1 generic failure   2 usage/config error   3 runtime error
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "vpn/api/router.hpp"
#include "vpn/api/store.hpp"
#include "vpn/common/endpoint.hpp"
#include "vpn/common/log.hpp"
#include "vpn/common/result.hpp"
#include "vpn/config/config.hpp"
#include "vpn/controlplane/http_server.hpp"
#include "vpn/obs/metrics.hpp"

#ifndef VPN_VERSION
#define VPN_VERSION "0.0.0"
#endif

namespace {

std::atomic<bool> g_stop_requested{false};
std::atomic<bool> g_reload_requested{false};

extern "C" void handle_signal(int /*sig*/) {
  // Async-signal-safe work only: set a flag, let the main loop unwind.
  g_stop_requested.store(true, std::memory_order_relaxed);
}

#if defined(SIGHUP)
extern "C" void handle_sighup(int /*sig*/) {
  // Reload request; the maintenance thread re-reads and validates the file.
  g_reload_requested.store(true, std::memory_order_relaxed);
}
#endif

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;
constexpr int kExitRuntime = 3;

void print_usage(FILE* out) {
  std::fprintf(out,
               "vpnd %s - VPN control plane\n\n"
               "Usage: vpnd [options]\n\n"
               "Options:\n"
               "  --config <path>        Load configuration from a TOML-subset file\n"
               "  --bind <host:port>     Override http.bind\n"
               "  --metrics-bind <h:p>   Override metrics.bind\n"
               "  --log-level <level>    trace|debug|info|warn|error|off\n"
               "  --print-config         Print effective config (secrets redacted) and exit\n"
               "  --validate-config      Validate configuration and exit\n"
               "  --print-version        Print version information and exit\n"
               "  --help                 Show this help and exit\n\n"
               "Exit codes: 0 ok, 1 failure, 2 usage/config error, 3 runtime error\n",
               VPN_VERSION);
}

[[nodiscard]] bool take_value(int argc, char** argv, int& i, std::string& out) {
  if (i + 1 >= argc) return false;
  out = argv[++i];
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path;
  std::string bind_override;
  std::string metrics_override;
  std::string log_level_override;
  bool print_config = false;
  bool validate_only = false;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};
    if (arg == "--help" || arg == "-h") {
      print_usage(stdout);
      return kExitOk;
    }
    if (arg == "--print-version" || arg == "-v") {
      std::printf("vpnd %s (wire v1, protocol 1)\n", VPN_VERSION);
      return kExitOk;
    }
    if (arg == "--print-config") {
      print_config = true;
      continue;
    }
    if (arg == "--validate-config") {
      validate_only = true;
      continue;
    }
    if (arg == "--config") {
      if (!take_value(argc, argv, i, config_path)) {
        std::fprintf(stderr, "error: --config requires a path\n");
        return kExitUsage;
      }
      continue;
    }
    if (arg == "--bind") {
      if (!take_value(argc, argv, i, bind_override)) {
        std::fprintf(stderr, "error: --bind requires host:port\n");
        return kExitUsage;
      }
      continue;
    }
    if (arg == "--metrics-bind") {
      if (!take_value(argc, argv, i, metrics_override)) {
        std::fprintf(stderr, "error: --metrics-bind requires host:port\n");
        return kExitUsage;
      }
      continue;
    }
    if (arg == "--log-level") {
      if (!take_value(argc, argv, i, log_level_override)) {
        std::fprintf(stderr, "error: --log-level requires a level\n");
        return kExitUsage;
      }
      continue;
    }
    std::fprintf(stderr, "error: unknown argument '%.*s'\n", static_cast<int>(arg.size()),
                 arg.data());
    print_usage(stderr);
    return kExitUsage;
  }

  // --- configuration: file -> environment -> explicit flags -----------------
  vpn::config::ServerConfig cfg;
  if (!config_path.empty()) {
    auto loaded = vpn::config::load_file(config_path);
    if (!loaded) {
      std::fprintf(stderr, "error: %s\n", loaded.error().to_string().c_str());
      return kExitUsage;
    }
    cfg = *loaded;
  }

  if (const vpn::Status st = vpn::config::apply_environment(cfg); !st.ok()) {
    std::fprintf(stderr, "error: %s\n", st.to_string().c_str());
    return kExitUsage;
  }

  if (!bind_override.empty()) {
    auto parsed = vpn::parse_endpoint(bind_override);
    if (!parsed) {
      std::fprintf(stderr, "error: --bind: %s\n", parsed.error().to_string().c_str());
      return kExitUsage;
    }
    cfg.http.bind = *parsed;
  }
  if (!metrics_override.empty()) {
    auto parsed = vpn::parse_endpoint(metrics_override);
    if (!parsed) {
      std::fprintf(stderr, "error: --metrics-bind: %s\n", parsed.error().to_string().c_str());
      return kExitUsage;
    }
    cfg.metrics_bind = *parsed;
  }
  if (!log_level_override.empty()) cfg.log.level = log_level_override;

  if (const vpn::Status st = vpn::config::validate(cfg); !st.ok()) {
    std::fprintf(stderr, "error: %s\n", st.to_string().c_str());
    return kExitUsage;
  }

  if (print_config) {
    std::fputs(vpn::config::to_string(cfg).c_str(), stdout);
    return kExitOk;
  }
  if (validate_only) {
    std::printf("configuration OK (environment=%s)\n", cfg.environment.c_str());
    return kExitOk;
  }

  // --- logging -------------------------------------------------------------
  vpn::log::Level level = vpn::log::Level::kInfo;
  if (!vpn::log::parse_level(cfg.log.level, level)) {
    std::fprintf(stderr, "error: invalid log level '%s'\n", cfg.log.level.c_str());
    return kExitUsage;
  }
  vpn::log::set_level(level);
  vpn::log::set_service("vpnd");
  vpn::log::info("vpnd starting", "version", VPN_VERSION);

  if (cfg.dev_mode) {
    vpn::log::warn("dev_mode is enabled - never use this in production");
  }

  // --- runtime -------------------------------------------------------------
  vpn::obs::Metrics metrics;
  metrics.set_gauge("vpn_build_info", 1, {{"version", VPN_VERSION}, {"wire", "1"}});

  vpn::controlplane::HealthState health;
  vpn::controlplane::HealthState metrics_health;
  const auto started_unix = static_cast<std::uint64_t>(std::time(nullptr));
  health.started_at_unix.store(started_unix, std::memory_order_relaxed);
  metrics_health.started_at_unix.store(started_unix, std::memory_order_relaxed);

  vpn::controlplane::HttpServer::Options api_options;
  api_options.bind = cfg.http.bind;
  api_options.request_timeout_secs = cfg.http.request_timeout_secs;
  api_options.max_header_bytes = cfg.http.max_header_bytes;
  api_options.max_concurrent_connections = cfg.http.max_connections;
  api_options.dev_mode = cfg.dev_mode;
  api_options.service_name = "vpnd";
  // TLS is terminated by the edge proxy (ADR-0009); these three knobs decide how
  // strictly we believe it. `require_https` turns a plaintext request that did not
  // come through the proxy into a 403 instead of a silent cleartext API.
  api_options.tls.require_https = cfg.tls.require_https;
  api_options.tls.hsts = cfg.tls.hsts;
  api_options.tls.hsts_max_age_secs = cfg.tls.hsts_max_age_secs;
  api_options.tls.trusted_proxies = cfg.tls.trusted_proxies;

  // Install the handlers before the socket exists: a SIGTERM in the window
  // between listen() and serve() would otherwise take the default action.
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);
#if defined(SIGHUP)
  std::signal(SIGHUP, handle_sighup);
#endif
#if defined(SIGPIPE)
  std::signal(SIGPIPE, SIG_IGN);  // a client that vanishes must not kill vpnd
#endif

  auto server = std::make_unique<vpn::controlplane::HttpServer>(api_options, health, metrics);
  if (const vpn::Status st = server->listen(); !st.ok()) {
    vpn::log::error("failed to listen", "error", st.to_string());
    return kExitRuntime;
  }

  // --- control-plane state and REST API -------------------------------------
  // A file-backed store keeps the deployment to a single binary; the same
  // interfaces are implemented by the PostgreSQL backend described in
  // server/migrations/0001_init.sql.
  vpn::api::StoreOptions store_options;
  const char* store_path = std::getenv("VPN_STORE_PATH");
  store_options.path = store_path == nullptr ? std::string{"vpn-control.log"} : store_path;
  const char* endpoint_host = std::getenv("VPN_ENDPOINT_HOST");
  store_options.endpoint_host =
      endpoint_host == nullptr ? std::string{"127.0.0.1"} : endpoint_host;
  const char* dns = std::getenv("VPN_DNS");
  if (dns != nullptr) store_options.dns = dns;

  auto store = vpn::api::Store::open(store_options);
  if (!store) {
    vpn::log::error("cannot open the control-plane store", "error",
                    store.error().to_string());
    return kExitRuntime;
  }
  vpn::api::RouterOptions router_options;
  router_options.store = store->get();
  router_options.token_ttl_seconds = 3600;
  // The renewal-reminder endpoint needs the SMTP relay settings; empty host means
  // "not configured", which the endpoint reports as 503 rather than pretending.
  router_options.smtp_host = cfg.smtp.host;
  router_options.smtp_port = cfg.smtp.port;
  router_options.smtp_from = cfg.smtp.from;
  router_options.smtp_username = cfg.smtp.username;
  router_options.smtp_password = cfg.smtp.password;
  router_options.smtp_dry_run = cfg.smtp.dry_run;
  vpn::api::Router router{router_options};
  server->set_router([&router](const vpn::controlplane::HttpRequest& request) {
    return router.handle(request);
  });
  vpn::log::info("control-plane API mounted", "users",
                 std::to_string(store->get()->user_count()));

  // Second listener: metrics on their own port. Scrape traffic never shares a
  // socket with the API, and :9100 can be firewalled separately.
  vpn::controlplane::HttpServer::Options metrics_options = api_options;
  metrics_options.bind = cfg.metrics_bind;
  metrics_options.metrics_only = true;
  metrics_options.dev_mode = false;
  metrics_options.service_name = "vpnd-metrics";
  auto metrics_server =
      std::make_unique<vpn::controlplane::HttpServer>(metrics_options, metrics_health, metrics);

  bool metrics_listening = true;
  if (const vpn::Status st = metrics_server->listen(); !st.ok()) {
    vpn::log::error("failed to bind the metrics listener", "error", st.to_string());
    metrics_listening = false;
    if (cfg.environment == "production") {
      return kExitRuntime;  // production must expose metrics; fail loudly
    }
    vpn::log::warn("continuing without a dedicated metrics listener (development only)");
  }

  std::thread metrics_thread{[&] {
    if (metrics_listening) (void)metrics_server->serve();
  }};

  // One maintenance thread: uptime gauge, shutdown propagation, SIGHUP reload.
  std::atomic<bool> refreshing{true};
  std::thread refresher{[&] {
    const auto start = std::chrono::steady_clock::now();
    while (refreshing.load(std::memory_order_relaxed)) {
      if (g_stop_requested.load(std::memory_order_relaxed)) {
        server->stop();
        metrics_server->stop();
      }
      if (g_reload_requested.exchange(false, std::memory_order_relaxed)) {
        if (config_path.empty()) {
          vpn::log::warn("SIGHUP ignored: no --config file to reload");
        } else {
          auto reloaded = vpn::config::load_file(config_path);
          vpn::Status rejected{};
          if (!reloaded) {
            rejected = reloaded.error();
          } else if (const vpn::Status st = vpn::config::apply_environment(*reloaded); !st.ok()) {
            rejected = st;
          } else {
            rejected = vpn::config::validate(*reloaded);
          }
          if (!rejected.ok()) {
            vpn::log::error("config reload rejected; keeping the running config", "error",
                            rejected.to_string());
            metrics.inc_counter("vpn_config_reload_total", {{"result", "error"}});
          } else {
            vpn::log::Level new_level = vpn::log::level();
            if (vpn::log::parse_level(reloaded->log.level, new_level)) {
              vpn::log::set_level(new_level);
            }
            // Sockets, worker counts and timeouts are captured at listen time.
            // Say so instead of pretending they were applied.
            const bool needs_restart =
                reloaded->http.bind.port != cfg.http.bind.port ||
                reloaded->metrics_bind.port != cfg.metrics_bind.port ||
                reloaded->http.max_connections != cfg.http.max_connections ||
                reloaded->http.request_timeout_secs != cfg.http.request_timeout_secs;
            cfg = *reloaded;
            const auto generation =
                health.config_generation.fetch_add(1, std::memory_order_relaxed) + 1;
            metrics.inc_counter("vpn_config_reload_total", {{"result", "ok"}});
            metrics.set_gauge("vpn_config_generation", static_cast<double>(generation));
            vpn::log::info("config reloaded from SIGHUP", "generation",
                           std::to_string(generation));
            if (needs_restart) {
              vpn::log::warn("bind/limit changes in the file need a restart to take effect");
            }
          }
        }
      }
      const auto elapsed = std::chrono::steady_clock::now() - start;
      const auto secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
      metrics.set_gauge("vpn_uptime_seconds", static_cast<double>(secs));
      metrics.set_gauge("vpn_http_active_connections",
                        static_cast<double>(server->active_connections()));
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }};

  vpn::log::info("accepting connections", "bind", cfg.http.bind.to_string());
  const vpn::Status serve_status = server->serve();

  refreshing.store(false, std::memory_order_relaxed);
  refresher.join();
  metrics_server->stop();
  if (metrics_thread.joinable()) metrics_thread.join();

  if (!serve_status.ok()) {
    vpn::log::error("server loop failed", "error", serve_status.to_string());
    return kExitRuntime;
  }

  vpn::log::info("vpnd stopped cleanly");
  return kExitOk;
}
