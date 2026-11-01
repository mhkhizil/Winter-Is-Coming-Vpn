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
#include <string>
#include <string_view>
#include <thread>

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

extern "C" void handle_signal(int /*sig*/) {
  // Async-signal-safe work only: set a flag, let the main loop unwind.
  g_stop_requested.store(true, std::memory_order_relaxed);
}

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
  health.started_at_unix.store(static_cast<std::uint64_t>(std::time(nullptr)),
                               std::memory_order_relaxed);

  vpn::controlplane::HttpServer::Options options;
  options.bind = cfg.http.bind;
  options.request_timeout_secs = cfg.http.request_timeout_secs;
  options.max_header_bytes = cfg.http.max_header_bytes;

  // Install the handlers before the socket exists: a SIGTERM in the window
  // between listen() and serve() would otherwise take the default action.
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);
#if defined(SIGPIPE)
  std::signal(SIGPIPE, SIG_IGN);  // a client that vanishes must not kill vpnd
#endif

  vpn::controlplane::HttpServer server{options, health, metrics};
  if (const vpn::Status st = server.listen(); !st.ok()) {
    vpn::log::error("failed to listen", "error", st.to_string());
    return kExitRuntime;
  }

  // metrics.bind is parsed and validated but not bound in M0: /metrics shares the
  // HTTP port. Say so out loud, because an operator who firewalls 9100 and
  // expects /metrics to be private there would otherwise be surprised.
  if (cfg.metrics_bind.host != cfg.http.bind.host || cfg.metrics_bind.port != cfg.http.bind.port) {
    vpn::log::warn("metrics.bind is ignored in M0: /metrics is served on http.bind",
                   "metrics_bind", cfg.metrics_bind.to_string());
  }

  // Uptime gauge refresh loop; also proves the process shuts down cleanly and
  // turns a SIGINT/SIGTERM into a prompt, graceful stop of the accept loop.
  std::atomic<bool> refreshing{true};
  std::thread refresher{[&] {
    const auto start = std::chrono::steady_clock::now();
    while (refreshing.load(std::memory_order_relaxed)) {
      if (g_stop_requested.load(std::memory_order_relaxed)) {
        server.stop();
      }
      const auto elapsed = std::chrono::steady_clock::now() - start;
      const auto secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
      metrics.set_gauge("vpn_uptime_seconds", static_cast<double>(secs));
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }};

  vpn::log::info("accepting connections", "bind", cfg.http.bind.to_string());
  const vpn::Status serve_status = server.serve();

  refreshing.store(false, std::memory_order_relaxed);
  refresher.join();

  if (!serve_status.ok()) {
    vpn::log::error("server loop failed", "error", serve_status.to_string());
    return kExitRuntime;
  }

  vpn::log::info("vpnd stopped cleanly");
  return kExitOk;
}
