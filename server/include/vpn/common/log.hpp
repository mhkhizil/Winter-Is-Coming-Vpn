// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// M0 structured logging: one JSON object per line on stderr, no allocation on
// the level check, no third-party dependency.
//
// M1 replaces the sink with spdlog (async, non-allocating) behind this same
// interface; call sites must not change. Deliberately absent: any facility for
// logging key material or packet contents (see docs/THREAT_MODEL.md).
#pragma once

#include <string>
#include <string_view>

namespace vpn::log {

enum class Level : int {
  kTrace = 0,
  kDebug = 1,
  kInfo = 2,
  kWarn = 3,
  kError = 4,
  kOff = 5,
};

[[nodiscard]] const char* to_string(Level level) noexcept;
[[nodiscard]] bool parse_level(std::string_view text, Level& out) noexcept;

void set_level(Level level) noexcept;
[[nodiscard]] Level level() noexcept;
[[nodiscard]] bool enabled(Level level) noexcept;

// Writes one JSON line: {"ts":"...","level":"info","msg":"...","service":"vpnd"}
void write(Level level, std::string_view message) noexcept;

// Structured variant: {"...","kv":{"key":"value"}} - values are escaped.
void write(Level level, std::string_view message, std::string_view key, std::string_view value) noexcept;

inline void trace(std::string_view m) noexcept { if (enabled(Level::kTrace)) write(Level::kTrace, m); }
inline void debug(std::string_view m) noexcept { if (enabled(Level::kDebug)) write(Level::kDebug, m); }
inline void info(std::string_view m) noexcept { if (enabled(Level::kInfo)) write(Level::kInfo, m); }
inline void warn(std::string_view m) noexcept { if (enabled(Level::kWarn)) write(Level::kWarn, m); }
inline void error(std::string_view m) noexcept { if (enabled(Level::kError)) write(Level::kError, m); }

inline void info(std::string_view m, std::string_view k, std::string_view v) noexcept {
  if (enabled(Level::kInfo)) write(Level::kInfo, m, k, v);
}
inline void warn(std::string_view m, std::string_view k, std::string_view v) noexcept {
  if (enabled(Level::kWarn)) write(Level::kWarn, m, k, v);
}
inline void error(std::string_view m, std::string_view k, std::string_view v) noexcept {
  if (enabled(Level::kError)) write(Level::kError, m, k, v);
}

// Sets the "service" field (defaults to "vpnd"); call once at startup.
void set_service(std::string_view service) noexcept;

}  // namespace vpn::log
