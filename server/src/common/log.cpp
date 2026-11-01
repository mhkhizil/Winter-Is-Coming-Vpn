// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/common/log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

namespace vpn::log {
namespace {

std::atomic<Level> g_level{Level::kInfo};
std::mutex g_mutex;            // serialises whole lines (not on any hot path)
std::string g_service{"vpnd"};

[[nodiscard]] bool needs_escape(unsigned char c) noexcept {
  return c < 0x20U || c == '"' || c == '\\';
}

void append_escaped(std::string& out, std::string_view in) {
  out.push_back('"');
  for (const char ch : in) {
    const auto c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (needs_escape(c)) {
          char buf[8] = {};
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
          out += buf;
        } else {
          out.push_back(ch);
        }
    }
  }
  out.push_back('"');
}

// RFC 3339 UTC, millisecond precision. gmtime_r/gmtime_s are guarded by g_mutex.
void append_timestamp(std::string& out) {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto secs = time_point_cast<seconds>(now);
  const auto ms = duration_cast<milliseconds>(now - secs).count();
  const std::time_t t = system_clock::to_time_t(secs);

  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif

  char buf[40] = {};
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<int>(ms));
  out += buf;
}

}  // namespace

const char* to_string(Level level) noexcept {
  switch (level) {
    case Level::kTrace: return "trace";
    case Level::kDebug: return "debug";
    case Level::kInfo: return "info";
    case Level::kWarn: return "warn";
    case Level::kError: return "error";
    case Level::kOff: return "off";
  }
  return "unknown";
}

bool parse_level(std::string_view text, Level& out) noexcept {
  if (text == "trace") { out = Level::kTrace; return true; }
  if (text == "debug") { out = Level::kDebug; return true; }
  if (text == "info") { out = Level::kInfo; return true; }
  if (text == "warn" || text == "warning") { out = Level::kWarn; return true; }
  if (text == "error") { out = Level::kError; return true; }
  if (text == "off" || text == "none") { out = Level::kOff; return true; }
  return false;
}

void set_level(Level level) noexcept { g_level.store(level, std::memory_order_relaxed); }
Level level() noexcept { return g_level.load(std::memory_order_relaxed); }
bool enabled(Level level) noexcept { return level >= g_level.load(std::memory_order_relaxed); }

void set_service(std::string_view service) noexcept {
  const std::lock_guard<std::mutex> lock(g_mutex);
  g_service.assign(service);
}

void write(Level level, std::string_view message) noexcept {
  write(level, message, {}, {});
}

void write(Level level, std::string_view message, std::string_view key,
           std::string_view value) noexcept {
  std::string line;
  line.reserve(160 + message.size() + key.size() + value.size());
  line += "{\"ts\":\"";
  append_timestamp(line);
  line += "\",\"level\":\"";
  line += to_string(level);
  line += "\",\"msg\":";
  append_escaped(line, message);
  {
    const std::lock_guard<std::mutex> lock(g_mutex);
    line += ",\"service\":";
    append_escaped(line, g_service);
    if (!key.empty()) {
      line += ",\"kv\":{";
      append_escaped(line, key);
      line += ':';
      append_escaped(line, value);
      line += '}';
    }
  }
  line += "}\n";
  // One fwrite per line: POSIX/Win32 guarantee the write is not interleaved.
  (void)std::fwrite(line.data(), 1, line.size(), stderr);
  (void)std::fflush(stderr);
}

}  // namespace vpn::log
