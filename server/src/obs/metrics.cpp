// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/obs/metrics.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>

namespace vpn::obs {
namespace {

[[nodiscard]] std::string format_number(double value) {
  // Check specials first: casting NaN/Inf to an integer is undefined behaviour.
  if (std::isnan(value)) return "NaN";
  if (std::isinf(value)) return value > 0 ? "+Inf" : "-Inf";
  // Integral values print without a decimal point, matching Prometheus tooling.
  if (value >= 0 && value < 1e15 &&
      value == static_cast<double>(static_cast<std::uint64_t>(value))) {
    return std::to_string(static_cast<std::uint64_t>(value));
  }
  char buf[64] = {};
  std::snprintf(buf, sizeof(buf), "%.17g", value);
  return buf;
}

bool same_labels(const Metrics::Labels& a, const Metrics::Labels& b) {
  return a == b;
}

// Canonical label order. Two call sites passing the same label set in a
// different order must land on the same series: Prometheus treats the label set
// as a set, so emitting both would be a duplicate series for one identity.
[[nodiscard]] Metrics::Labels canonical_labels(Metrics::Labels labels) {
  std::sort(labels.begin(), labels.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  return labels;
}

}  // namespace

Metrics::Metrics() {
  describe("vpn_build_info", "Build and protocol version information", "gauge");
  describe("vpn_uptime_seconds", "Seconds since the process started", "gauge");
  describe("vpn_http_requests_total", "HTTP requests served, by route and status",
           "counter");
}

std::string Metrics::escape_label(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char c : value) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

void Metrics::describe(std::string_view name, std::string_view help, std::string_view type) {
  const std::lock_guard<std::mutex> lock(mutex_);
  describe_locked(Descriptor{std::string{name}, std::string{help}, std::string{type}});
}

void Metrics::describe_locked(const Descriptor& d) {
  for (const auto& existing : descriptors_) {
    if (existing.name == d.name) return;
  }
  descriptors_.push_back(d);
}

Metrics::Sample& Metrics::sample_locked(std::string_view name, const Labels& labels,
                                        Kind kind) {
  const Labels normalized = canonical_labels(labels);
  for (auto& s : samples_) {
    if (s.name == name && same_labels(s.labels, normalized)) return s;
  }
  Sample s;
  s.name = std::string{name};
  s.labels = normalized;
  s.kind = kind;
  samples_.push_back(std::move(s));
  return samples_.back();
}

const char* Metrics::kind_name(Kind kind) noexcept {
  switch (kind) {
    case Kind::kCounter: return "counter";
    case Kind::kGauge: return "gauge";
    case Kind::kHistogram: return "histogram";
  }
  return "untyped";
}

void Metrics::inc_counter(std::string_view name, const Labels& labels) {
  add_counter(name, 1, labels);
}

void Metrics::add_counter(std::string_view name, std::uint64_t delta, const Labels& labels) {
  const std::lock_guard<std::mutex> lock(mutex_);
  Sample& s = sample_locked(name, labels, Kind::kCounter);
  s.value += static_cast<double>(delta);
}

void Metrics::set_gauge(std::string_view name, double value, const Labels& labels) {
  const std::lock_guard<std::mutex> lock(mutex_);
  sample_locked(name, labels, Kind::kGauge).value = value;
}

void Metrics::observe_histogram_count(std::string_view name, double sum, std::uint64_t count,
                                      const Labels& labels) {
  const std::lock_guard<std::mutex> lock(mutex_);
  Sample& s = sample_locked(name, labels, Kind::kHistogram);
  s.sum += sum;
  s.count += count;
  s.value += static_cast<double>(count);
}

std::string Metrics::render() const {
  const std::lock_guard<std::mutex> lock(mutex_);

  std::string out;
  out.reserve(2048);

  std::set<std::string> emitted;
  for (const auto& d : descriptors_) {
    out += "# HELP ";
    out += d.name;
    out += ' ';
    out += d.help;
    out += "\n# TYPE ";
    out += d.name;
    out += ' ';
    out += d.type;
    out += '\n';
    emitted.insert(d.name);
  }

  for (const auto& s : samples_) {
    if (emitted.find(s.name) == emitted.end()) {
      out += "# TYPE ";
      out += s.name;
      out += ' ';
      out += kind_name(s.kind);
      out += '\n';
      emitted.insert(s.name);
    }

    // name{labels} for a plain sample; name_count{labels} / name_sum{labels} for
    // a histogram. The suffix goes *before* the label block, as the exposition
    // format requires - "name{labels}_count" is not a valid sample.
    const auto append_series = [&](std::string_view suffix) {
      out += s.name;
      out += suffix;
      if (!s.labels.empty()) {
        out += '{';
        bool first = true;
        for (const auto& [k, v] : s.labels) {
          if (!first) out += ',';
          first = false;
          out += k;
          out += "=\"";
          out += escape_label(v);
          out += '"';
        }
        out += '}';
      }
    };

    if (s.kind == Kind::kHistogram) {
      append_series("_count");
      out += ' ';
      out += std::to_string(s.count);
      out += '\n';
      append_series("_sum");
      out += ' ';
      out += format_number(s.sum);
      out += '\n';
    } else {
      append_series({});
      out += ' ';
      out += format_number(s.value);
      out += '\n';
    }
  }
  return out;
}

}  // namespace vpn::obs
