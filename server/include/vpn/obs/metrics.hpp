// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Prometheus-compatible metrics registry for the control plane.
//
// Scope: M0 needs /metrics with real numbers (build info, uptime, request
// counts, readiness). The registry is mutex-protected and therefore NOT used on
// the data-plane packet path: the data plane keeps per-worker lock-free counters
// and exports them through a different, allocation-free path (M2, docs/ops/metrics.md).
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vpn::obs {

class Metrics {
 public:
  using Labels = std::vector<std::pair<std::string, std::string>>;

  Metrics();

  void inc_counter(std::string_view name, const Labels& labels = {});
  void add_counter(std::string_view name, std::uint64_t delta, const Labels& labels = {});
  void set_gauge(std::string_view name, double value, const Labels& labels = {});
  void observe_histogram_count(std::string_view name, double sum, std::uint64_t count,
                               const Labels& labels = {});

  // Prometheus text exposition format 0.0.4.
  [[nodiscard]] std::string render() const;

  // Registers HELP/TYPE metadata; must be called before the sample is created.
  void describe(std::string_view name, std::string_view help, std::string_view type);

  [[nodiscard]] static std::string escape_label(std::string_view value);

 private:
  struct Descriptor {
    std::string name;
    std::string help;
    std::string type;
  };

  // The sample's own kind, so an auto-discovered series is typed correctly
  // instead of always being advertised as a counter.
  enum class Kind { kCounter, kGauge, kHistogram };

  struct Sample {
    std::string name;
    Labels labels;
    double value{0};
    std::uint64_t count{0};
    double sum{0};
    Kind kind{Kind::kCounter};
  };

  void describe_locked(const Descriptor& d);
  Sample& sample_locked(std::string_view name, const Labels& labels, Kind kind);

  [[nodiscard]] static const char* kind_name(Kind kind) noexcept;

  mutable std::mutex mutex_;
  std::vector<Descriptor> descriptors_;
  std::vector<Sample> samples_;
};

}  // namespace vpn::obs
