// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Prometheus exposition-format conformance. These are format bugs, not style:
// a scrape with an invalid sample line is rejected wholesale by Prometheus, and
// a mis-typed series is silently unusable.
#include "test_support.hpp"
#include "vpn/obs/metrics.hpp"

#include <string>

namespace {

[[nodiscard]] std::size_t count_lines(std::string_view text, std::string_view needle) {
  std::size_t n = 0;
  for (std::size_t at = text.find(needle); at != std::string_view::npos;
       at = text.find(needle, at + needle.size())) {
    ++n;
  }
  return n;
}

}  // namespace

TEST(Metrics, histogram_samples_put_the_suffix_before_the_labels) {
  vpn::obs::Metrics m;
  m.observe_histogram_count("vpn_handshake_seconds", 1.5, 3, {{"proto", "wg"}});
  const std::string text = m.render();
  // Prometheus text format: name_count{labels} value - never name{labels}_count.
  const bool good = text.find("vpn_handshake_seconds_count{proto=\"wg\"} 3") !=
                    std::string::npos;
  CHECK_MSG(good, "exposition must be name_count{labels}, got:\n" + text);
  CHECK_MSG(text.find("}_count") == std::string::npos,
            "sample line has the label block before the _count suffix:\n" + text);
  CHECK_MSG(text.find("_sum{proto=\"wg\"} 1.5") != std::string::npos,
            "histogram _sum must also carry the labels:\n" + text);
}

TEST(Metrics, unregistered_gauge_is_not_typed_as_a_counter) {
  vpn::obs::Metrics m;
  m.set_gauge("vpn_unregistered_gauge", 7.0);
  const std::string text = m.render();
  CHECK_MSG(text.find("# TYPE vpn_unregistered_gauge gauge") != std::string::npos,
            "# TYPE must say gauge for a gauge sample, got:\n" + text);
}

TEST(Metrics, type_lines_are_never_duplicated) {
  vpn::obs::Metrics m;
  m.inc_counter("vpn_x_total");
  m.inc_counter("vpn_x_total");
  const std::string text = m.render();
  CHECK_EQ(count_lines(text, "# TYPE vpn_x_total"), std::size_t{1});
}

TEST(Metrics, label_sets_are_order_independent) {
  vpn::obs::Metrics m;
  m.inc_counter("vpn_y_total", {{"a", "1"}, {"b", "2"}});
  m.inc_counter("vpn_y_total", {{"b", "2"}, {"a", "1"}});
  const std::string text = m.render();
  // Same label set in a different order must update the existing series, not
  // create a second one with the same identity (Prometheus rejects that).
  CHECK_EQ(count_lines(text, "vpn_y_total{"), std::size_t{1});
  CHECK_MSG(text.find("vpn_y_total{a=\"1\",b=\"2\"} 2") != std::string::npos,
            "expected a canonical, sorted label order with value 2:\n" + text);
}

TEST(Metrics, numbers_that_are_not_finite_do_not_wrap) {
  vpn::obs::Metrics m;
  const double inf = 1.0 / 0.0;
  m.set_gauge("vpn_inf_gauge", inf);
  m.set_gauge("vpn_nan_gauge", inf - inf);
  m.set_gauge("vpn_neg_gauge", -3.5);
  const std::string text = m.render();
  CHECK_MSG(text.find("vpn_inf_gauge +Inf") != std::string::npos,
            "+Inf must be exported as +Inf:\n" + text);
  CHECK_MSG(text.find("vpn_nan_gauge NaN") != std::string::npos,
            "NaN must be exported as NaN:\n" + text);
  CHECK_MSG(text.find("vpn_neg_gauge -3.5") != std::string::npos,
            "negative gauge must keep its sign:\n" + text);
}

TEST(Metrics, labels_are_escaped_per_spec) {
  vpn::obs::Metrics m;
  m.inc_counter("vpn_z_total", {{"route", "a\"b\\c\nd"}});
  const std::string text = m.render();
  CHECK_MSG(text.find("route=\"a\\\"b\\\\c\\nd\"") != std::string::npos,
            "quotes/backslashes/newlines must be escaped:\n" + text);
}
