// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Extremely small test harness: register a case, run it, print a diff-friendly
// report, exit non-zero on failure.
//
// Deliberate choice: M0 has no third-party dependencies, so the foundation can
// be built and gated offline. GoogleTest is introduced at M2 for the integration
// and golden-vector suites (see docs/DECISIONS/ADR-0003-build-system.md).
#pragma once

#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace vpn_test {

struct Case {
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

inline int& failures() {
  static int count = 0;
  return count;
}

inline bool& current_failed() {
  static bool failed = false;
  return failed;
}

inline void add(const char* name, void (*fn)()) { registry().push_back(Case{name, fn}); }

inline void report_failure(const char* file, int line, const std::string& what) {
  current_failed() = true;
  ++failures();
  std::fprintf(stderr, "    FAIL %s:%d  %s\n", file, line, what.c_str());
}

template <class A, class B>
[[nodiscard]] std::string diff_message(const char* a_expr, const A& a, const char* b_expr,
                                       const B& b) {
  std::ostringstream os;
  os << a_expr << " == " << b_expr << " (left=" << a << ", right=" << b << ")";
  return os.str();
}

inline int run_all() {
  int executed = 0;
  for (const auto& c : registry()) {
    current_failed() = false;
    std::printf("[ RUN      ] %s\n", c.name);
    c.fn();
    ++executed;
    if (current_failed()) {
      std::printf("[  FAILED  ] %s\n", c.name);
    } else {
      std::printf("[       OK ] %s\n", c.name);
    }
  }
  std::printf("\n%d test(s) run, %d assertion failure(s)\n", executed, failures());
  return failures() == 0 ? 0 : 1;
}

}  // namespace vpn_test

#define TEST(suite, name)                                                             \
  static void suite##_##name##_impl();                                                \
  namespace {                                                                         \
  const int suite##_##name##_registered =                                             \
      (vpn_test::add(#suite "." #name, &suite##_##name##_impl), 0);                    \
  }                                                                                   \
  static void suite##_##name##_impl()

#define CHECK(cond)                                                                   \
  do {                                                                                \
    if (!(cond)) vpn_test::report_failure(__FILE__, __LINE__, "CHECK(" #cond ")");     \
  } while (false)

#define CHECK_EQ(a, b)                                                                \
  do {                                                                                \
    const auto& vpn_test_a = (a);                                                      \
    const auto& vpn_test_b = (b);                                                      \
    if (!(vpn_test_a == vpn_test_b)) {                                                 \
      vpn_test::report_failure(__FILE__, __LINE__,                                     \
                               vpn_test::diff_message(#a, vpn_test_a, #b, vpn_test_b)); \
    }                                                                                 \
  } while (false)

#define CHECK_MSG(cond, msg)                                                          \
  do {                                                                                \
    if (!(cond)) vpn_test::report_failure(__FILE__, __LINE__, (msg));                  \
  } while (false)

#define CHECK_NEAR(a, b, eps)                                                         \
  do {                                                                                \
    const double vpn_test_a = static_cast<double>(a);                                  \
    const double vpn_test_b = static_cast<double>(b);                                  \
    if (std::fabs(vpn_test_a - vpn_test_b) > (eps)) {                                  \
      vpn_test::report_failure(__FILE__, __LINE__, "CHECK_NEAR(" #a ", " #b ")");      \
    }                                                                                 \
  } while (false)
