// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Driver for verify_replay_window.py: replays counter sequences against the real
// server/src/wire/replay_window.cpp.
//
// Spec line format ('#' comments skipped):
//     label|op1,op2,op3,...
//   * op = decimal counter  -> ReplayWindow::accept(counter)
//   * op = "R"              -> ReplayWindow::reset()
//
// Output line format:
//     label|OK|<bits>|<highest>|<initialized>
//   * bits: one character per op - '1' accepted, '0' rejected, 'r' reset
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "vpn/wire/replay_window.hpp"

namespace {

std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (const char ch : s) {
    if (ch == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(ch);
    }
  }
  out.push_back(cur);
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <spec-file>\n", argv[0]);
    return 2;
  }
  std::FILE* f = std::fopen(argv[1], "rb");
  if (f == nullptr) {
    std::fprintf(stderr, "cannot open %s\n", argv[1]);
    return 2;
  }

  std::vector<char> line(1 << 20);
  while (std::fgets(line.data(), static_cast<int>(line.size()), f) != nullptr) {
    std::string s{line.data()};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    if (s.empty() || s[0] == '#') continue;

    const auto bar = s.find('|');
    if (bar == std::string::npos) {
      std::fprintf(stderr, "malformed spec line: %s\n", s.c_str());
      continue;
    }
    const std::string label = s.substr(0, bar);
    const std::string ops = s.substr(bar + 1);

    vpn::wire::ReplayWindow window;
    std::string bits;
    for (const auto& op : split(ops, ',')) {
      if (op.empty()) continue;
      if (op == "R") {
        window.reset();
        bits.push_back('r');
      } else {
        const auto counter = std::strtoull(op.c_str(), nullptr, 10);
        bits.push_back(window.accept(counter) ? '1' : '0');
      }
    }

    std::printf("%s|OK|%s|%llu|%d\n", label.c_str(), bits.c_str(),
                static_cast<unsigned long long>(window.highest()),
                window.initialized() ? 1 : 0);
  }
  std::fclose(f);
  return 0;
}
