// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Golden-vector driver for verify_blake2s.py: exercises the real
// server/src/crypto/blake2s.cpp for a spec file of cases produced by the Python
// verifier, so that the expected values come from hashlib and never from this
// build.
//
// Spec line format (ASCII, one case per line, '#' comments skipped):
//     label|out_len|key_hex|data_hex|chunk
//   * key_hex / data_hex: lowercase hex, or "-" for empty
//   * chunk: 0 == one-shot blake2s(), N > 0 == N-byte update() calls
//
// Output line format:
//     label|OK|digest_hex      or      label|BAD|-
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "vpn/common/bytes.hpp"
#include "vpn/crypto/blake2s.hpp"

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

// Strict lowercase/uppercase hex -> bytes. Returns false on any bad input.
bool unhex(const std::string& hex, std::vector<vpn::Byte>& out) {
  out.clear();
  if (hex == "-" || hex.empty()) return true;
  if (hex.size() % 2 != 0) return false;
  out.resize(hex.size() / 2);
  return vpn::from_hex(std::string_view{hex},
                       vpn::MutableByteSpan{out.data(), out.size()});
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
  int bad = 0;
  int total = 0;
  while (std::fgets(line.data(), static_cast<int>(line.size()), f) != nullptr) {
    std::string s{line.data()};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    if (s.empty() || s[0] == '#') continue;

    const auto parts = split(s, '|');
    if (parts.size() != 5) {
      std::fprintf(stderr, "malformed spec line: %s\n", s.c_str());
      ++bad;
      continue;
    }
    ++total;

    std::vector<vpn::Byte> key;
    std::vector<vpn::Byte> data;
    const std::size_t out_len = static_cast<std::size_t>(std::strtoull(parts[1].c_str(), nullptr, 10));
    const std::size_t chunk = static_cast<std::size_t>(std::strtoull(parts[4].c_str(), nullptr, 10));

    if (!unhex(parts[2], key) || !unhex(parts[3], data)) {
      std::printf("%s|BAD|-\n", parts[0].c_str());
      ++bad;
      continue;
    }

    std::vector<vpn::Byte> out(out_len, 0);
    const vpn::ByteSpan key_span{key.data(), key.size()};
    const vpn::ByteSpan data_span{data.data(), data.size()};
    const vpn::MutableByteSpan out_span{out.data(), out.size()};

    bool ok = false;
    if (chunk == 0) {
      ok = vpn::crypto::blake2s(data_span, key_span, out_span);
    } else if (out_len >= 1 && out_len <= vpn::crypto::kBlake2sMaxOut) {
      vpn::crypto::Blake2s h{out_len, key_span};
      std::size_t offset = 0;
      while (offset < data.size()) {
        const std::size_t n =
            (data.size() - offset) < chunk ? (data.size() - offset) : chunk;
        h.update(vpn::ByteSpan{data.data() + offset, n});
        offset += n;
      }
      ok = h.final(out_span) == out_len;
    }

    if (ok) {
      const std::string hex = vpn::to_hex(out_span);
      std::printf("%s|OK|%s\n", parts[0].c_str(), hex.c_str());
    } else {
      std::printf("%s|BAD|-\n", parts[0].c_str());
      ++bad;
    }
  }
  std::fclose(f);
  if (bad != 0) {
    std::fprintf(stderr, "%d/%d driver cases failed\n", bad, total);
    return 1;
  }
  return 0;
}
