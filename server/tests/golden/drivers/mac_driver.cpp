// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Driver for verify_macs.py: runs the real server/src/wire/message.cpp primitives
// on cases authored independently in Python (so the expected mac1/mac2/cookie
// values come from hashlib, never from this build).
//
// Spec line format ('#' comments skipped):
//     label|kind|pubkey_hex|cookie_hex|data_hex|port
//   * "-" == empty field
//   * kinds: mac1, mac2, mac1key, cookie, roundtrip
//       mac1       compute_mac1(data, pubkey)
//       mac1key    mac1_key(pubkey)
//       mac2       compute_mac2(data, cookie)
//       cookie     compute_cookie(secret=pubkey, source_ip=data, port)
//       roundtrip  decode(data) then encode() again -> re-serialised datagram
// Output: label|OK|hex   or   label|BAD|<reason>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "vpn/common/bytes.hpp"
#include "vpn/crypto/blake2s.hpp"
#include "vpn/wire/message.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;
using namespace vpn::wire;

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

bool unhex(const std::string& hex, std::vector<Byte>& out) {
  out.clear();
  if (hex == "-" || hex.empty()) return true;
  if (hex.size() % 2 != 0) return false;
  out.resize(hex.size() / 2);
  return vpn::from_hex(std::string_view{hex}, MutableByteSpan{out.data(), out.size()});
}

bool to_fixed32(const std::vector<Byte>& in, Bytes<32>& out) {
  if (in.size() != 32) return false;
  for (std::size_t i = 0; i < 32; ++i) out[i] = in[i];
  return true;
}

bool to_fixed16(const std::vector<Byte>& in, Bytes<16>& out) {
  if (in.size() != 16) return false;
  for (std::size_t i = 0; i < 16; ++i) out[i] = in[i];
  return true;
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
  while (std::fgets(line.data(), static_cast<int>(line.size()), f) != nullptr) {
    std::string s{line.data()};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    if (s.empty() || s[0] == '#') continue;

    const auto parts = split(s, '|');
    if (parts.size() != 6) {
      std::fprintf(stderr, "malformed spec line: %s\n", s.c_str());
      ++bad;
      continue;
    }
    const std::string& label = parts[0];
    const std::string& kind = parts[1];

    std::vector<Byte> pub_raw;
    std::vector<Byte> cookie_raw;
    std::vector<Byte> data;
    if (!unhex(parts[2], pub_raw) || !unhex(parts[3], cookie_raw) ||
        !unhex(parts[4], data)) {
      std::printf("%s|BAD|bad hex\n", label.c_str());
      ++bad;
      continue;
    }
    const unsigned long port = std::strtoul(parts[5].c_str(), nullptr, 10);

    Bytes<32> pub{};
    Bytes<16> cookie{};
    const bool have_pub = to_fixed32(pub_raw, pub);
    const bool have_cookie = to_fixed16(cookie_raw, cookie);
    const ByteSpan data_span{data.data(), data.size()};

    std::string hex;
    if (kind == "mac1" || kind == "mac1key") {
      if (!have_pub) {
        std::printf("%s|BAD|pubkey must be 32 bytes\n", label.c_str());
        ++bad;
        continue;
      }
      if (kind == "mac1") {
        const Bytes<16> mac = compute_mac1(data_span, pub);
        hex = vpn::to_hex(ByteSpan{mac.data(), mac.size()});
      } else {
        const Bytes<32> key = mac1_key(pub);
        hex = vpn::to_hex(ByteSpan{key.data(), key.size()});
      }
    } else if (kind == "mac2") {
      if (!have_cookie) {
        std::printf("%s|BAD|cookie must be 16 bytes\n", label.c_str());
        ++bad;
        continue;
      }
      const Bytes<16> mac = compute_mac2(data_span, cookie);
      hex = vpn::to_hex(ByteSpan{mac.data(), mac.size()});
    } else if (kind == "cookie") {
      if (!have_pub) {
        std::printf("%s|BAD|secret must be 32 bytes\n", label.c_str());
        ++bad;
        continue;
      }
      const Bytes<16> c = compute_cookie(pub, data_span,
                                         static_cast<std::uint16_t>(port));
      hex = vpn::to_hex(ByteSpan{c.data(), c.size()});
    } else if (kind == "roundtrip") {
      auto decoded = decode(data_span);
      if (!decoded) {
        std::printf("%s|BAD|decode:%s\n", label.c_str(),
                    decoded.error().to_string().c_str());
        ++bad;
        continue;
      }
      std::vector<Byte> out(data.size() + 64, 0);
      const MutableByteSpan out_span{out.data(), out.size()};
      std::size_t n = 0;
      switch (decoded->type) {
        case MessageType::kHandshakeInitiation:
          n = encode(decoded->initiation, out_span);
          break;
        case MessageType::kHandshakeResponse:
          n = encode(decoded->response, out_span);
          break;
        case MessageType::kCookieReply:
          n = encode(decoded->cookie, out_span);
          break;
        case MessageType::kTransportData:
          n = encode(decoded->transport, decoded->transport.payload, out_span);
          break;
      }
      if (n == 0) {
        std::printf("%s|BAD|encode returned 0\n", label.c_str());
        ++bad;
        continue;
      }
      out.resize(n);
      hex = vpn::to_hex(MutableByteSpan{out.data(), out.size()});
    } else {
      std::printf("%s|BAD|unknown kind %s\n", label.c_str(), kind.c_str());
      ++bad;
      continue;
    }

    std::printf("%s|OK|%s\n", label.c_str(), hex.c_str());
  }
  std::fclose(f);
  if (bad != 0) {
    std::fprintf(stderr, "%d driver case(s) failed\n", bad);
    return 1;
  }
  return 0;
}
