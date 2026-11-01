// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/crypto/random.hpp"

#include <cstdint>
#include <limits>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

namespace vpn::crypto {
namespace {

#if !defined(_WIN32)
[[nodiscard]] bool read_urandom(MutableByteSpan out) noexcept {
  const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  std::size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::read(fd, out.data() + done, out.size() - done);
    if (n > 0) {
      done += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    (void)::close(fd);
    return false;
  }
  (void)::close(fd);
  return true;
}
#endif

}  // namespace

bool fill_random(MutableByteSpan out) noexcept {
  if (out.empty()) return true;

#if defined(_WIN32)
  const NTSTATUS status = ::BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return status == 0;  // STATUS_SUCCESS
#else
  std::size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::getrandom(out.data() + done, out.size() - done, 0);
    if (n > 0) {
      done += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    break;  // fall through to /dev/urandom
  }
  if (done == out.size()) return true;
  return read_urandom(MutableByteSpan{out.data() + done, out.size() - done});
#endif
}

bool random_below(std::uint32_t bound, std::uint32_t& out) noexcept {
  if (bound == 0) return false;
  constexpr std::uint32_t kMax = std::numeric_limits<std::uint32_t>::max();
  // Largest multiple of `bound`; values at or above it are rejected so that the
  // modulo below is uniform (no modulo bias).
  const std::uint32_t limit = kMax - (kMax % bound);
  for (;;) {
    std::uint32_t value = 0;
    if (!fill_random(MutableByteSpan{reinterpret_cast<Byte*>(&value), sizeof(value)})) {
      return false;
    }
    if (value < limit) {
      out = value % bound;
      return true;
    }
  }
}

bool random_index(std::uint32_t& out) noexcept {
  for (;;) {
    std::uint32_t value = 0;
    if (!fill_random(MutableByteSpan{reinterpret_cast<Byte*>(&value), sizeof(value)})) {
      return false;
    }
    if (value != 0) {  // 0 is reserved: it never identifies a live session
      out = value;
      return true;
    }
  }
}

}  // namespace vpn::crypto
