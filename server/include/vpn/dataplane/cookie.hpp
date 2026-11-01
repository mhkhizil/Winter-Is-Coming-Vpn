// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// The stateless anti-DoS path: mac1 verification, the rotating cookie secret, and
// CookieReply creation/consumption (WireGuard §5.4.7 "Cookie Reply").
//
// Why this exists: an attacker who can spoof a source address can make a
// responder burn an X25519 operation per datagram. mac1 alone does not stop
// that - mac1 requires the *responder's* public key, which is public. The cookie
// path makes the initiator prove it can receive at the address it claims by
// echoing back a value derived from a secret only the responder holds, so no DH
// work is spent until the client is validated.
//
// Rules implemented here:
//   * mac1 is verified before anything else; a bad mac1 costs no DH.
//   * the cookie = keyed-BLAKE2s-128(secret, source_ip || source_port_be) - the
//     port is part of the input, so a cookie cannot be reused from another port
//     behind the same NAT address.
//   * the secret rotates every 120 s with two secrets live at once, so a client
//     that had a cookie minted just before a rotation is not punished.
//   * CookieReply payload = XChaCha20-Poly1305(cookie) keyed by
//     BLAKE2s-256("cookie--" || responder_static_pub), with the mac1 of the
//     refused message as associated data - that is what authenticates the reply
//     to the initiator, since only the responder knows the cookie key.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result.hpp"
#include "vpn/crypto/x25519.hpp"
#include "vpn/dataplane/socket_address.hpp"
#include "vpn/wire/constants.hpp"

namespace vpn::wire {

// BLAKE2s-256("cookie--" || responder_static_pub): the XChaCha20-Poly1305 key
// that protects CookieReply payloads. Derivable by both sides.
[[nodiscard]] Bytes<32> cookie_key(const crypto::X25519PublicKey& responder_static) noexcept;

// Rotating cookie secret holder (responder side only).
class CookieChecker {
 public:
  CookieChecker() noexcept;
  ~CookieChecker() noexcept;
  CookieChecker(const CookieChecker&) = delete;
  CookieChecker& operator=(const CookieChecker&) = delete;

  // Seeds the first secret from the CSPRNG and binds the checker to our static
  // public key. Fails closed if the OS RNG is unavailable.
  [[nodiscard]] Status init(const crypto::X25519PublicKey& self, std::uint64_t now_ms) noexcept;

  [[nodiscard]] bool initialized() const noexcept { return initialized_; }

  // The cookie this responder would hand out to `src` right now.
  [[nodiscard]] Bytes<16> cookie_for(const dataplane::SocketAddress& src,
                                     std::uint64_t now_ms) noexcept;

  // True if the mac2 carried by `msg` (a 148- or 92-byte handshake message) is
  // valid for `src` under either live secret.
  [[nodiscard]] bool verify_mac2(ByteSpan msg, const dataplane::SocketAddress& src,
                                 std::uint64_t now_ms) noexcept;

  // Builds a 64-byte CookieReply refusing `refused_message` from `src`.
  [[nodiscard]] Status create_cookie_reply(ByteSpan refused_message,
                                           const dataplane::SocketAddress& src,
                                           std::uint64_t now_ms,
                                           MutableByteSpan out_64) noexcept;

  // Initiator side: authenticate+decrypt a CookieReply that answers the message
  // whose mac1 was `sent_mac1`. On success `out_cookie` is what mac2 must use.
  [[nodiscard]] static Status open_cookie_reply(ByteSpan msg_64,
                                                const crypto::X25519PublicKey& responder_static,
                                                const Bytes<16>& sent_mac1,
                                                Bytes<16>& out_cookie) noexcept;

  // Applies the 120 s rotation rule. Called from every entry point so the caller
  // never has to remember to do it.
  void rotate(std::uint64_t now_ms) noexcept;

  void reset() noexcept;

 private:
  [[nodiscard]] std::uint64_t secret_generation() const noexcept { return generation_; }

  Bytes<32> key_{};        // cookie-- label key (encrypts CookieReply payloads)
  Bytes<32> secret_[2]{};  // [0] = current, [1] = previous (still accepted)
  std::uint64_t born_ms_[2]{0, 0};
  std::uint64_t generation_{0};
  bool have_secret_{false};
  bool initialized_{false};
};

// Per-source handshake rate limiter that decides *when* to demand a cookie.
//
// Bounded and allocation-free: a fixed table keyed by address||port. It is a
// heuristic, not a security boundary - the cookie itself is the security
// boundary; this only decides when to stop being generous.
class HandshakeLimiter {
 public:
  struct Options {
    std::uint32_t threshold{4};       // initiations per source per window
    std::uint64_t window_ms{10000};
  };

  explicit HandshakeLimiter(const Options& options = {}) noexcept;

  // Records one mac1-valid initiation from `src`. Returns true when the source
  // has exceeded its budget and a cookie must be demanded.
  [[nodiscard]] bool record(const dataplane::SocketAddress& src, std::uint64_t now_ms) noexcept;

  void reset() noexcept;

 private:
  static constexpr std::size_t kSlots = 256;

  struct Entry {
    dataplane::SocketAddress addr{};
    std::uint64_t window_start_ms{0};
    std::uint32_t count{0};
    bool used{false};
  };

  std::array<Entry, kSlots> slots_{};
  Options options_{};
};

}  // namespace vpn::wire

namespace vpn::dataplane {
// The cookie machinery is logically part of the data plane even though it lives
// in vpn::wire (next to the MAC helpers it uses). Pull it into this namespace so
// callers do not have to remember the split.
using vpn::wire::CookieChecker;
using vpn::wire::HandshakeLimiter;
}  // namespace vpn::dataplane
