// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include "vpn/dataplane/cookie.hpp"

#include "vpn/common/endian.hpp"
#include "vpn/common/result_helpers.hpp"
#include "vpn/crypto/aead.hpp"
#include "vpn/crypto/blake2s.hpp"
#include "vpn/crypto/ct.hpp"
#include "vpn/crypto/random.hpp"
#include "vpn/wire/message.hpp"

namespace vpn::wire {
namespace {

constexpr std::uint64_t kRotateMs =
    static_cast<std::uint64_t>(kCookieRefreshTime.count()) * 1000ULL;

// Offset of the trailing mac2 for the two message types that carry one.
[[nodiscard]] std::size_t mac2_offset(std::size_t message_size) noexcept {
  switch (message_size) {
    case kHandshakeInitiationSize: return kHandshakeInitiationSize - kMacSize;
    case kHandshakeResponseSize: return kHandshakeResponseSize - kMacSize;
    default: return 0;
  }
}

[[nodiscard]] std::size_t mac1_offset_for(std::size_t message_size) noexcept {
  const std::size_t mac2_at = mac2_offset(message_size);
  return mac2_at == 0 ? 0 : mac2_at - kMacSize;
}

[[nodiscard]] Status bad_cookie_message(const char* what) {
  return make_error(ErrorCode::kMalformed, what);
}

}  // namespace

Bytes<32> cookie_key(const crypto::X25519PublicKey& responder_static) noexcept {
  constexpr std::size_t label_len = sizeof(kCookieLabel) - 1;  // drop the NUL
  crypto::Blake2s hash{32, ByteSpan{}};
  Byte label[label_len];
  for (std::size_t i = 0; i < label_len; ++i) label[i] = static_cast<Byte>(kCookieLabel[i]);
  hash.update(ByteSpan{label, label_len});
  hash.update(as_span(responder_static));
  Bytes<32> out{};
  hash.final(as_span(out));
  return out;
}

CookieChecker::CookieChecker() noexcept = default;
CookieChecker::~CookieChecker() noexcept { reset(); }

void CookieChecker::reset() noexcept {
  secure_zero(as_span(key_));
  secure_zero(as_span(secret_[0]));
  secure_zero(as_span(secret_[1]));
  born_ms_[0] = 0;
  born_ms_[1] = 0;
  generation_ = 0;
  have_secret_ = false;
  initialized_ = false;
}

Status CookieChecker::init(const crypto::X25519PublicKey& self, std::uint64_t now_ms) noexcept {
  reset();
  key_ = cookie_key(self);
  if (!crypto::fill_random(as_span(secret_[0]))) {
    return make_error(ErrorCode::kInternal, "cookie secret: OS RNG unavailable");
  }
  born_ms_[0] = now_ms;
  have_secret_ = true;
  initialized_ = true;
  ++generation_;
  return {};
}

void CookieChecker::rotate(std::uint64_t now_ms) noexcept {
  if (!have_secret_ || !initialized_) return;
  // A clock that jumped backwards must not create a secret that is valid
  // "forever": re-anchor instead of rotating.
  if (now_ms < born_ms_[0]) {
    born_ms_[0] = now_ms;
    return;
  }
  if (now_ms - born_ms_[0] < kRotateMs) return;

  // Two secrets live at once: the old current becomes the previous one so a
  // cookie minted just before the rotation keeps working until it rotates out.
  secret_[1] = secret_[0];
  born_ms_[1] = born_ms_[0];
  if (!crypto::fill_random(as_span(secret_[0]))) {
    // Fail closed: keep the old secret rather than reuse a predictable one.
    secret_[0] = secret_[1];
    born_ms_[0] = born_ms_[1];
    return;
  }
  born_ms_[0] = now_ms;
  ++generation_;
}

Bytes<16> CookieChecker::cookie_for(const dataplane::SocketAddress& src,
                                    std::uint64_t now_ms) noexcept {
  rotate(now_ms);
  if (!have_secret_ || !src.valid()) return Bytes<16>{};
  return compute_cookie(secret_[0], src.address_bytes(), src.port);
}

bool CookieChecker::verify_mac2(ByteSpan msg, const dataplane::SocketAddress& src,
                                std::uint64_t now_ms) noexcept {
  const std::size_t offset = mac2_offset(msg.size());
  if (offset == 0 || !have_secret_ || !src.valid()) return false;
  rotate(now_ms);

  const ByteSpan before_mac2 = msg.first(offset);
  const ByteSpan carried = msg.subspan(offset, kMacSize);

  const Bytes<16> cookie_now = compute_cookie(secret_[0], src.address_bytes(), src.port);
  const Bytes<16> mac2_now = compute_mac2(before_mac2, cookie_now);
  if (ct::equal(as_span(mac2_now), carried)) return true;

  // The previous secret is still accepted while it has not aged out.
  if (born_ms_[1] == 0 || now_ms < born_ms_[1] || now_ms - born_ms_[1] >= 2 * kRotateMs) {
    return false;
  }
  const Bytes<16> cookie_old = compute_cookie(secret_[1], src.address_bytes(), src.port);
  const Bytes<16> mac2_old = compute_mac2(before_mac2, cookie_old);
  return ct::equal(as_span(mac2_old), carried);
}

Status CookieChecker::create_cookie_reply(ByteSpan refused_message,
                                          const dataplane::SocketAddress& src,
                                          std::uint64_t now_ms,
                                          MutableByteSpan out_64) noexcept {
  if (!initialized_) return make_error(ErrorCode::kInternal, "cookie checker is not initialised");
  const std::size_t mac1_at = mac1_offset_for(refused_message.size());
  if (mac1_at == 0) return bad_cookie_message("cookie reply: refused message has no mac1");
  if (out_64.size() < kCookieReplySize) {
    return make_error(ErrorCode::kInvalidArgument, "cookie reply: output buffer too small");
  }
  if (!src.valid()) {
    return make_error(ErrorCode::kInvalidArgument, "cookie reply: no source address");
  }

  CookieReply reply;
  reply.receiver_index = load_le32(refused_message.data() + 4);
  if (!crypto::fill_random(as_span(reply.nonce))) {
    return make_error(ErrorCode::kInternal, "cookie reply: OS RNG unavailable");
  }

  const Bytes<16> cookie = cookie_for(src, now_ms);
  // The AAD is the mac1 of the refused message: the initiator computed it, so it
  // authenticates the reply without any shared secret.
  const ByteSpan aad = refused_message.subspan(mac1_at, kMacSize);
  if (!crypto::xchacha20poly1305_seal(as_span(reply.encrypted_cookie), as_span(cookie), key_,
                                      reply.nonce, aad)) {
    return make_error(ErrorCode::kInternal, "cookie reply: encryption failed");
  }

  if (encode(reply, out_64) != kCookieReplySize) {
    return make_error(ErrorCode::kInternal, "cookie reply: encoding failed");
  }
  return {};
}

Status CookieChecker::open_cookie_reply(ByteSpan msg_64,
                                        const crypto::X25519PublicKey& responder_static,
                                        const Bytes<16>& sent_mac1,
                                        Bytes<16>& out_cookie) noexcept {
  if (msg_64.size() != kCookieReplySize) {
    return bad_cookie_message("cookie reply must be exactly 64 bytes");
  }
  if (load_le32(msg_64.data()) != static_cast<std::uint32_t>(MessageType::kCookieReply)) {
    return bad_cookie_message("not a cookie reply");
  }
  CookieReply reply;
  reply.receiver_index = load_le32(msg_64.data() + 4);
  for (std::size_t i = 0; i < kCookieNonceSize; ++i) reply.nonce[i] = msg_64[8 + i];
  for (std::size_t i = 0; i < reply.encrypted_cookie.size(); ++i) {
    reply.encrypted_cookie[i] = msg_64[32 + i];
  }
  if (reply.receiver_index == 0) return bad_cookie_message("cookie reply: zero receiver index");

  const Bytes<32> key = cookie_key(responder_static);
  Bytes<16> plain{};
  if (!crypto::xchacha20poly1305_open(as_span(plain), as_span(reply.encrypted_cookie), key,
                                      reply.nonce, as_span(sent_mac1))) {
    return make_error(ErrorCode::kUnauthenticated, "cookie reply failed authentication");
  }
  out_cookie = plain;
  secure_zero(as_span(plain));
  return {};
}

// --- HandshakeLimiter -------------------------------------------------------

HandshakeLimiter::HandshakeLimiter(const Options& options) noexcept : options_(options) {
  if (options_.threshold == 0) options_.threshold = 1;
  if (options_.window_ms == 0) options_.window_ms = 1;
}

void HandshakeLimiter::reset() noexcept {
  for (auto& slot : slots_) slot = Entry{};
}

bool HandshakeLimiter::record(const dataplane::SocketAddress& src, std::uint64_t now_ms) noexcept {
  // FNV-1a over address||port: cheap, no per-packet allocation, no crypto needed
  // (an attacker who can steer the hash only hurts itself).
  std::uint64_t hash = 1469598103934665603ULL;
  for (const Byte b : src.address_bytes()) {
    hash ^= b;
    hash *= 1099511628211ULL;
  }
  hash ^= src.port;
  hash *= 1099511628211ULL;
  const auto index = static_cast<std::size_t>(hash % kSlots);

  Entry& slot = slots_[index];
  const bool fresh = !slot.used || slot.addr != src || now_ms < slot.window_start_ms ||
                     now_ms - slot.window_start_ms >= options_.window_ms;
  if (fresh) {
    slot.addr = src;
    slot.window_start_ms = now_ms;
    slot.count = 1;
    slot.used = true;
    return options_.threshold <= 1;
  }
  if (slot.count < 0xFFFFFFFFU) ++slot.count;
  return slot.count > options_.threshold;
}

}  // namespace vpn::wire
