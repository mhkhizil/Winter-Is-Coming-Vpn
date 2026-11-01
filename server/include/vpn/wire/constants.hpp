// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Every number the wire protocol depends on, in one place, with the doc
// reference next to it. Nothing here may be tuned without an ADR.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace vpn::wire {

// --- message sizes (bytes) ---------------------------------------------------
inline constexpr std::size_t kMacSize = 16;
inline constexpr std::size_t kKeySize = 32;
inline constexpr std::size_t kCookieSize = 16;
inline constexpr std::size_t kCookieNonceSize = 24;
inline constexpr std::size_t kTimestampSize = 12;              // TAI64N
inline constexpr std::size_t kEncryptedTimestampSize = 28;     // 12 + 16 tag
inline constexpr std::size_t kEncryptedStaticSize = 48;        // 32 + 16 tag
inline constexpr std::size_t kEncryptedNothingSize = 16;       //  0 + 16 tag

inline constexpr std::uint32_t kProtocolVersion = 1;
inline constexpr std::size_t kTypePrefixSize = 4;

inline constexpr std::size_t kHandshakeInitiationSize =
    kTypePrefixSize + 4 + kKeySize + kEncryptedStaticSize + kEncryptedTimestampSize + kMacSize +
    kMacSize;  // = 148
inline constexpr std::size_t kHandshakeResponseSize =
    kTypePrefixSize + 4 + 4 + kKeySize + kEncryptedNothingSize + kMacSize + kMacSize;  // = 92
inline constexpr std::size_t kCookieReplySize =
    kTypePrefixSize + 4 + kCookieNonceSize + kCookieSize + 16;  // = 64 (cookie AEAD tag)
inline constexpr std::size_t kTransportHeaderSize = kTypePrefixSize + 4 + 8;  // = 16
inline constexpr std::size_t kTransportTagSize = 16;
inline constexpr std::size_t kTransportOverhead = kTransportHeaderSize + kTransportTagSize;  // 32
inline constexpr std::size_t kEmptyKeepaliveSize = kTransportOverhead;                       // 32

// Maximum UDP payload we will ever parse. Larger datagrams are dropped without
// inspecting them (anti-amplification: our replies must stay smaller).
inline constexpr std::size_t kMaxDatagramSize = 65535;
// Largest inner packet we accept from a client (outer size - overhead).
inline constexpr std::size_t kMaxInnerPacketSize = kMaxDatagramSize - kTransportOverhead;

// --- labels (exact bytes; changing them breaks interop) ----------------------
inline constexpr char kMac1Label[] = "mac1----";  // 8 bytes, then server static pubkey
inline constexpr char kCookieLabel[] = "cookie--";  // 8 bytes, then server static pubkey

// --- timers (WireGuard §6.5 "Timers and Statelessness") ----------------------
inline constexpr std::chrono::seconds kRekeyAfterTime{120};
inline constexpr std::chrono::seconds kRejectAfterTime{180};
inline constexpr std::chrono::seconds kRekeyTimeout{5};
inline constexpr std::chrono::seconds kKeepaliveTimeout{10};
inline constexpr std::chrono::seconds kCookieRefreshTime{120};
inline constexpr std::chrono::milliseconds kRekeyTimeoutJitterMax{334};
inline constexpr std::chrono::seconds kHandshakeMaxAge{90};  // 18 attempts * 5 s

// --- message counters -------------------------------------------------------
inline constexpr std::uint64_t kRekeyAfterMessages = 1ULL << 60U;
// (2^64 - 2^13 - 1), matching wireguard-go's REJECT_AFTER_MESSAGES.
inline constexpr std::uint64_t kRejectAfterMessages =
    std::numeric_limits<std::uint64_t>::max() - (1ULL << 13U);

// --- replay window (RFC 6479 shape used by WireGuard) -----------------------
inline constexpr std::size_t kCounterWindowSize = 8128;
inline constexpr std::size_t kCounterBitsTotal = 8192;
inline constexpr std::size_t kCounterWords = kCounterBitsTotal / 64;  // 128 words

// --- MTU --------------------------------------------------------------------
inline constexpr std::uint16_t kDefaultMtu = 1420;
inline constexpr std::uint16_t kMinimumMtu = 1280;  // IPv6 minimum link MTU

}  // namespace vpn::wire
