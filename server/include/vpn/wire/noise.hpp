// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Noise_IKpsk2 handshake as used by WireGuard, plus the transport session that
// comes out of it. This is the interface the data plane codes against; the
// implementation is server/src/wire/noise.cpp.
//
// Design rules:
//   * No allocation on any path; all buffers are caller-provided.
//   * Every failure is a Status; a failed handshake leaves no key material.
//   * The responder verifies mac1 before spending any DH operation, and the
//     cookie path is stateless (no per-source state until mac2 verifies).
#pragma once

#include <cstdint>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result.hpp"
#include "vpn/crypto/aead.hpp"
#include "vpn/crypto/x25519.hpp"
#include "vpn/wire/constants.hpp"
#include "vpn/wire/message.hpp"
#include "vpn/wire/replay_window.hpp"

namespace vpn::wire {

// One direction of transport keys plus the indices that route packets.
struct TunnelKeys {
  Bytes<32> send_key{};        // key for packets we send
  Bytes<32> recv_key{};        // key for packets we receive
  std::uint64_t send_counter{0};
  std::uint32_t local_index{0};   // our sender_index
  std::uint32_t remote_index{0};  // peer's sender_index
  Bytes<32> handshake_hash{};     // chaining value after the handshake (rekey/debug)
};

class NoiseIk {
 public:
  // Initiator: we know our static keypair and the responder's static public key.
  NoiseIk() noexcept;
  ~NoiseIk() noexcept;
  NoiseIk(const NoiseIk&) = delete;
  NoiseIk& operator=(const NoiseIk&) = delete;
  NoiseIk(NoiseIk&&) noexcept;
  NoiseIk& operator=(NoiseIk&&) noexcept;

  [[nodiscard]] static Result<NoiseIk> initiator(const crypto::X25519KeyPair& self,
                                                 const crypto::X25519PublicKey& peer_static);

  // Responder: knows only its own static keypair; learns the initiator's static
  // key from message 1.
  [[nodiscard]] static Result<NoiseIk> responder(const crypto::X25519KeyPair& self);

  // --- initiator ------------------------------------------------------------
  // Writes a 148-byte HandshakeInitiation (type, sender_index, ephemeral,
  // encrypted_static, encrypted_timestamp, mac1, mac2=zero) and records the
  // local index. Returns kInternal if called out of order.
  [[nodiscard]] Status create_initiation(MutableByteSpan out_148) noexcept;

  // Verifies mac1 and the responder's static key, decrypts the timestamp and
  // derives the transport keys. On success `keys()` is valid.
  [[nodiscard]] Status consume_response(ByteSpan msg_92) noexcept;

  // --- responder ------------------------------------------------------------
  // Stateless mac1 check: what the data plane runs before queueing a handshake.
  [[nodiscard]] static bool verify_mac1(ByteSpan msg, const crypto::X25519PublicKey& self) noexcept;

  // Decrypts the initiator's static key and timestamp. `learned_static` is the
  // peer identity the control plane must authorise before create_response().
  [[nodiscard]] Status consume_initiation(ByteSpan msg_148,
                                          crypto::X25519PublicKey& learned_static) noexcept;

  // Writes a 92-byte HandshakeResponse with a fresh local index and derives the
  // transport keys.
  [[nodiscard]] Status create_response(MutableByteSpan out_92) noexcept;

  // --- outcome --------------------------------------------------------------
  [[nodiscard]] bool has_keys() const noexcept;
  [[nodiscard]] const TunnelKeys& keys() const noexcept;

  // Wipes all secret state; the object is reusable for a new handshake.
  void reset() noexcept;

 private:
  struct Impl;
  Impl* impl_;
};

// Transport data plane: seal/open with the per-direction key and counter, plus
// the replay window for the receive direction.
class TransportSession {
 public:
  TransportSession() noexcept;

  [[nodiscard]] Status init(const TunnelKeys& keys) noexcept;

  // dst must hold inner.size() + kTransportOverhead. Returns the number of bytes
  // written (header + ciphertext + tag) or 0 if dst is too small.
  [[nodiscard]] std::size_t seal(MutableByteSpan dst, ByteSpan inner_packet) noexcept;

  // Verifies the counter against the replay window *after* successful AEAD, then
  // returns a view of the inner packet, decrypted in place inside `datagram`.
  [[nodiscard]] Result<ByteSpan> open(MutableByteSpan datagram) noexcept;

  [[nodiscard]] std::uint32_t local_index() const noexcept;
  void reset() noexcept;

 private:
  TunnelKeys keys_{};
  ReplayWindow replay_{};
  bool ready_{false};
};

}  // namespace vpn::wire
