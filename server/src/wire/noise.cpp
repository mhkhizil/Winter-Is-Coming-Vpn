// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Noise_IKpsk2 (the WireGuard handshake) and the transport session that follows.
//
// Transcript rules follow wireguard-go exactly:
//   ck = HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
//   h  = HASH(ck || "WireGuard v1 zx2c4 Jason@zx2c4.com")
//   h  = HASH(h  || responder_static)
// and every message field is mixed into h before the next AEAD is sealed/opened.
// Any deviation here shows up as an authentication failure, never as a crash.
#include <cstdint>
#include "vpn/wire/noise.hpp"

#include <chrono>
#include <cstring>

#include "vpn/common/endian.hpp"
#include "vpn/crypto/blake2s.hpp"
#include "vpn/crypto/ct.hpp"
#include "vpn/crypto/kdf.hpp"
#include "vpn/crypto/random.hpp"
#include "vpn/crypto/x25519.hpp"

namespace vpn::wire {
namespace {
constexpr char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr std::size_t kConstructionLen = sizeof(kConstruction) - 1;
constexpr std::size_t kIdentifierLen = sizeof(kIdentifier) - 1;

// BLAKE2s-256 over the concatenation of up to four spans.
Bytes<32> hash_parts(ByteSpan a, ByteSpan b = {}, ByteSpan c = {}, ByteSpan d = {}) noexcept {
  crypto::Blake2s h{32, ByteSpan{}};
  h.update(a);
  h.update(b);
  h.update(c);
  h.update(d);
  Bytes<32> out{};
  (void)h.final(as_span(out));
  return out;
}

// TAI64N: 8-byte big-endian label + 4-byte big-endian nanoseconds. WireGuard uses
// it as a monotonic sequence value; we never compare it to our own clock.
void tai64n_now(Byte out[12]) noexcept {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto secs = time_point_cast<seconds>(now);
  const auto nanos = duration_cast<nanoseconds>(now - secs).count();
  const std::uint64_t label = 0x400000000000000AULL + static_cast<std::uint64_t>(secs.time_since_epoch().count());
  store_be64(out, label);
  store_be32(out + 8, static_cast<std::uint32_t>(nanos));
}

void mix_hash(Bytes<32>& h, ByteSpan data) noexcept { h = hash_parts(as_span(h), data); }

void mix_key(Bytes<32>& chaining_key, ByteSpan input) noexcept {
  Bytes<32> out{};
  (void)crypto::kdf(as_span(chaining_key), input, as_span(out));
  chaining_key = out;
  ::vpn::ct::cleanse(as_span(out));
}


struct NoiseState {
  enum class Role { kInitiator, kResponder };
  enum class Step { kIdle, kInitiationSent, kInitiationReceived, kResponseSent, kDone };

  Role role{Role::kInitiator};
  Step step{Step::kIdle};
  crypto::X25519KeyPair self{};
  crypto::X25519PublicKey peer_static{};
  crypto::X25519PrivateKey ephemeral_priv{};
  crypto::X25519PublicKey ephemeral_pub{};
  crypto::X25519PublicKey peer_ephemeral{};
  Bytes<32> chaining_key{};
  Bytes<32> hash{};
  std::uint32_t local_index{0};
  std::uint32_t remote_index{0};
  TunnelKeys keys{};
  bool have_keys{false};
};

void derive_base(Bytes<32>& ck, Bytes<32>& h) noexcept {
  ck = hash_parts(ByteSpan{reinterpret_cast<const Byte*>(kConstruction), kConstructionLen});
  h = hash_parts(as_span(ck), ByteSpan{reinterpret_cast<const Byte*>(kIdentifier), kIdentifierLen});
}

// AEAD over the handshake keys (12-byte all-zero nonce).
bool seal_with(MutableByteSpan dst, ByteSpan plaintext, const Bytes<32>& key,
               ByteSpan aad) noexcept {
  const crypto::AeadNonce nonce{};
  crypto::AeadKey k{};
  for (std::size_t i = 0; i < k.size(); ++i) k[i] = key[i];
  const bool ok = crypto::chacha20poly1305_seal(dst, plaintext, k, nonce, aad);
  ::vpn::ct::cleanse(as_span(k));
  return ok;
}

bool open_with(MutableByteSpan dst, ByteSpan ciphertext, const Bytes<32>& key,
               ByteSpan aad) noexcept {
  const crypto::AeadNonce nonce{};
  crypto::AeadKey k{};
  for (std::size_t i = 0; i < k.size(); ++i) k[i] = key[i];
  const bool ok = crypto::chacha20poly1305_open(dst, ciphertext, k, nonce, aad);
  ::vpn::ct::cleanse(as_span(k));
  return ok;
}

// KDF2: returns the new chaining key and a one-time AEAD key.
void kdf2(Bytes<32>& chaining_key, ByteSpan input, Bytes<32>& key_out) noexcept {
  Bytes<64> out{};
  (void)crypto::kdf(as_span(chaining_key), input, as_span(out));
  for (std::size_t i = 0; i < 32; ++i) chaining_key[i] = out[i];
  for (std::size_t i = 0; i < 32; ++i) key_out[i] = out[32 + i];
  ::vpn::ct::cleanse(as_span(out));
}

}  // namespace

// The pimpl *is* the state: inheriting keeps the `impl_->field` call sites tidy
// and avoids a second indirection on the handshake path.
struct NoiseIk::Impl : NoiseState {};

NoiseIk::NoiseIk() noexcept : impl_(new Impl()) {}

NoiseIk::~NoiseIk() noexcept {
  reset();
  delete impl_;
}

NoiseIk::NoiseIk(NoiseIk&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }

NoiseIk& NoiseIk::operator=(NoiseIk&& other) noexcept {
  if (this != &other) {
    reset();
    delete impl_;
    impl_ = other.impl_;
    other.impl_ = nullptr;
  }
  return *this;
}

Result<NoiseIk> NoiseIk::initiator(const crypto::X25519KeyPair& self,
                                   const crypto::X25519PublicKey& peer_static) {
  if (is_zero(as_span(self.private_key)) || is_zero(as_span(peer_static))) {
    return Status{ErrorCode::kInvalidArgument, "handshake keys are empty"};
  }
  NoiseIk hs;
  hs.impl_->role = NoiseState::Role::kInitiator;
  hs.impl_->self = self;
  hs.impl_->peer_static = peer_static;
  derive_base(hs.impl_->chaining_key, hs.impl_->hash);
  mix_hash(hs.impl_->hash, as_span(peer_static));
  return hs;
}

Result<NoiseIk> NoiseIk::responder(const crypto::X25519KeyPair& self) {
  if (is_zero(as_span(self.private_key))) {
    return Status{ErrorCode::kInvalidArgument, "responder key is empty"};
  }
  NoiseIk hs;
  hs.impl_->role = NoiseState::Role::kResponder;
  hs.impl_->self = self;
  derive_base(hs.impl_->chaining_key, hs.impl_->hash);
  // The responder mixes its OWN static public key, exactly as the initiator does.
  mix_hash(hs.impl_->hash, as_span(self.public_key));
  return hs;
}

Status NoiseIk::create_initiation(MutableByteSpan out_148) noexcept {
  if (impl_ == nullptr || impl_->role != NoiseState::Role::kInitiator) {
    return Status{ErrorCode::kInternal, "create_initiation on a responder"};
  }
  if (out_148.size() < kHandshakeInitiationSize) {
    return Status{ErrorCode::kInvalidArgument, "initiation buffer too small"};
  }
  crypto::X25519KeyPair ephemeral{};
  if (!crypto::x25519_generate(ephemeral) || !crypto::random_index(impl_->local_index)) {
    return Status{ErrorCode::kInternal, "OS random source failed"};
  }
  impl_->ephemeral_priv = ephemeral.private_key;
  impl_->ephemeral_pub = ephemeral.public_key;

  HandshakeInitiation msg{};
  msg.sender_index = impl_->local_index;
  msg.ephemeral = impl_->ephemeral_pub;
  mix_hash(impl_->hash, as_span(msg.ephemeral));
  mix_key(impl_->chaining_key, as_span(msg.ephemeral));

  // es = DH(ephemeral_private, responder_static)
  crypto::X25519PublicKey es{};
  if (!crypto::x25519(es, impl_->ephemeral_priv, impl_->peer_static)) {
    return Status{ErrorCode::kInvalidArgument, "peer static key is low order"};
  }
  Bytes<32> temp_key{};
  kdf2(impl_->chaining_key, as_span(es), temp_key);
  if (!seal_with(as_span(msg.encrypted_static), as_span(impl_->self.public_key), temp_key,
                 as_span(impl_->hash))) {
    return Status{ErrorCode::kInternal, "cannot seal the static key"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_static));

  // ss = DH(initiator_static_private, responder_static)
  crypto::X25519PublicKey ss{};
  if (!crypto::x25519(ss, impl_->self.private_key, impl_->peer_static)) {
    return Status{ErrorCode::kInvalidArgument, "peer static key is low order"};
  }
  kdf2(impl_->chaining_key, as_span(ss), temp_key);

  Byte timestamp[kTimestampSize] = {};
  tai64n_now(timestamp);
  if (!seal_with(as_span(msg.encrypted_timestamp), ByteSpan{timestamp, sizeof(timestamp)},
                 temp_key, as_span(impl_->hash))) {
    return Status{ErrorCode::kInternal, "cannot seal the timestamp"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_timestamp));

  if (encode(msg, out_148) != kHandshakeInitiationSize) {
    return Status{ErrorCode::kInternal, "cannot encode the initiation"};
  }
  const Bytes<16> mac1 =
      compute_mac1(ByteSpan{out_148.data(), kHandshakeInitiationSize - kMacSize * 2},
                   impl_->peer_static);
  for (std::size_t i = 0; i < mac1.size(); ++i) out_148[116 + i] = mac1[i];
  for (std::size_t i = 0; i < kMacSize; ++i) out_148[132 + i] = 0;  // mac2: no cookie yet

  impl_->step = NoiseState::Step::kInitiationSent;
  ::vpn::ct::cleanse(as_span(temp_key));
  ::vpn::ct::cleanse(MutableByteSpan{timestamp, sizeof(timestamp)});
  ::vpn::ct::cleanse(as_span(es));
  ::vpn::ct::cleanse(as_span(ss));
  return Status{};
}

bool NoiseIk::verify_mac1(ByteSpan msg, const crypto::X25519PublicKey& self) noexcept {
  if (msg.size() < kHandshakeInitiationSize) return false;
  const Bytes<16> expected =
      compute_mac1(ByteSpan{msg.data(), kHandshakeInitiationSize - kMacSize * 2}, self);
  return ::vpn::ct::equal(as_span(expected),
                           ByteSpan{msg.data() + kHandshakeInitiationSize - kMacSize * 2, kMacSize});
}

Status NoiseIk::consume_initiation(ByteSpan msg_148,
                                   crypto::X25519PublicKey& learned_static) noexcept {
  if (impl_ == nullptr || impl_->role != NoiseState::Role::kResponder) {
    return Status{ErrorCode::kInternal, "consume_initiation on an initiator"};
  }
  if (!verify_mac1(msg_148, impl_->self.public_key)) {
    return Status{ErrorCode::kMalformed, "mac1 verification failed"};
  }
  auto decoded = decode(msg_148);
  if (!decoded || decoded->type != MessageType::kHandshakeInitiation) {
    return Status{ErrorCode::kMalformed, "not a handshake initiation"};
  }
  const HandshakeInitiation& msg = decoded->initiation;

  impl_->remote_index = msg.sender_index;
  impl_->peer_ephemeral = msg.ephemeral;
  mix_hash(impl_->hash, as_span(msg.ephemeral));
  mix_key(impl_->chaining_key, as_span(msg.ephemeral));

  // es = DH(responder_static_private, initiator_ephemeral)
  crypto::X25519PublicKey es{};
  if (!crypto::x25519(es, impl_->self.private_key, impl_->peer_ephemeral)) {
    return Status{ErrorCode::kMalformed, "ephemeral key is low order"};
  }
  Bytes<32> temp_key{};
  kdf2(impl_->chaining_key, as_span(es), temp_key);

  crypto::X25519PublicKey initiator_static{};
  if (!open_with(as_span(initiator_static), as_span(msg.encrypted_static), temp_key,
                 as_span(impl_->hash))) {
    return Status{ErrorCode::kMalformed, "cannot open the static key"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_static));

  // ss = DH(responder_static_private, initiator_static)
  crypto::X25519PublicKey ss{};
  if (!crypto::x25519(ss, impl_->self.private_key, initiator_static)) {
    return Status{ErrorCode::kMalformed, "static key is low order"};
  }
  kdf2(impl_->chaining_key, as_span(ss), temp_key);

  Byte timestamp[kTimestampSize] = {};
  if (!open_with(MutableByteSpan{timestamp, sizeof(timestamp)},
                 as_span(msg.encrypted_timestamp), temp_key, as_span(impl_->hash))) {
    return Status{ErrorCode::kMalformed, "cannot open the timestamp"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_timestamp));

  impl_->peer_static = initiator_static;
  learned_static = initiator_static;
  impl_->step = NoiseState::Step::kInitiationReceived;
  ::vpn::ct::cleanse(as_span(temp_key));
  ::vpn::ct::cleanse(MutableByteSpan{timestamp, sizeof(timestamp)});
  ::vpn::ct::cleanse(as_span(es));
  ::vpn::ct::cleanse(as_span(ss));
  return Status{};
}

Status NoiseIk::create_response(MutableByteSpan out_92) noexcept {
  if (impl_ == nullptr || impl_->role != NoiseState::Role::kResponder ||
      impl_->step != NoiseState::Step::kInitiationReceived) {
    return Status{ErrorCode::kInternal, "create_response without an initiation"};
  }
  if (out_92.size() < kHandshakeResponseSize) {
    return Status{ErrorCode::kInvalidArgument, "response buffer too small"};
  }
  crypto::X25519KeyPair ephemeral{};
  if (!crypto::x25519_generate(ephemeral) || !crypto::random_index(impl_->local_index)) {
    return Status{ErrorCode::kInternal, "OS random source failed"};
  }
  impl_->ephemeral_priv = ephemeral.private_key;
  impl_->ephemeral_pub = ephemeral.public_key;

  HandshakeResponse msg{};
  msg.sender_index = impl_->local_index;
  msg.receiver_index = impl_->remote_index;
  msg.ephemeral = impl_->ephemeral_pub;
  mix_hash(impl_->hash, as_span(msg.ephemeral));
  mix_key(impl_->chaining_key, as_span(msg.ephemeral));

  // ee = DH(responder_ephemeral, initiator_ephemeral)
  crypto::X25519PublicKey ee{};
  if (!crypto::x25519(ee, impl_->ephemeral_priv, impl_->peer_ephemeral)) {
    return Status{ErrorCode::kMalformed, "ephemeral key is low order"};
  }
  mix_key(impl_->chaining_key, as_span(ee));

  // se = DH(responder_ephemeral, initiator_static)
  crypto::X25519PublicKey se{};
  if (!crypto::x25519(se, impl_->ephemeral_priv, impl_->peer_static)) {
    return Status{ErrorCode::kMalformed, "static key is low order"};
  }
  mix_key(impl_->chaining_key, as_span(se));

  // psk step: no pre-shared key in v1 => 32 zero bytes.
  const Bytes<32> psk{};
  Bytes<96> kdf3{};
  (void)crypto::kdf(as_span(impl_->chaining_key), as_span(psk), as_span(kdf3));
  for (std::size_t i = 0; i < 32; ++i) impl_->chaining_key[i] = kdf3[i];
  Bytes<32> tau{};
  Bytes<32> temp_key{};
  for (std::size_t i = 0; i < 32; ++i) tau[i] = kdf3[32 + i];
  for (std::size_t i = 0; i < 32; ++i) temp_key[i] = kdf3[64 + i];
  mix_hash(impl_->hash, as_span(tau));

  if (!seal_with(as_span(msg.encrypted_nothing), ByteSpan{}, temp_key, as_span(impl_->hash))) {
    return Status{ErrorCode::kInternal, "cannot seal the empty payload"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_nothing));

  // Transport keys: KDF2(ck, empty) -> (t1, t2); responder sends t2, receives t1.
  Bytes<64> pair{};
  (void)crypto::kdf(as_span(impl_->chaining_key), ByteSpan{}, as_span(pair));
  for (std::size_t i = 0; i < 32; ++i) impl_->keys.recv_key[i] = pair[i];
  for (std::size_t i = 0; i < 32; ++i) impl_->keys.send_key[i] = pair[32 + i];
  impl_->keys.local_index = impl_->local_index;
  impl_->keys.remote_index = impl_->remote_index;
  impl_->keys.handshake_hash = impl_->hash;
  impl_->have_keys = true;

  if (encode(msg, out_92) != kHandshakeResponseSize) {
    return Status{ErrorCode::kInternal, "cannot encode the response"};
  }
  const Bytes<16> mac1 =
      compute_mac1(ByteSpan{out_92.data(), kHandshakeResponseSize - kMacSize * 2},
                   impl_->peer_static);
  for (std::size_t i = 0; i < mac1.size(); ++i) out_92[60 + i] = mac1[i];
  for (std::size_t i = 0; i < kMacSize; ++i) out_92[76 + i] = 0;

  impl_->step = NoiseState::Step::kDone;
  ::vpn::ct::cleanse(as_span(temp_key));
  ::vpn::ct::cleanse(as_span(tau));
  ::vpn::ct::cleanse(MutableByteSpan{reinterpret_cast<Byte*>(&kdf3), sizeof(kdf3)});
  ::vpn::ct::cleanse(as_span(pair));
  ::vpn::ct::cleanse(as_span(ee));
  ::vpn::ct::cleanse(as_span(se));
  return Status{};
}

Status NoiseIk::consume_response(ByteSpan msg_92) noexcept {
  if (impl_ == nullptr || impl_->role != NoiseState::Role::kInitiator ||
      impl_->step != NoiseState::Step::kInitiationSent) {
    return Status{ErrorCode::kInternal, "consume_response without an initiation"};
  }
  if (msg_92.size() < kHandshakeResponseSize) {
    return Status{ErrorCode::kMalformed, "response too short"};
  }
  const Bytes<16> expected =
      // mac1 is keyed by the RECEIVER's static public key: for msg2 that is us.
      compute_mac1(ByteSpan{msg_92.data(), kHandshakeResponseSize - kMacSize * 2},
                   impl_->self.public_key);
  if (!::vpn::ct::equal(
          as_span(expected),
          ByteSpan{msg_92.data() + kHandshakeResponseSize - kMacSize * 2, kMacSize})) {
    return Status{ErrorCode::kMalformed, "mac1 verification failed"};
  }
  auto decoded = decode(msg_92);
  if (!decoded || decoded->type != MessageType::kHandshakeResponse) {
    return Status{ErrorCode::kMalformed, "not a handshake response"};
  }
  const HandshakeResponse& msg = decoded->response;
  if (msg.receiver_index != impl_->local_index) {
    return Status{ErrorCode::kMalformed, "response is for another session"};
  }

  impl_->remote_index = msg.sender_index;
  mix_hash(impl_->hash, as_span(msg.ephemeral));
  mix_key(impl_->chaining_key, as_span(msg.ephemeral));

  crypto::X25519PublicKey ee{};
  if (!crypto::x25519(ee, impl_->ephemeral_priv, msg.ephemeral)) {
    return Status{ErrorCode::kMalformed, "ephemeral key is low order"};
  }
  mix_key(impl_->chaining_key, as_span(ee));

  crypto::X25519PublicKey se{};
  if (!crypto::x25519(se, impl_->self.private_key, msg.ephemeral)) {
    return Status{ErrorCode::kMalformed, "ephemeral key is low order"};
  }
  mix_key(impl_->chaining_key, as_span(se));

  const Bytes<32> psk{};
  Bytes<96> kdf3{};
  (void)crypto::kdf(as_span(impl_->chaining_key), as_span(psk), as_span(kdf3));
  for (std::size_t i = 0; i < 32; ++i) impl_->chaining_key[i] = kdf3[i];
  Bytes<32> tau{};
  Bytes<32> temp_key{};
  for (std::size_t i = 0; i < 32; ++i) tau[i] = kdf3[32 + i];
  for (std::size_t i = 0; i < 32; ++i) temp_key[i] = kdf3[64 + i];
  mix_hash(impl_->hash, as_span(tau));

  Byte empty[1] = {};
  if (!open_with(MutableByteSpan{empty, 0}, as_span(msg.encrypted_nothing), temp_key,
                 as_span(impl_->hash))) {
    return Status{ErrorCode::kMalformed, "cannot open the empty payload"};
  }
  mix_hash(impl_->hash, as_span(msg.encrypted_nothing));

  Bytes<64> pair{};
  (void)crypto::kdf(as_span(impl_->chaining_key), ByteSpan{}, as_span(pair));
  for (std::size_t i = 0; i < 32; ++i) impl_->keys.send_key[i] = pair[i];
  for (std::size_t i = 0; i < 32; ++i) impl_->keys.recv_key[i] = pair[32 + i];
  impl_->keys.local_index = impl_->local_index;
  impl_->keys.remote_index = impl_->remote_index;
  impl_->keys.handshake_hash = impl_->hash;
  impl_->have_keys = true;

  impl_->step = NoiseState::Step::kDone;
  ::vpn::ct::cleanse(as_span(temp_key));
  ::vpn::ct::cleanse(as_span(tau));
  ::vpn::ct::cleanse(MutableByteSpan{reinterpret_cast<Byte*>(&kdf3), sizeof(kdf3)});
  ::vpn::ct::cleanse(as_span(pair));
  ::vpn::ct::cleanse(as_span(ee));
  ::vpn::ct::cleanse(as_span(se));
  return Status{};
}

bool NoiseIk::has_keys() const noexcept { return impl_ != nullptr && impl_->have_keys; }

const TunnelKeys& NoiseIk::keys() const noexcept {
  static const TunnelKeys kEmpty{};
  return impl_ == nullptr ? kEmpty : impl_->keys;
}

void NoiseIk::reset() noexcept {
  if (impl_ == nullptr) return;
  ::vpn::ct::cleanse(as_span(impl_->chaining_key));
  ::vpn::ct::cleanse(as_span(impl_->hash));
  ::vpn::ct::cleanse(as_span(impl_->ephemeral_priv));
  ::vpn::ct::cleanse(as_span(impl_->peer_static));
  ::vpn::ct::cleanse(as_span(impl_->keys.send_key));
  ::vpn::ct::cleanse(as_span(impl_->keys.recv_key));
  impl_->have_keys = false;
  impl_->step = NoiseState::Step::kIdle;
  impl_->local_index = 0;
  impl_->remote_index = 0;
}

TransportSession::TransportSession() noexcept = default;

Status TransportSession::init(const TunnelKeys& keys) noexcept {
  if (is_zero(as_span(keys.send_key)) || is_zero(as_span(keys.recv_key))) {
    return Status{ErrorCode::kInvalidArgument, "transport keys are empty"};
  }
  keys_ = keys;
  keys_.send_counter = 0;
  replay_.reset();
  ready_ = true;
  return Status{};
}

std::size_t TransportSession::seal(MutableByteSpan dst, ByteSpan inner_packet) noexcept {
  if (!ready_) return 0;
  if (inner_packet.size() > kMaxInnerPacketSize) return 0;
  const std::size_t total = kTransportHeaderSize + inner_packet.size() + kTransportTagSize;
  if (dst.size() < total) return 0;

  store_le32(dst.data(), static_cast<std::uint32_t>(MessageType::kTransportData));
  store_le32(dst.data() + 4, keys_.remote_index);
  store_le64(dst.data() + 8, keys_.send_counter);

  crypto::AeadKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = keys_.send_key[i];
  const bool ok = crypto::chacha20poly1305_seal(dst.subspan(kTransportHeaderSize), inner_packet,
                                                key, crypto::transport_nonce(keys_.send_counter),
                                                ByteSpan{});
  ::vpn::ct::cleanse(as_span(key));
  if (!ok) return 0;
  ++keys_.send_counter;
  return total;
}

Result<ByteSpan> TransportSession::open(MutableByteSpan datagram) noexcept {
  if (!ready_) {
    return Status{ErrorCode::kUnavailable, "no transport keys"};
  }
  if (datagram.size() < kEmptyKeepaliveSize) {
    return Status{ErrorCode::kMalformed, "datagram too short"};
  }
  auto decoded = decode(ByteSpan{datagram.data(), datagram.size()});
  if (!decoded || decoded->type != MessageType::kTransportData) {
    return Status{ErrorCode::kMalformed, "not a transport packet"};
  }
  if (decoded->transport.receiver_index != keys_.local_index) {
    return Status{ErrorCode::kNotFound, "packet is for another session"};
  }
  const std::uint64_t counter = decoded->transport.counter;
  const std::size_t payload_size = datagram.size() - kTransportOverhead;

  crypto::AeadKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = keys_.recv_key[i];
  const bool ok = crypto::chacha20poly1305_open(
      datagram.subspan(kTransportHeaderSize, payload_size),
      ByteSpan{datagram.data() + kTransportHeaderSize, payload_size + kTransportTagSize}, key,
      crypto::transport_nonce(counter), ByteSpan{});
  ::vpn::ct::cleanse(as_span(key));
  if (!ok) {
    return Status{ErrorCode::kMalformed, "authentication failed"};
  }
  // Only after the AEAD succeeded may the replay window learn this counter.
  if (!replay_.accept(counter)) {
    return Status{ErrorCode::kAlreadyExists, "replayed counter"};
  }
  return ByteSpan{datagram.data() + kTransportHeaderSize, payload_size};
}

std::uint32_t TransportSession::local_index() const noexcept { return keys_.local_index; }

void TransportSession::reset() noexcept {
  ::vpn::ct::cleanse(as_span(keys_.send_key));
  ::vpn::ct::cleanse(as_span(keys_.recv_key));
  keys_ = TunnelKeys{};
  replay_.reset();
  ready_ = false;
}

}  // namespace vpn::wire
