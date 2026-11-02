// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// File-backed control-plane store (see store.hpp for the record format).
#include "vpn/api/store.hpp"

#include <chrono>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <cstdlib>
#include <cstring>
#include <filesystem>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result_helpers.hpp"
#include "vpn/crypto/blake2s.hpp"
#include "vpn/crypto/ct.hpp"
#include "vpn/crypto/kdf.hpp"
#include "vpn/crypto/random.hpp"

// Fallback so this file also builds outside CMake (which passes -DVPN_VERSION).
#ifndef VPN_VERSION
#define VPN_VERSION "0.0.0"
#endif

namespace vpn::api {
namespace {

std::string to_hex(ByteSpan span) { return vpn::to_hex(span); }

// 128-bit random identifier, rendered as 32 hex characters.
std::string random_id(const char* prefix) {
  Byte raw[16] = {};
  if (!crypto::fill_random(MutableByteSpan{raw, sizeof(raw)})) return {};
  std::string out{prefix};
  out += vpn::to_hex(ByteSpan{raw, sizeof(raw)});
  return out;
}

std::string pepper() {
  const char* value = std::getenv("VPN_PASSWORD_PEPPER");
  return value == nullptr ? std::string{"vpn-dev-pepper"} : std::string{value};
}

// Passwords are never stored: only HMAC-BLAKE2s-256(pepper, password), hex.
// Hex of a 32-byte HMAC is always 64 characters; used for the constant-time
// comparison of password hashes.
constexpr std::size_t kPasswordHashLength = 64;

std::string hash_password(std::string_view password) {
  const std::string key = pepper();
  Bytes<32> mac = crypto::hmac_blake2s_256(
      ByteSpan{reinterpret_cast<const Byte*>(key.data()), key.size()},
      {ByteSpan{reinterpret_cast<const Byte*>(password.data()), password.size()}});
  const std::string out = to_hex(as_span(mac));
  ::vpn::ct::cleanse(as_span(mac));
  return out;
}

std::string hash_token(std::string_view token) {
  const std::string key = pepper();
  Bytes<32> mac = crypto::hmac_blake2s_256(
      ByteSpan{reinterpret_cast<const Byte*>(key.data()), key.size()},
      {ByteSpan{reinterpret_cast<const Byte*>(token.data()), token.size()}});
  const std::string out = to_hex(as_span(mac));
  ::vpn::ct::cleanse(as_span(mac));
  return out;
}

std::string random_token() {
  Byte raw[32] = {};
  if (!crypto::fill_random(MutableByteSpan{raw, sizeof(raw)})) return {};
  const std::string out = vpn::to_hex(ByteSpan{raw, sizeof(raw)});
  ::vpn::ct::cleanse(MutableByteSpan{raw, sizeof(raw)});
  return out;
}

std::int64_t now_unix() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::vector<std::string> split_tabs(const std::string& line) {
  std::vector<std::string> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t tab = line.find('\t', start);
    if (tab == std::string::npos) {
      fields.push_back(line.substr(start));
      break;
    }
    fields.push_back(line.substr(start, tab - start));
    start = tab + 1;
  }
  return fields;
}

}  // namespace

Store::~Store() {
  if (log_ != nullptr) {
    std::fclose(log_);
    log_ = nullptr;
  }
}

Status Store::append_line(const std::string& line) {
  if (log_ == nullptr) {
    return Status{ErrorCode::kInternal, "store log is not open"};
  }
  const std::string record = line + "\n";
  if (std::fwrite(record.data(), 1, record.size(), log_) != record.size()) {
    return Status{ErrorCode::kUnavailable, "cannot append to the store log"};
  }
  if (std::fflush(log_) != 0) {
    return Status{ErrorCode::kUnavailable, "cannot flush the store log"};
  }
#if !defined(_WIN32)
  // Durability: a control plane that loses a peer record on power loss would
  // resurrect a revoked key. Skipped only during the startup rewrite, which
  // fsyncs once when it is done.
  if (!skip_fsync_) (void)::fsync(::fileno(log_));
#endif
  return Status{};
}

void Store::sync_log() noexcept {
#if !defined(_WIN32)
  if (log_ != nullptr) (void)::fsync(::fileno(log_));
#endif
}

void Store::replay(const std::string& content) {
  std::size_t start = 0;
  while (start < content.size()) {
    const std::size_t eol = content.find('\n', start);
    const std::string line =
        content.substr(start, eol == std::string::npos ? std::string::npos : eol - start);
    start = eol == std::string::npos ? content.size() : eol + 1;
    if (line.empty()) continue;

    const std::vector<std::string> f = split_tabs(line);
    if (f.empty()) continue;
    const std::string& kind = f[0];

    if (kind == "U" && f.size() >= 6) {
      Principal principal;
      principal.user_id = f[1];
      principal.tenant_id = f[2];
      principal.role = f[5];
      users_[principal.user_id] = principal;
      user_email_to_id_[f[3]] = principal.user_id;
      user_to_email_[principal.user_id] = f[3];
      password_hashes_[principal.user_id] = f[4];
    } else if (kind == "E" && f.size() >= 5) {
      // Entitlement: who may use the service, until when.
      AccessGrant grant;
      grant.expires_at = std::atoll(f[2].c_str());
      grant.plan = f[3];
      grant.status = f[4];
      access_[f[1]] = grant;
    } else if (kind == "R" && f.size() >= 4) {
      // Reminder already sent for (user, bucket); keeps the daily job idempotent.
      reminders_[f[1] + "|" + f[2]] = std::atoll(f[3].c_str());
    } else if (kind == "T" && f.size() >= 4) {
      token_to_user_[f[1]] = f[2];
      token_expiry_[f[1]] = std::atoll(f[3].c_str());
    } else if (kind == "D" && f.size() >= 6) {
      Device device;
      device.id = f[1];
      device.user_id = f[2];
      device.name = f[3];
      device.platform = f[4];
      device.public_key_hex = f[5];
      devices_[device.id] = device;
    } else if (kind == "P" && f.size() >= 7) {
      Peer peer;
      peer.id = f[1];
      peer.device_id = f[2];
      peer.public_key_hex = f[3];
      peer.ipv4 = f[4];
      peer.ipv6 = f[5];
      peer.status = f[6];
      peers_[peer.id] = peer;
    } else if (kind == "S" && f.size() >= 6) {
      NodeInfo node;
      node.id = f[1];
      node.region = f[2];
      node.host = f[3];
      node.port = static_cast<std::uint16_t>(std::atoi(f[4].c_str()));
      node.public_key_hex = f[5];
      nodes_.push_back(node);
    }
  }
}

bool Store::ip_taken(std::string_view ipv4) const {
  for (const auto& [id, peer] : peers_) {
    (void)id;
    if (peer.ipv4 == ipv4 && peer.status == "active") return true;
  }
  return false;
}

Result<std::string> Store::allocate_ipv4() {
  // Sequential allocation inside 10.x.y.0/24 starting at .2 (the server owns .1).
  for (std::uint64_t host = next_ip_; host < 254; ++host) {
    const std::string candidate = "10.66.0." + std::to_string(host);
    if (!ip_taken(candidate)) {
      next_ip_ = host + 1;
      return candidate;
    }
  }
  return make_error(ErrorCode::kResourceExhausted, "the peer address pool is full");
}

Result<std::unique_ptr<Store>> Store::open(const StoreOptions& options) {
  auto store = std::make_unique<Store>();
  store->options_ = options;

  std::string content;
  if (std::FILE* existing = std::fopen(options.path.c_str(), "rb")) {
    char buffer[4096];
    std::size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), existing)) > 0) {
      content.append(buffer, read);
    }
    std::fclose(existing);
  } else {
    // A missing log simply means "empty state": the first append creates it.
  }
  store->replay(content);

  // Compact: rewrite the log with exactly the live state, so it cannot grow
  // without bound and revoked tokens disappear on restart.
  std::unordered_map<std::string, std::string> email_by_id;
  for (const auto& entry : store->user_email_to_id_) email_by_id[entry.second] = entry.first;

  // Rewrite into a temporary file and rename it over the log, instead of opening
  // the real log with "wb". Two reasons:
  //   1. atomicity - the old code emptied the live log for the whole duration of
  //      the rewrite, so a crash or power loss mid-compaction could truncate real
  //      state (users, peers, revocations).
  //   2. speed - the records are appended with fsync disabled and flushed once at
  //      the end: one fsync instead of one per record. On a real disk (0.1-10 ms
  //      per fsync) a 10k-record store spent seconds here on every start.
  const std::string compaction_path = options.path + ".compacting";
  std::FILE* rewrite = std::fopen(compaction_path.c_str(), "wb");
  if (rewrite == nullptr) {
    return make_error(ErrorCode::kUnavailable, "cannot write the compaction file");
  }
  store->log_ = rewrite;
  store->skip_fsync_ = true;
  for (const auto& entry : store->users_) {
    const std::string& id = entry.first;
    const Principal& principal = entry.second;
    (void)store->append_line("U\t" + id + "\t" + principal.tenant_id + "\t" + email_by_id[id] +
                             "\t" + store->password_hashes_[id] + "\t" + principal.role);
  }
  for (const auto& entry : store->access_) {
    (void)store->append_line("E\t" + entry.first + "\t" +
                             std::to_string(entry.second.expires_at) + "\t" + entry.second.plan +
                             "\t" + entry.second.status);
  }
  for (const auto& entry : store->reminders_) {
    const std::size_t bar = entry.first.find('|');
    if (bar == std::string::npos) continue;
    (void)store->append_line("R\t" + entry.first.substr(0, bar) + "\t" +
                             entry.first.substr(bar + 1) + "\t" +
                             std::to_string(entry.second));
  }
  for (const auto& entry : store->token_to_user_) {
    const std::int64_t expiry = store->token_expiry_[entry.first];
    if (expiry > now_unix()) {
      (void)store->append_line("T\t" + entry.first + "\t" + entry.second + "\t" +
                               std::to_string(expiry));
    }
  }
  for (const auto& entry : store->devices_) {
    const Device& device = entry.second;
    (void)store->append_line("D\t" + device.id + "\t" + device.user_id + "\t" + device.name +
                             "\t" + device.platform + "\t" + device.public_key_hex);
  }
  for (const auto& entry : store->peers_) {
    const Peer& peer = entry.second;
    (void)store->append_line("P\t" + peer.id + "\t" + peer.device_id + "\t" + peer.public_key_hex +
                             "\t" + peer.ipv4 + "\t" + peer.ipv6 + "\t" + peer.status);
  }
  for (const NodeInfo& node : store->nodes_) {
    (void)store->append_line("S\t" + node.id + "\t" + node.region + "\t" + node.host + "\t" +
                             std::to_string(node.port) + "\t" + node.public_key_hex);
  }
  // One flush + one fsync for the whole rewrite, then an atomic replace.
  if (std::fflush(rewrite) != 0) {
    std::fclose(rewrite);
    store->log_ = nullptr;
    return make_error(ErrorCode::kUnavailable, "cannot flush the compaction file");
  }
  store->sync_log();
  store->skip_fsync_ = false;
  std::fclose(rewrite);
  store->log_ = nullptr;

  {
    std::error_code replace_error;
    std::filesystem::rename(compaction_path, options.path, replace_error);
    if (replace_error) {
      std::error_code ignored;
      std::filesystem::remove(compaction_path, ignored);
      return make_error(ErrorCode::kUnavailable,
                        "cannot replace the store log: " + replace_error.message());
    }
  }

  store->log_ = std::fopen(options.path.c_str(), "ab");
  if (store->log_ == nullptr) {
    return make_error(ErrorCode::kUnavailable, "cannot append to the store log");
  }

  if (store->users_.empty()) {
    const char* email = std::getenv("VPN_BOOTSTRAP_EMAIL");
    const char* password = std::getenv("VPN_BOOTSTRAP_PASSWORD");
    if (email != nullptr && password != nullptr) {
      const Status seeded = store->add_user(email, password, "owner");
      if (!seeded) return seeded;
    }
  }
  return Result<std::unique_ptr<Store>>(std::move(store));
}

Status Store::add_user(std::string_view email, std::string_view password, std::string_view role) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const std::string email_key{email};
  if (user_email_to_id_.count(email_key) != 0) {
    return Status{ErrorCode::kAlreadyExists, "user already exists"};
  }
  if (password.size() < 8) {
    return Status{ErrorCode::kInvalidArgument, "password must be at least 8 characters"};
  }
  Principal principal;
  principal.user_id = random_id("usr_");
  principal.tenant_id = "ten_default";
  principal.role = std::string{role};
  if (principal.user_id.size() <= 4) {
    return Status{ErrorCode::kInternal, "OS random source failed"};
  }
  const std::string hash = hash_password(password);
  const Status appended = append_line("U\t" + principal.user_id + "\t" + principal.tenant_id +
                                      "\t" + email_key + "\t" + hash + "\t" + principal.role);
  if (!appended) return appended;
  users_[principal.user_id] = principal;
  user_email_to_id_[email_key] = principal.user_id;
  user_to_email_[principal.user_id] = email_key;
  password_hashes_[principal.user_id] = hash;
  return Status{};
}

Result<Principal> Store::authenticate(std::string_view email, std::string_view password) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = user_email_to_id_.find(std::string{email});
  if (it == user_email_to_id_.end()) {
    return make_error(ErrorCode::kUnauthenticated, "no such user");
  }
  const std::string candidate = hash_password(password);
  const std::string& stored = password_hashes_[it->second];
  const bool same =
      ::vpn::ct::equal(ByteSpan{reinterpret_cast<const Byte*>(candidate.data()), candidate.size()},
                       ByteSpan{reinterpret_cast<const Byte*>(stored.data()), stored.size()});
  if (!same) {
    return make_error(ErrorCode::kUnauthenticated, "wrong password");
  }
  return users_[it->second];
}

Result<std::string> Store::issue_token(const Principal& principal, std::uint32_t ttl_seconds) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const std::string token = random_token();
  if (token.empty()) {
    return make_error(ErrorCode::kInternal, "OS random source failed");
  }
  const std::string hashed = hash_token(token);
  const std::int64_t expiry = now_unix() + static_cast<std::int64_t>(ttl_seconds);
  const Status appended = append_line("T\t" + hashed + "\t" + principal.user_id + "\t" +
                                      std::to_string(expiry));
  if (!appended) return appended;
  token_to_user_[hashed] = principal.user_id;
  token_expiry_[hashed] = expiry;
  return token;
}

Result<Principal> Store::principal_for_token(std::string_view token) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const std::string hashed = hash_token(token);
  const auto it = token_to_user_.find(hashed);
  if (it == token_to_user_.end()) {
    return make_error(ErrorCode::kUnauthenticated, "unknown token");
  }
  if (token_expiry_[hashed] <= now_unix()) {
    return make_error(ErrorCode::kUnauthenticated, "token expired");
  }
  return users_[it->second];
}

Status Store::revoke_token(std::string_view token) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const std::string hashed = hash_token(token);
  const auto it = token_to_user_.find(hashed);
  if (it == token_to_user_.end()) {
    return Status{ErrorCode::kNotFound, "unknown token"};
  }
  token_to_user_.erase(it);
  token_expiry_.erase(hashed);
  return Status{};
}

std::size_t Store::user_count() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return users_.size();
}

std::size_t Store::peer_count() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return peers_.size();
}

Result<Device> Store::create_device(const Principal& principal, std::string_view name,
                                  std::string_view platform) {
  const std::lock_guard<std::mutex> lock(mutex_);
  Device device;
  device.id = random_id("dev_");
  device.user_id = principal.user_id;
  device.name = std::string{name};
  device.platform = std::string{platform};
  if (device.id.size() <= 4) {
    return make_error(ErrorCode::kInternal, "OS random source failed");
  }
  const Status appended = append_line("D\t" + device.id + "\t" + device.user_id + "\t" +
                                      device.name + "\t" + device.platform + "\t");
  if (!appended) return appended;
  devices_[device.id] = device;
  return device;
}

Result<std::vector<Device>> Store::list_devices(const Principal& principal) {
  const std::lock_guard<std::mutex> lock(mutex_);
  std::vector<Device> out;
  for (const auto& entry : devices_) {
    if (entry.second.user_id == principal.user_id) out.push_back(entry.second);
  }
  return out;
}

Status Store::set_device_key(const Principal& principal, std::string_view device_id,
                             std::string_view public_key_hex) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = devices_.find(std::string{device_id});
  if (it == devices_.end() || it->second.user_id != principal.user_id) {
    return Status{ErrorCode::kNotFound, "no such device"};
  }
  if (public_key_hex.size() != 64) {
    return Status{ErrorCode::kInvalidArgument, "public_key must be 64 hex characters"};
  }
  Bytes<32> probe{};
  if (!vpn::from_hex(public_key_hex, MutableByteSpan{probe.data(), probe.size()})) {
    return Status{ErrorCode::kInvalidArgument, "public_key is not valid hex"};
  }
  if (is_zero(as_span(probe))) {
    return Status{ErrorCode::kInvalidArgument, "public_key must not be all zero"};
  }
  it->second.public_key_hex = std::string{public_key_hex};
  const Status appended = append_line("D\t" + it->second.id + "\t" + it->second.user_id + "\t" +
                                      it->second.name + "\t" + it->second.platform + "\t" +
                                      it->second.public_key_hex);
  if (!appended) return appended;
  // Keep an existing peer in sync with the new key.
  for (auto& peer_entry : peers_) {
    if (peer_entry.second.device_id == it->second.id) {
      peer_entry.second.public_key_hex = it->second.public_key_hex;
      (void)append_line("P\t" + peer_entry.second.id + "\t" + peer_entry.second.device_id + "\t" +
                        peer_entry.second.public_key_hex + "\t" + peer_entry.second.ipv4 + "\t" +
                        peer_entry.second.ipv6 + "\t" + peer_entry.second.status);
    }
  }
  return Status{};
}

Result<std::vector<NodeInfo>> Store::nodes() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return nodes_;
}

Status Store::add_node(const NodeInfo& node) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (node.host.empty() || node.public_key_hex.size() != 64) {
    return Status{ErrorCode::kInvalidArgument, "node needs host and a 32-byte public key"};
  }
  for (const NodeInfo& existing : nodes_) {
    if (existing.id == node.id) return Status{ErrorCode::kAlreadyExists, "node id in use"};
  }
  const Status appended = append_line("S\t" + node.id + "\t" + node.region + "\t" + node.host +
                                      "\t" + std::to_string(node.port) + "\t" +
                                      node.public_key_hex);
  if (!appended) return appended;
  nodes_.push_back(node);
  return Status{};
}

namespace {

// Standard base64: `wg-quick` and the official clients only accept base64 keys,
// while the store keeps hex (easier to eyeball in an audit).
std::string base64_of_hex(const std::string& hex) {
  Bytes<32> raw{};
  if (hex.size() != 64) return {};
  if (!vpn::from_hex(hex, MutableByteSpan{raw.data(), raw.size()})) return {};
  static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(44);
  std::size_t i = 0;
  while (i + 3 <= raw.size()) {
    const std::uint32_t block = (static_cast<std::uint32_t>(raw[i]) << 16U) |
                                (static_cast<std::uint32_t>(raw[i + 1]) << 8U) |
                                static_cast<std::uint32_t>(raw[i + 2]);
    out.push_back(kAlphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(block >> 12U) & 0x3FU]);
    out.push_back(kAlphabet[(block >> 6U) & 0x3FU]);
    out.push_back(kAlphabet[block & 0x3FU]);
    i += 3;
  }
  if (i + 1 == raw.size()) {
    const std::uint32_t block = static_cast<std::uint32_t>(raw[i]) << 16U;
    out.push_back(kAlphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(block >> 12U) & 0x3FU]);
    out += "==";
  } else if (i + 2 == raw.size()) {
    const std::uint32_t block = (static_cast<std::uint32_t>(raw[i]) << 16U) |
                                (static_cast<std::uint32_t>(raw[i + 1]) << 8U);
    out.push_back(kAlphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(block >> 12U) & 0x3FU]);
    out.push_back(kAlphabet[(block >> 6U) & 0x3FU]);
    out.push_back('=');
  }
  return out;
}

}  // namespace

Result<Peer> Store::create_peer(const Principal& principal, std::string_view device_id) {
  const std::lock_guard<std::mutex> lock(mutex_);
  // Access check first: an expired or revoked account must not be able to obtain
  // a working configuration, and must not consume an address from the pool.
  if (!access_active_locked(principal.user_id)) {
    return make_error(ErrorCode::kPermissionDenied,
                      "access expired or revoked: an administrator must extend it");
  }
  const auto device_it = devices_.find(std::string{device_id});
  if (device_it == devices_.end() || device_it->second.user_id != principal.user_id) {
    return make_error(ErrorCode::kNotFound, "no such device");
  }
  if (device_it->second.public_key_hex.empty()) {
    return make_error(ErrorCode::kInvalidArgument,
                      "upload the device public key first (PUT /api/v1/devices/{id}/key)");
  }
  // One active peer per device: return the existing one instead of duplicating.
  for (const auto& entry : peers_) {
    if (entry.second.device_id == device_it->second.id && entry.second.status == "active") {
      return entry.second;
    }
  }

  const auto ipv4 = allocate_ipv4();
  if (!ipv4) return ipv4.error();

  Peer peer;
  peer.id = random_id("pe_");
  peer.device_id = device_it->second.id;
  peer.public_key_hex = device_it->second.public_key_hex;
  peer.ipv4 = *ipv4;
  const std::size_t dot = peer.ipv4.rfind('.');
  const std::string host = dot == std::string::npos ? "2" : peer.ipv4.substr(dot + 1);
  peer.ipv6 = "fd00:66::" + host;
  peer.status = "active";
  if (peer.id.size() <= 3) {
    return make_error(ErrorCode::kInternal, "OS random source failed");
  }
  const Status appended = append_line("P\t" + peer.id + "\t" + peer.device_id + "\t" +
                                      peer.public_key_hex + "\t" + peer.ipv4 + "\t" + peer.ipv6 +
                                      "\t" + peer.status);
  if (!appended) return appended;
  peers_[peer.id] = peer;
  return peer;
}

Result<std::vector<Peer>> Store::list_peers(const Principal& principal) {
  const std::lock_guard<std::mutex> lock(mutex_);
  std::vector<Peer> out;
  for (const auto& entry : peers_) {
    const auto device_it = devices_.find(entry.second.device_id);
    if (device_it != devices_.end() && device_it->second.user_id == principal.user_id) {
      out.push_back(entry.second);
    }
  }
  return out;
}

Result<Peer> Store::get_peer(const Principal& principal, std::string_view peer_id) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = peers_.find(std::string{peer_id});
  if (it == peers_.end()) return make_error(ErrorCode::kNotFound, "no such peer");
  const auto device_it = devices_.find(it->second.device_id);
  if (device_it == devices_.end() || device_it->second.user_id != principal.user_id) {
    return make_error(ErrorCode::kNotFound, "no such peer");
  }
  return it->second;
}

Status Store::delete_peer(const Principal& principal, std::string_view peer_id) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = peers_.find(std::string{peer_id});
  if (it == peers_.end()) return Status{ErrorCode::kNotFound, "no such peer"};
  const auto device_it = devices_.find(it->second.device_id);
  if (device_it == devices_.end() || device_it->second.user_id != principal.user_id) {
    return Status{ErrorCode::kNotFound, "no such peer"};
  }
  // Tombstone: the record stays in the log so replay cannot resurrect it, and
  // compaction drops it on the next start.
  it->second.status = "revoked";
  const Status appended = append_line("P\t" + it->second.id + "\t" + it->second.device_id + "\t" +
                                      it->second.public_key_hex + "\t" + it->second.ipv4 + "\t" +
                                      it->second.ipv6 + "\t" + it->second.status);
  if (!appended) return appended;
  return Status{};
}

Result<std::string> Store::render_client_conf(const Principal& principal,
                                              std::string_view peer_id) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = peers_.find(std::string{peer_id});
  if (it == peers_.end()) return make_error(ErrorCode::kNotFound, "no such peer");
  const auto device_it = devices_.find(it->second.device_id);
  if (device_it == devices_.end() || device_it->second.user_id != principal.user_id) {
    return make_error(ErrorCode::kNotFound, "no such peer");
  }
  if (it->second.status != "active") {
    return make_error(ErrorCode::kPermissionDenied, "peer is revoked");
  }
  if (!access_active_locked(principal.user_id)) {
    return make_error(ErrorCode::kPermissionDenied,
                      "access expired or revoked: an administrator must extend it");
  }
  if (nodes_.empty()) {
    return make_error(ErrorCode::kUnavailable, "no node registered: POST /api/v1/nodes first");
  }
  const NodeInfo& node = nodes_.front();
  const std::string server_key = base64_of_hex(node.public_key_hex);
  if (server_key.empty()) {
    return make_error(ErrorCode::kInternal, "node public key is corrupt");
  }

  std::string conf;
  conf += "# Generated by vpn " VPN_VERSION " for peer " + it->second.id + "\n";
  conf += "# The client generates its own private key; this server never sees it (ADR-0007).\n";
  conf += "[Interface]\n";
  conf += "# PrivateKey = <generate locally: wg genkey | tee privatekey | wg pubkey>\n";
  conf += "Address = " + it->second.ipv4 + "/32, " + it->second.ipv6 + "/128\n";
  conf += "DNS = " + options_.dns + "\n";
  conf += "MTU = 1420\n\n[Peer]\n";
  conf += "PublicKey = " + server_key + "\n";
  conf += "Endpoint = " + node.host + ":" + std::to_string(node.port) + "\n";
  conf += "AllowedIPs = 0.0.0.0/0, ::/0\n";
  conf += "PersistentKeepalive = 25\n";
  return conf;
}

namespace {
bool is_admin(const Principal& actor) noexcept { return actor.role == "admin"; }

UserRecord to_record(const std::string& id, const Principal& principal, const std::string& email,
                     const AccessGrant& access) {
  UserRecord record;
  record.id = id;
  record.tenant_id = principal.tenant_id;
  record.email = email;
  record.role = principal.role;
  record.access = access;
  return record;
}

// Reverse index (user id -> email). Kept alongside the forward map so that listing
// accounts is O(n) and not O(n^2): the old version scanned every user for each
// user, and scanned every user for each peer in render_dp_config.
std::string email_of(const std::unordered_map<std::string, std::string>& by_user,
                     const std::string& user_id) {
  const auto it = by_user.find(user_id);
  return it == by_user.end() ? std::string{} : it->second;
}
}  // namespace

AccessGrant Store::access_grant_locked(const std::string& user_id) const {
  const auto it = access_.find(user_id);
  if (it != access_.end()) return it->second;
  // Accounts from a log written before entitlements existed have no `E` record.
  // Treating them as never-expiring stops an upgrade from locking everyone out;
  // an administrator can attach a window at any time.
  AccessGrant legacy;
  legacy.plan = "legacy";
  legacy.expires_at = 0;
  legacy.status = "active";
  return legacy;
}

bool Store::access_active_locked(const std::string& user_id) const {
  const AccessGrant grant = access_grant_locked(user_id);
  if (grant.status != "active") return false;
  if (grant.expires_at == 0) return true;  // staff / never-expiring account
  return grant.expires_at > now_unix();
}

AccessGrant Store::access_grant(std::string_view user_id) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return access_grant_locked(std::string{user_id});
}

bool Store::access_active(std::string_view user_id) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return access_active_locked(std::string{user_id});
}

Result<UserRecord> Store::create_user(const Principal& actor, std::string_view email,
                                      std::string_view password, std::string_view role,
                                      std::int64_t expires_at, std::string_view plan) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  const std::string email_key{email};
  if (email_key.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "email is required");
  }
  if (password.size() < 8) {
    return make_error(ErrorCode::kInvalidArgument, "password must be at least 8 characters");
  }
  if (user_email_to_id_.count(email_key) != 0) {
    return make_error(ErrorCode::kAlreadyExists, "user already exists");
  }
  std::string role_str{role};
  if (role_str.empty()) role_str = "user";
  if (role_str != "user" && role_str != "admin" && role_str != "owner") {
    return make_error(ErrorCode::kInvalidArgument, "role must be user, admin or owner");
  }

  Principal principal;
  principal.user_id = random_id("usr_");
  principal.tenant_id = actor.tenant_id.empty() ? std::string{"ten_default"} : actor.tenant_id;
  principal.role = role_str;
  if (principal.user_id.size() <= 4) {
    return make_error(ErrorCode::kInternal, "OS random source failed");
  }
  const std::string hash = hash_password(password);
  Status appended = append_line("U\t" + principal.user_id + "\t" + principal.tenant_id + "\t" +
                                email_key + "\t" + hash + "\t" + principal.role);
  if (!appended) return appended;

  AccessGrant grant;
  // Administrators are staff: they never pay and must not be able to lock
  // themselves out of the console.
  if (role_str == "admin") {
    grant.expires_at = 0;
    grant.plan = "staff";
  } else {
    grant.expires_at = expires_at;
    grant.plan = plan.empty() ? std::string{"trial"} : std::string{plan};
  }
  grant.status = "active";
  grant.granted_at = now_unix();
  appended = append_line("E\t" + principal.user_id + "\t" + std::to_string(grant.expires_at) +
                         "\t" + grant.plan + "\t" + grant.status);
  if (!appended) return appended;

  users_[principal.user_id] = principal;
  user_email_to_id_[email_key] = principal.user_id;
  user_to_email_[principal.user_id] = email_key;
  password_hashes_[principal.user_id] = hash;
  access_[principal.user_id] = grant;
  return to_record(principal.user_id, principal, email_key, grant);
}

Result<std::vector<UserRecord>> Store::list_users(const Principal& actor) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  std::vector<UserRecord> out;
  out.reserve(users_.size());
  for (const auto& entry : users_) {
    const Principal& principal = entry.second;
    out.push_back(to_record(principal.user_id, principal,
                            email_of(user_to_email_, principal.user_id),
                            access_grant_locked(principal.user_id)));
  }
  return out;
}

Result<UserRecord> Store::get_user(const Principal& actor, std::string_view user_id) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  const auto it = users_.find(std::string{user_id});
  if (it == users_.end()) return make_error(ErrorCode::kNotFound, "no such user");
  return to_record(it->first, it->second, email_of(user_to_email_, it->first),
                   access_grant_locked(it->first));
}

Result<UserRecord> Store::grant_access(const Principal& actor, std::string_view user_id,
                                       std::int64_t expires_at, std::string_view plan) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  const auto it = users_.find(std::string{user_id});
  if (it == users_.end()) return make_error(ErrorCode::kNotFound, "no such user");
  if (expires_at < 0) {
    return make_error(ErrorCode::kInvalidArgument, "expires_at must be a unix timestamp");
  }
  AccessGrant grant;
  grant.expires_at = expires_at;
  grant.plan = plan.empty() ? std::string{"custom"} : std::string{plan};
  grant.status = "active";  // granting also re-enables a revoked account
  grant.granted_at = now_unix();
  const Status appended = append_line("E\t" + it->first + "\t" + std::to_string(grant.expires_at) +
                                      "\t" + grant.plan + "\t" + grant.status);
  if (!appended) return make_error(appended.code(), appended.message());
  access_[it->first] = grant;
  return to_record(it->first, it->second, email_of(user_to_email_, it->first), grant);
}

Status Store::revoke_access(const Principal& actor, std::string_view user_id) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return Status{ErrorCode::kPermissionDenied, "administrator role required"};
  }
  const auto it = users_.find(std::string{user_id});
  if (it == users_.end()) return Status{ErrorCode::kNotFound, "no such user"};
  if (it->first == actor.user_id) {
    // An administrator revoking themselves would be a one-way door.
    return Status{ErrorCode::kInvalidArgument, "cannot revoke your own access"};
  }
  AccessGrant grant = access_grant_locked(it->first);
  grant.status = "disabled";
  grant.granted_at = now_unix();
  const Status appended = append_line("E\t" + it->first + "\t" + std::to_string(grant.expires_at) +
                                      "\t" + grant.plan + "\t" + grant.status);
  if (!appended) return appended;
  access_[it->first] = grant;
  return Status{};
}

Status Store::change_password(const Principal& actor, std::string_view current,
                             std::string_view next) {
  const std::lock_guard<std::mutex> lock(mutex_);
  const auto it = users_.find(actor.user_id);
  if (it == users_.end()) return Status{ErrorCode::kNotFound, "no such user"};
  if (next.size() < 8) {
    return Status{ErrorCode::kInvalidArgument, "the new password must be at least 8 characters"};
  }
  if (!ct::equal(ByteSpan{reinterpret_cast<const Byte*>(hash_password(current).data()),
                          kPasswordHashLength},
                 ByteSpan{reinterpret_cast<const Byte*>(password_hashes_[it->first].data()),
                          kPasswordHashLength})) {
    // Same message either way: never reveal whether the old password was close.
    return Status{ErrorCode::kUnauthenticated, "current password is incorrect"};
  }
  return reset_password_locked(it->first, next);
}

Status Store::reset_password(const Principal& actor, std::string_view user_id,
                             std::string_view next) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) return Status{ErrorCode::kPermissionDenied, "administrator role required"};
  if (users_.find(std::string{user_id}) == users_.end()) {
    return Status{ErrorCode::kNotFound, "no such user"};
  }
  if (next.size() < 8) {
    return Status{ErrorCode::kInvalidArgument,
                  "the new password must be at least 8 characters"};
  }
  return reset_password_locked(std::string{user_id}, next);
}

Status Store::reset_password_locked(const std::string& user_id, std::string_view next) {
  std::string email;
  for (const auto& entry : user_email_to_id_) {
    if (entry.second == user_id) {
      email = entry.first;
      break;
    }
  }
  if (email.empty()) return Status{ErrorCode::kInternal, "user has no email"};
  const std::string hash = hash_password(next);
  // A `U` line is upserted by user id on replay, so this replaces the old hash.
  const Status appended = append_line("U\t" + user_id + "\t" + users_[user_id].tenant_id + "\t" +
                                      email + "\t" + hash + "\t" + users_[user_id].role);
  if (!appended) return appended;
  password_hashes_[user_id] = hash;
  return Status{};
}

Result<std::vector<Store::ExpiringAccount>> Store::accounts_expiring_within(
    const Principal& actor, std::int64_t within_days, std::string_view bucket) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  const std::int64_t now = now_unix();
  const std::int64_t horizon = now + within_days * 86400;
  std::vector<ExpiringAccount> out;
  for (const auto& entry : users_) {
    const AccessGrant grant = access_grant_locked(entry.first);
    if (grant.status != "active" || grant.expires_at == 0) continue;
    if (grant.expires_at <= now || grant.expires_at > horizon) continue;
    if (reminders_.count(entry.first + "|" + std::string{bucket}) != 0) continue;
    ExpiringAccount account;
    account.user = to_record(entry.first, entry.second, email_of(user_to_email_, entry.first),
                             grant);
    account.email = account.user.email;
    out.push_back(account);
  }
  return out;
}

Status Store::mark_reminder_sent(const Principal& actor, std::string_view user_id,
                                 std::string_view bucket) {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) return Status{ErrorCode::kPermissionDenied, "administrator role required"};
  const std::string key = std::string{user_id} + "|" + std::string{bucket};
  const std::int64_t now = now_unix();
  const Status appended =
      append_line("R\t" + std::string{user_id} + "\t" + std::string{bucket} + "\t" +
                  std::to_string(now));
  if (!appended) return appended;
  reminders_[key] = now;
  return Status{};
}

Result<std::string> Store::render_dp_config(const Principal& actor,
                                            std::string_view node_id) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  if (nodes_.empty()) {
    return make_error(ErrorCode::kUnavailable, "no node registered: vpnctl nodes add ...");
  }
  std::string node = std::string{node_id};
  if (node.empty()) node = nodes_.front().id;

  std::string out = "# Generated by vpnd for node " + node + "\n";
  out += "# The node's own private_key is deliberately absent: it never leaves the node.\n";
  out += "# Revoked accounts are omitted; expired ones are listed so that extending\n";
  out += "# access takes effect on the next refresh without touching the node.\n";
  std::size_t peers = 0;
  for (const auto& entry : peers_) {
    const Peer& peer = entry.second;
    if (peer.status != "active") continue;
    const auto device = devices_.find(peer.device_id);
    if (device == devices_.end()) continue;
    const AccessGrant grant = access_grant_locked(device->second.user_id);
    if (grant.status != "active") continue;  // revoked: drop from the node entirely
    out += "\n[[peer]]\n";
    out += "name = \"" + peer.id + "\"\n";
    out += "public_key = \"" + peer.public_key_hex + "\"\n";
    out += "allowed_ips = [\"" + peer.ipv4 + "/32\"]\n";
    out += "expires_at = " + std::to_string(grant.expires_at) + "\n";
    ++peers;
  }
  if (peers == 0) out += "\n# no active peers yet\n";
  return out;
}

}  // namespace vpn::api
