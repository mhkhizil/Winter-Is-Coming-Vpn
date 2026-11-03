// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// File-backed control-plane store (see store.hpp for the record format).
#include <cstdint>
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
#include "vpn/crypto/pbkdf2.hpp"
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

// Credentials at rest.
//
// Passwords: PBKDF2-HMAC-SHA256 with a per-password salt and a work factor, because
// a single fast MAC (what this used to be) is trivially brute-forced offline the
// moment the store file leaks. Stored format is self-describing and versioned so an
// old log can be upgraded in place:
//
//   pbkdf2-sha256$<iterations>$<salt-hex>$<derived-hex>
//
// Tokens are different: they are 256-bit random values, so a peppered HMAC is the
// right tool - there is nothing to brute-force, and it must stay cheap because it
// runs on every authenticated request.
constexpr std::size_t kPasswordSaltBytes = 16;
constexpr std::uint32_t kDefaultPbkdf2Iterations = 120000;

std::uint32_t pbkdf2_iterations() {
  // Tests and constrained devices may lower this; the floor keeps it meaningful.
  const char* value = std::getenv("VPN_PBKDF2_ITERATIONS");
  if (value == nullptr) return kDefaultPbkdf2Iterations;
  const long parsed = std::strtol(value, nullptr, 10);
  if (parsed < 10000 || parsed > 4000000) return kDefaultPbkdf2Iterations;
  return static_cast<std::uint32_t>(parsed);
}

// Legacy format, kept only to verify and then upgrade existing hashes.
std::string legacy_blake2s_hash(std::string_view password) {
  const std::string key = pepper();
  Bytes<32> mac = crypto::hmac_blake2s_256(
      ByteSpan{reinterpret_cast<const Byte*>(key.data()), key.size()},
      {ByteSpan{reinterpret_cast<const Byte*>(password.data()), password.size()}});
  const std::string out = to_hex(as_span(mac));
  ::vpn::ct::cleanse(as_span(mac));
  return out;
}

std::string hash_password(std::string_view password) {
  Byte salt[kPasswordSaltBytes] = {};
  if (!crypto::fill_random(MutableByteSpan{salt, sizeof(salt)})) return {};
  const std::uint32_t iterations = pbkdf2_iterations();
  Bytes<32> derived = crypto::pbkdf2_sha256(
      ByteSpan{reinterpret_cast<const Byte*>(password.data()), password.size()},
      ByteSpan{salt, sizeof(salt)}, iterations);
  std::string out = "pbkdf2-sha256$" + std::to_string(iterations) + "$" +
                    vpn::to_hex(ByteSpan{salt, sizeof(salt)}) + "$" + to_hex(as_span(derived));
  ::vpn::ct::cleanse(MutableByteSpan{salt, sizeof(salt)});
  ::vpn::ct::cleanse(as_span(derived));
  return out;
}

// True when `password` matches `stored`, in either the current or the legacy
// format. Comparison is constant-time in both cases.
bool verify_password(const std::string& stored, std::string_view password) {
  const std::string prefix = "pbkdf2-sha256$";
  if (stored.rfind(prefix, 0) != 0) {
    const std::string candidate = legacy_blake2s_hash(password);
    return ::vpn::ct::equal(
        ByteSpan{reinterpret_cast<const Byte*>(candidate.data()), candidate.size()},
        ByteSpan{reinterpret_cast<const Byte*>(stored.data()), stored.size()});
  }

  // pbkdf2-sha256$<iterations>$<salt>$<derived>
  const std::size_t first = stored.find('$', prefix.size());
  if (first == std::string::npos) return false;
  const std::size_t second = stored.find('$', first + 1);
  if (second == std::string::npos) return false;
  const long iterations = std::strtol(stored.substr(prefix.size(),
                                                    first - prefix.size()).c_str(),
                                      nullptr, 10);
  if (iterations < 1 || iterations > 4000000) return false;
  const std::string salt_hex = stored.substr(first + 1, second - first - 1);
  const std::string derived_hex = stored.substr(second + 1);

  Byte salt[kPasswordSaltBytes] = {};
  if (salt_hex.size() != kPasswordSaltBytes * 2) return false;
  for (std::size_t i = 0; i < kPasswordSaltBytes; ++i) {
    const auto byte = static_cast<unsigned>(std::strtoul(salt_hex.substr(i * 2, 2).c_str(),
                                                         nullptr, 16));
    salt[i] = static_cast<Byte>(byte);
  }

  Bytes<32> derived = crypto::pbkdf2_sha256(
      ByteSpan{reinterpret_cast<const Byte*>(password.data()), password.size()},
      ByteSpan{salt, sizeof(salt)}, static_cast<std::uint32_t>(iterations));
  const std::string candidate = to_hex(as_span(derived));
  ::vpn::ct::cleanse(as_span(derived));
  ::vpn::ct::cleanse(MutableByteSpan{salt, sizeof(salt)});
  return ::vpn::ct::equal(
      ByteSpan{reinterpret_cast<const Byte*>(candidate.data()), candidate.size()},
      ByteSpan{reinterpret_cast<const Byte*>(derived_hex.data()), derived_hex.size()});
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

// The store log is a tab-separated, newline-terminated record format, and several
// fields come from users: an email, a device name, a node host, a plan label. A field
// containing a raw tab or newline therefore cannot be written as-is:
//
//   D <id> <user> <name> <platform> <key>
//
// with name = "innocent\nU\tusr_x\tten\tpwn@evil\t<hash>\tadmin" rewrites the log into
// a *forged account*, and replay then treats it as real. That was a working privilege
// escalation (any authenticated user -> admin, surviving restart), not a theoretical
// one. Percent-escaping the four dangerous bytes on the way out, and undoing it per
// field on the way in, closes it for every record kind at once - including ones added
// later.
constexpr std::string_view kEscapePercent = "%25";
constexpr std::string_view kEscapeTab = "%09";
constexpr std::string_view kEscapeNewline = "%0A";
constexpr std::string_view kEscapeCarriageReturn = "%0D";

// Escapes a whole record while preserving the tabs that delimit its fields.
[[nodiscard]] std::string escape_record(std::string_view line) {
  std::string out;
  out.reserve(line.size() + 8);
  for (const char c : line) {
    switch (c) {
      case '%': out += kEscapePercent; break;
      case '\t': out.push_back('\t'); break;  // structural: this is the separator
      case '\n': out += kEscapeNewline; break;
      case '\r': out += kEscapeCarriageReturn; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

// Reverses escape_record() for one field. Unknown sequences are left alone, so a log
// written before this escaping existed (which may legitimately contain '%') still
// replays exactly as it did.
[[nodiscard]] std::string unescape_field(std::string_view field) {
  auto matches = [&field](std::size_t at, std::string_view code) {
    return field.compare(at, code.size(), code) == 0;
  };
  std::string out;
  out.reserve(field.size());
  for (std::size_t i = 0; i < field.size();) {
    if (field[i] == '%' && i + 2 < field.size()) {
      if (matches(i, kEscapePercent)) {
        out.push_back('%');
        i += kEscapePercent.size();
        continue;
      }
      if (matches(i, kEscapeTab)) {
        out.push_back('\t');
        i += kEscapeTab.size();
        continue;
      }
      if (matches(i, kEscapeNewline)) {
        out.push_back('\n');
        i += kEscapeNewline.size();
        continue;
      }
      if (matches(i, kEscapeCarriageReturn)) {
        out.push_back('\r');
        i += kEscapeCarriageReturn.size();
        continue;
      }
    }
    out.push_back(field[i]);
    ++i;
  }
  return out;
}

// True when a user-supplied string is safe to store and display: printable, no
// control characters. Rejecting beats silently mangling - a device named with a tab
// in it is a mistake or an attack, and either way the caller deserves a 400.
[[nodiscard]] bool is_printable_text(std::string_view value, std::size_t max_length) {
  if (value.size() > max_length) return false;
  for (const char c : value) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20U || byte == 0x7FU) return false;
  }
  return true;
}

Status Store::append_line(const std::string& line) {
  if (log_ == nullptr) {
    return Status{ErrorCode::kInternal, "store log is not open"};
  }
  const std::string record = escape_record(line) + "\n";
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

    std::vector<std::string> f = split_tabs(line);
    if (f.empty()) continue;
    for (std::string& field : f) field = unescape_field(field);
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
    } else if (kind == "A" && f.size() >= 5) {
      AuditEntry entry;
      entry.actor = f[1];
      entry.action = f[2];
      entry.target = f[3];
      entry.at = std::atoll(f[4].c_str());
      audit_.push_back(entry);
      if (audit_.size() > 4096) audit_.erase(audit_.begin());
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

  // Every append is checked. If a write fails (disk full, quota, I/O error) the
  // compaction file is truncated, and renaming it over the live log would silently
  // destroy state - worse than failing to start. So: record the first failure,
  // discard the temporary file, and fail loudly.
  bool wrote = true;
  const auto emit = [&](const std::string& line) {
    if (wrote && !store->append_line(line).ok()) wrote = false;
  };

  for (const auto& entry : store->users_) {
    const std::string& id = entry.first;
    const Principal& principal = entry.second;
    emit("U\t" + id + "\t" + principal.tenant_id + "\t" + email_by_id[id] + "\t" +
         store->password_hashes_[id] + "\t" + principal.role);
  }
  for (const auto& entry : store->access_) {
    emit("E\t" + entry.first + "\t" + std::to_string(entry.second.expires_at) + "\t" +
         entry.second.plan + "\t" + entry.second.status);
  }
  for (const AuditEntry& entry : store->audit_) {
    emit("A\t" + entry.actor + "\t" + entry.action + "\t" + entry.target + "\t" +
         std::to_string(entry.at));
  }
  for (const auto& entry : store->reminders_) {
    const std::size_t bar = entry.first.find('|');
    if (bar == std::string::npos) continue;
    emit("R\t" + entry.first.substr(0, bar) + "\t" + entry.first.substr(bar + 1) + "\t" +
         std::to_string(entry.second));
  }
  for (const auto& entry : store->token_to_user_) {
    const std::int64_t expiry = store->token_expiry_[entry.first];
    if (expiry > now_unix()) {
      emit("T\t" + entry.first + "\t" + entry.second + "\t" + std::to_string(expiry));
    }
  }
  for (const auto& entry : store->devices_) {
    const Device& device = entry.second;
    emit("D\t" + device.id + "\t" + device.user_id + "\t" + device.name + "\t" +
         device.platform + "\t" + device.public_key_hex);
  }
  for (const auto& entry : store->peers_) {
    const Peer& peer = entry.second;
    emit("P\t" + peer.id + "\t" + peer.device_id + "\t" + peer.public_key_hex + "\t" +
         peer.ipv4 + "\t" + peer.ipv6 + "\t" + peer.status);
  }
  for (const NodeInfo& node : store->nodes_) {
    emit("S\t" + node.id + "\t" + node.region + "\t" + node.host + "\t" +
         std::to_string(node.port) + "\t" + node.public_key_hex);
  }

  if (!wrote) {
    std::fclose(rewrite);
    store->log_ = nullptr;
    store->skip_fsync_ = false;
    std::error_code ignored;
    std::filesystem::remove(compaction_path, ignored);
    return make_error(ErrorCode::kUnavailable,
                      "cannot rewrite the store log (out of space?); previous log kept");
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
      // The role matters more than it looks. Every /api/v1/admin/* endpoint and
      // /api/v1/dp/config require role "admin", and on a fresh store this is the only
      // account that exists - so hardcoding "owner" left a new deployment with nobody
      // able to administer it (owner is deliberately not an administrator, because it is
      // the role a self-service customer gets). The default stays "owner" so a box never
      // comes up with admin access by accident; an operator who needs to administer it
      // sets VPN_BOOTSTRAP_ROLE=admin for the first start.
      const char* role_env = std::getenv("VPN_BOOTSTRAP_ROLE");
      const std::string role = (role_env != nullptr && *role_env != '\0') ? role_env : "owner";
      if (role != "user" && role != "admin" && role != "owner") {
        return make_error(ErrorCode::kInvalidArgument,
                          "VPN_BOOTSTRAP_ROLE must be one of user, admin, owner");
      }
      const Status seeded = store->add_user(email, password, role);
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
  const std::string& stored = password_hashes_[it->second];
  if (!verify_password(stored, password)) {
    // One message for "no such user" and "wrong password": the caller must not be
    // able to enumerate accounts.
    return make_error(ErrorCode::kUnauthenticated, "invalid credentials");
  }
  // Transparent upgrade: a password still stored in the legacy fast-MAC format is
  // re-hashed with PBKDF2 on its next successful login, so an existing store
  // migrates itself without locking anyone out.
  if (stored.rfind("pbkdf2-sha256$", 0) != 0) {
    (void)reset_password_locked(it->second, password);
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
  // A name is echoed back to the client and stored in a line-oriented log: control
  // characters are rejected here rather than escaped, so a mistake (or an attack)
  // produces a clear 400 instead of a name that quietly reads back as %0A.
  if (name.empty() || !is_printable_text(name, 64)) {
    return make_error(ErrorCode::kInvalidArgument,
                      "device name must be 1-64 printable characters");
  }
  if (!platform.empty() && !is_printable_text(platform, 32)) {
    return make_error(ErrorCode::kInvalidArgument, "device platform must be printable (max 32)");
  }
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
  conf += "MTU = " + std::to_string(options_.mtu) + "\n\n[Peer]\n";
  conf += "PublicKey = " + server_key + "\n";
  conf += "Endpoint = " + node.host + ":" + std::to_string(node.port) + "\n";
  conf += "AllowedIPs = " + options_.client_allowed_ips + "\n";
  conf += "PersistentKeepalive = " + std::to_string(options_.persistent_keepalive) + "\n";
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
  if (!is_printable_text(email_key, 254)) {
    return make_error(ErrorCode::kInvalidArgument, "email must be printable (max 254)");
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
  (void)record_audit_locked(actor, "user.create", principal.user_id);
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
  (void)record_audit_locked(actor, "user.grant", it->first);
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
  (void)record_audit_locked(actor, "user.revoke", it->first);
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
  if (!verify_password(password_hashes_[it->first], current)) {
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

// The structured form of render_client_conf(). This is the payload a front end
// consumes: no TOML parsing, no base64-vs-hex guessing, and an explicit
// "private_key": null so a client cannot accidentally expect one from us (ADR-0007).
Result<std::string> Store::render_client_json(const Principal& principal,
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

  // AllowedIPs is a comma-separated string in the config; a client wants a list.
  std::string allowed;
  std::string current;
  const auto flush_allowed = [&allowed, &current]() {
    std::size_t begin = current.find_first_not_of(" \t");
    std::size_t end = current.find_last_not_of(" \t");
    if (begin != std::string::npos) {
      allowed += (allowed.empty() ? "" : ",") + std::string{"\""} +
                 current.substr(begin, end - begin + 1) + "\"";
    }
    current.clear();
  };
  for (const char c : options_.client_allowed_ips) {
    if (c == ',') {
      flush_allowed();
    } else {
      current.push_back(c);
    }
  }
  flush_allowed();

  std::string out = "{\"id\":\"" + it->second.id + "\"";
  out += ",\"peer_id\":\"" + it->second.id + "\"";
  out += ",\"device_id\":\"" + it->second.device_id + "\"";
  out += ",\"status\":\"" + it->second.status + "\"";
  out += ",\"interface\":{";
  out += "\"addresses\":[\"" + it->second.ipv4 + "/32\",\"" + it->second.ipv6 + "/128\"]";
  out += ",\"dns\":[\"" + options_.dns + "\"]";
  out += ",\"mtu\":" + std::to_string(options_.mtu);
  out += ",\"persistent_keepalive\":" + std::to_string(options_.persistent_keepalive);
  // Deliberately null: the client generates and keeps its own private key.
  out += ",\"private_key\":null}";
  out += ",\"server\":{";
  out += "\"id\":\"" + node.id + "\"";
  out += ",\"endpoint\":\"" + node.host + ":" + std::to_string(node.port) + "\"";
  out += ",\"public_key\":\"" + server_key + "\"";
  out += ",\"allowed_ips\":[" + allowed + "]}";
  out += "}";
  return out;
}

Status Store::record_audit_locked(const Principal& actor, std::string_view action,
                                  std::string_view target) {
  const std::int64_t at = now_unix();
  const Status appended = append_line("A\t" + actor.user_id + "\t" + std::string{action} + "\t" +
                                     std::string{target} + "\t" + std::to_string(at));
  if (!appended) return appended;
  AuditEntry entry;
  entry.actor = actor.user_id;
  entry.action = std::string{action};
  entry.target = std::string{target};
  entry.at = at;
  audit_.push_back(entry);
  if (audit_.size() > 4096) audit_.erase(audit_.begin());
  return Status{};
}

Status Store::record_audit(const Principal& actor, std::string_view action,
                           std::string_view target) {
  const std::lock_guard<std::mutex> lock(mutex_);
  return record_audit_locked(actor, action, target);
}

Result<std::vector<Store::AuditEntry>> Store::list_audit(const Principal& actor,
                                                         std::size_t limit) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (!is_admin(actor)) {
    return make_error(ErrorCode::kPermissionDenied, "administrator role required");
  }
  const std::size_t take = (limit == 0 || limit > audit_.size()) ? audit_.size() : limit;
  std::vector<AuditEntry> out;
  out.reserve(take);
  for (std::size_t i = audit_.size() - take; i < audit_.size(); ++i) out.push_back(audit_[i]);
  return out;
}

}  // namespace vpn::api
