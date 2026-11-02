// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Control-plane state: users, tokens, devices, peers and the node catalog.
//
// Dependency-free by design: an append-only, fsync'ed record log plus an
// in-memory index, so one static binary is a complete control plane with no
// PostgreSQL and no Redis. Line-oriented and auditable:
//
//   U <user-id> <tenant-id> <email> <password-hash> <role>
//   T <token-hash> <user-id> <expires-unix>
//   D <device-id> <user-id> <name> <platform> <public-key-hex>
//   P <peer-id> <device-id> <public-key-hex> <ipv4> <ipv6> <status>
//   S <node-id> <region> <host> <port> <public-key-hex>
//
// Every mutation appends one line and fsyncs; the log is compacted on open.
// PostgreSQL stays the production target (server/migrations/0001_init.sql) with
// the same semantics, so swapping the backend does not touch the API.
#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "vpn/common/result.hpp"

namespace vpn::api {

struct Principal {
  std::string user_id{};
  std::string tenant_id{};
  std::string role{"owner"};
};

struct Device {
  std::string id{};
  std::string user_id{};
  std::string name{};
  std::string platform{};
  std::string public_key_hex{};
};

struct Peer {
  std::string id{};
  std::string device_id{};
  std::string public_key_hex{};
  std::string ipv4{};
  std::string ipv6{};
  std::string status{"active"};
  std::uint64_t rx_bytes{0};
  std::uint64_t tx_bytes{0};
};

struct NodeInfo {
  std::string id{};
  std::string region{};
  std::string host{};
  std::uint16_t port{51820};
  std::string public_key_hex{};
};

// Access grant: this is how money turns into service.
//
// Payment is collected out of band (bank transfer, cash, mobile money - whatever
// the operator uses) and an administrator records the outcome here: who, until
// when, on which plan. No payment processor, no webhooks, no card data, and
// therefore no PCI scope (see ADR-0010).
struct AccessGrant {
  std::int64_t expires_at{0};     // unix seconds; 0 means "never expires" (staff)
  std::string plan{"trial"};      // free-form: trial | 1m | 6m | 12m | staff
  std::string status{"active"};   // active | disabled (revoked by an administrator)
  std::int64_t granted_at{0};     // unix seconds
};

struct UserRecord {
  std::string id{};
  std::string tenant_id{};
  std::string email{};
  std::string role{"user"};
  AccessGrant access{};
};

struct StoreOptions {
  std::string path{};            // e.g. /var/lib/vpn/control.log
  std::string endpoint_host{};   // advertised node host in client configs
  std::uint16_t endpoint_port{51820};
  std::string dns{"10.66.0.1"};
  std::string server_ipv4{"10.66.0.1"};
  std::string server_ipv6{"fd00:66::1"};
  std::string ipv6_block{"fd00:66::/64"};
};

class Store {
 public:
  Store() = default;
  ~Store();

  [[nodiscard]] static Result<std::unique_ptr<Store>> open(const StoreOptions& options);

  // --- authentication -------------------------------------------------------
  [[nodiscard]] Result<Principal> authenticate(std::string_view email,
                                               std::string_view password);
  [[nodiscard]] Result<std::string> issue_token(const Principal& principal,
                                                std::uint32_t ttl_seconds);
  [[nodiscard]] Result<Principal> principal_for_token(std::string_view token);
  [[nodiscard]] Status revoke_token(std::string_view token);
  [[nodiscard]] Status add_user(std::string_view email, std::string_view password,
                                std::string_view role);

  // --- administration: accounts and paid access ------------------------------
  // Every method below requires the actor's role to be "admin". They are the only
  // way to attach an expiry to an account, and expiry is what makes the VPN stop
  // working for a customer whose month (or six) has run out.
  [[nodiscard]] Result<UserRecord> create_user(const Principal& actor, std::string_view email,
                                               std::string_view password, std::string_view role,
                                               std::int64_t expires_at, std::string_view plan);
  [[nodiscard]] Result<std::vector<UserRecord>> list_users(const Principal& actor) const;
  [[nodiscard]] Result<UserRecord> get_user(const Principal& actor, std::string_view user_id) const;

  // Sets (or replaces) the access window. Extending is the common case: pass the
  // new absolute expiry, computed by the caller from the plan length.
  [[nodiscard]] Result<UserRecord> grant_access(const Principal& actor, std::string_view user_id,
                                                std::int64_t expires_at, std::string_view plan);
  // Immediate lockout that keeps the record (so the operator can see it and
  // re-enable later). Deletes nothing.
  [[nodiscard]] Status revoke_access(const Principal& actor, std::string_view user_id);

  // --- audit trail ----------------------------------------------------------
  // Who did what, appended to the same durable log. Not a replacement for an
  // external audit system, but it means an administrator action (grant, revoke,
  // password reset, user creation) is attributable after the fact instead of
  // existing only in whatever chat message prompted it.
  struct AuditEntry {
    std::string actor{};   // user id of the administrator
    std::string action{};  // user.create | user.grant | user.revoke | user.password
    std::string target{};  // affected user id
    std::int64_t at{0};    // unix seconds
  };
  [[nodiscard]] Status record_audit(const Principal& actor, std::string_view action,
                                    std::string_view target);
  [[nodiscard]] Result<std::vector<AuditEntry>> list_audit(const Principal& actor,
                                                           std::size_t limit) const;

  // --- credentials ----------------------------------------------------------
  // The initial password is issued by an administrator, so a way to change it is
  // not optional: otherwise every customer keeps the password that travelled
  // through a chat message.
  [[nodiscard]] Status change_password(const Principal& actor, std::string_view current,
                                       std::string_view next);
  // Administrator reset for a customer who forgot theirs. Does not require the
  // old password; it is the "phone the operator" path.
  [[nodiscard]] Status reset_password(const Principal& actor, std::string_view user_id,
                                      std::string_view next);

  // --- renewal reminders ----------------------------------------------------
  // Accounts whose access ends within `within_days` and which have not already
  // been reminded for `bucket` (e.g. "7d", "1d"). Idempotent: a daily cron may
  // call this as often as it likes.
  struct ExpiringAccount {
    UserRecord user{};
    std::string email{};
  };
  [[nodiscard]] Result<std::vector<ExpiringAccount>> accounts_expiring_within(
      const Principal& actor, std::int64_t within_days, std::string_view bucket) const;
  // Records that the reminder for (user, bucket) was sent, so it is not repeated.
  [[nodiscard]] Status mark_reminder_sent(const Principal& actor, std::string_view user_id,
                                          std::string_view bucket);

  // --- data plane -----------------------------------------------------------
  // The whole peer table rendered as the TOML subset vpn-dp already parses, so a
  // node can be bootstrapped with `vpn-dp --config-url ...` instead of an operator
  // hand-copying keys. Includes each peer's access expiry (ADR-0010).
  [[nodiscard]] Result<std::string> render_dp_config(const Principal& actor, std::string_view node_id) const;

  // "Can this account create peers / fetch configurations right now?"
  // A missing grant means a legacy or staff account and is treated as active.
  [[nodiscard]] bool access_active(std::string_view user_id) const;
  [[nodiscard]] AccessGrant access_grant(std::string_view user_id) const;

  // --- devices --------------------------------------------------------------
  [[nodiscard]] Result<Device> create_device(const Principal& principal, std::string_view name,
                                             std::string_view platform);
  [[nodiscard]] Result<std::vector<Device>> list_devices(const Principal& principal);
  [[nodiscard]] Status set_device_key(const Principal& principal, std::string_view device_id,
                                      std::string_view public_key_hex);

  // --- peers ----------------------------------------------------------------
  [[nodiscard]] Result<Peer> create_peer(const Principal& principal, std::string_view device_id);
  [[nodiscard]] Result<std::vector<Peer>> list_peers(const Principal& principal);
  [[nodiscard]] Result<Peer> get_peer(const Principal& principal, std::string_view peer_id);
  [[nodiscard]] Status delete_peer(const Principal& principal, std::string_view peer_id);

  // --- catalog --------------------------------------------------------------
  [[nodiscard]] Result<std::vector<NodeInfo>> nodes() const;
  [[nodiscard]] Status add_node(const NodeInfo& node);

  // --- client configuration -------------------------------------------------
  // wg-quick compatible text. The private key is intentionally absent: the client
  // generates it (ADR-0007).
  [[nodiscard]] Result<std::string> render_client_conf(const Principal& principal,
                                                       std::string_view peer_id) const;

  [[nodiscard]] const StoreOptions& options() const noexcept { return options_; }
  [[nodiscard]] std::size_t user_count() const;
  [[nodiscard]] std::size_t peer_count() const;

 private:
  [[nodiscard]] bool access_active_locked(const std::string& user_id) const;
  [[nodiscard]] AccessGrant access_grant_locked(const std::string& user_id) const;
  [[nodiscard]] Status reset_password_locked(const std::string& user_id, std::string_view next);
  [[nodiscard]] Status record_audit_locked(const Principal& actor, std::string_view action,
                                          std::string_view target);
  [[nodiscard]] Status append_line(const std::string& line);
  // fsync the log to disk (no-op where the platform offers nothing portable).
  void sync_log() noexcept;
  void replay(const std::string& content);
  [[nodiscard]] bool ip_taken(std::string_view ipv4) const;
  [[nodiscard]] Result<std::string> allocate_ipv4();

  mutable std::mutex mutex_;
  StoreOptions options_{};
  std::FILE* log_{nullptr};
  // While the log is being rewritten at startup we append thousands of records and
  // fsync once at the end, instead of paying one fsync per record.
  bool skip_fsync_{false};
  std::uint64_t next_ip_{2};  // .1 is the server

  std::unordered_map<std::string, std::string> user_email_to_id_;
  // Reverse index: without it every account listing was O(n^2).
  std::unordered_map<std::string, std::string> user_to_email_;
  std::unordered_map<std::string, Principal> users_;
  std::unordered_map<std::string, std::string> password_hashes_;
  std::unordered_map<std::string, std::string> token_to_user_;
  std::unordered_map<std::string, std::int64_t> token_expiry_;
  std::unordered_map<std::string, Device> devices_;
  std::unordered_map<std::string, Peer> peers_;
  std::vector<NodeInfo> nodes_;
  std::unordered_map<std::string, AccessGrant> access_;
  // "<user-id>|<bucket>" -> unix time the reminder was sent (idempotency).
  std::unordered_map<std::string, std::int64_t> reminders_;
  // Bounded ring of recent audit entries (oldest dropped first).
  std::vector<AuditEntry> audit_;
};

}  // namespace vpn::api
