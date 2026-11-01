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
  [[nodiscard]] Status append_line(const std::string& line);
  void replay(const std::string& content);
  [[nodiscard]] bool ip_taken(std::string_view ipv4) const;
  [[nodiscard]] Result<std::string> allocate_ipv4();

  mutable std::mutex mutex_;
  StoreOptions options_{};
  std::FILE* log_{nullptr};
  std::uint64_t next_ip_{2};  // .1 is the server

  std::unordered_map<std::string, std::string> user_email_to_id_;
  std::unordered_map<std::string, Principal> users_;
  std::unordered_map<std::string, std::string> password_hashes_;
  std::unordered_map<std::string, std::string> token_to_user_;
  std::unordered_map<std::string, std::int64_t> token_expiry_;
  std::unordered_map<std::string, Device> devices_;
  std::unordered_map<std::string, Peer> peers_;
  std::vector<NodeInfo> nodes_;
};

}  // namespace vpn::api
