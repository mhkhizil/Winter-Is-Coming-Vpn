// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/api/router.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result_helpers.hpp"

namespace vpn::api {
namespace {

using vpn::controlplane::HttpRequest;
using vpn::controlplane::HttpResponse;

std::string escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (const char c : in) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20U) {
          char buffer[8] = {};
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(c));
          out += buffer;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

// Very small extractor for a flat JSON object: {"name":"value"} or {"name":123}.
// The API contract only uses flat objects, and a hand-written parser keeps the
// dependency list at zero. Unknown/again malformed input simply yields false.
bool extract_field(const std::string& body, const char* name, std::string& out) {
  const std::string needle = std::string{"\""} + name + "\"";
  const std::size_t key = body.find(needle);
  if (key == std::string::npos) return false;
  const std::size_t colon = body.find(':', key + needle.size());
  if (colon == std::string::npos) return false;
  std::size_t i = colon + 1;
  while (i < body.size() && (body[i] == ' ' || body[i] == '\t')) ++i;
  if (i >= body.size()) return false;
  if (body[i] == '"') {
    ++i;
    std::string value;
    while (i < body.size() && body[i] != '"') {
      if (body[i] == '\\' && i + 1 < body.size()) ++i;
      value.push_back(body[i]);
      ++i;
    }
    if (i >= body.size()) return false;
    out = value;
    return true;
  }
  std::string value;
  while (i < body.size() && body[i] != ',' && body[i] != '}' && body[i] != ' ') {
    value.push_back(body[i]);
    ++i;
  }
  if (value.empty()) return false;
  out = value;
  return true;
}

std::int64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

Router::Router(RouterOptions options) : options_(options) {}

HttpResponse Router::json(int status, const std::string& body) {
  HttpResponse response;
  response.status = status;
  response.content_type = "application/json; charset=utf-8";
  response.body = body;
  return response;
}

HttpResponse Router::text(int status, const std::string& body) {
  HttpResponse response;
  response.status = status;
  response.content_type = "text/plain; charset=utf-8";
  response.body = body;
  return response;
}

HttpResponse Router::problem(int status, const char* title, const char* code,
                             const std::string& detail) {
  HttpResponse response;
  response.status = status;
  response.content_type = "application/problem+json";
  response.body = std::string{"{\"type\":\"about:blank\",\"title\":\"",} + title + "\",\"status\":" +
                  std::to_string(status) + ",\"code\":\"" + code + "\"";
  if (!detail.empty()) response.body += ",\"detail\":\"" + escape(detail) + "\"";
  response.body += "}";
  return response;
}

bool Router::field(const std::string& json_body, const char* name, std::string& out) {
  return extract_field(json_body, name, out);
}

bool Router::allow(const std::string& client_ip) {
  const std::lock_guard<std::mutex> lock(buckets_mutex_);
  Bucket& bucket = buckets_[client_ip];
  const std::int64_t now = now_ms();
  if (bucket.last_refill_ms == 0) {
    bucket.tokens = static_cast<double>(options_.rate_limit_burst);
    bucket.last_refill_ms = now;
  }
  const double elapsed_seconds = static_cast<double>(now - bucket.last_refill_ms) / 1000.0;
  bucket.tokens += elapsed_seconds * static_cast<double>(options_.rate_limit_per_second);
  const double cap = static_cast<double>(options_.rate_limit_burst);
  if (bucket.tokens > cap) bucket.tokens = cap;
  bucket.last_refill_ms = now;
  if (bucket.tokens < 1.0) return false;
  bucket.tokens -= 1.0;
  return true;
}

Result<Principal> Router::authenticate(const HttpRequest& request) const {
  // The bearer token may arrive as a JSON field ("access_token") or as a query
  // parameter (?token=...), which is what the mobile deep-link flows use. The
  // HTTP layer deliberately does not expose headers to the router, so those are
  // the two documented carriers (see docs/API.md).
  std::string token;
  // 1. Standard bearer header (what the mobile clients and curl use).
  const std::string& auth = request.authorization;
  if (auth.size() > 7) {
    std::string scheme = auth.substr(0, 7);
    for (char& ch : scheme) {
      if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    if (scheme == "bearer ") token = auth.substr(7);
  }
  // 2. JSON body field, 3. query parameter (documented in docs/API.md).
  if (token.empty() && !extract_field(request.body, "access_token", token) &&
      !extract_field(request.query, "access_token", token)) {
    for (const char* key : {"token=", "access_token="}) {
      const std::size_t at = request.query.find(key);
      if (at == std::string::npos) continue;
      std::size_t start = at + std::strlen(key);
      std::size_t end = request.query.find('&', start);
      if (end == std::string::npos) end = request.query.size();
      token = request.query.substr(start, end - start);
      if (!token.empty()) break;
    }
  }
  if (token.empty()) {
    return make_error(ErrorCode::kUnauthenticated, "missing access token");
  }
  return options_.store->principal_for_token(token);
}

controlplane::HttpResponse Router::handle(const HttpRequest& request) {
  if (options_.store == nullptr) {
    return problem(503, "Service Unavailable", "store_unavailable");
  }
  if (!allow(request.client_ip)) {
    return problem(429, "Too Many Requests", "rate_limited");
  }
  if (request.path.rfind("/api/v1", 0) != 0) {
    return problem(404, "Not Found", "not_found");
  }

  std::vector<std::string> parts;
  std::size_t start = 1;
  while (start <= request.path.size()) {
    const std::size_t slash = request.path.find('/', start);
    parts.push_back(request.path.substr(
        start, slash == std::string::npos ? std::string::npos : slash - start));
    if (slash == std::string::npos) break;
    start = slash + 1;
  }
  if (parts.size() < 3) return problem(404, "Not Found", "not_found");
  const std::string& resource = parts[2];

  if (resource == "health") return json(200, R"({"status":"ok"})");

  if (resource == "auth" && parts.size() >= 4) {
    const std::string& action = parts[3];
    if (action == "login" && request.method == "POST") {
      std::string email;
      std::string password;
      if (!field(request.body, "email", email) || !field(request.body, "password", password)) {
        return problem(400, "Bad Request", "invalid_argument", "email and password are required");
      }
      auto principal = options_.store->authenticate(email, password);
      if (!principal) {
        return problem(401, "Unauthorized", "unauthenticated", "invalid credentials");
      }
      auto token = options_.store->issue_token(*principal, options_.token_ttl_seconds);
      if (!token) return problem(500, "Internal Server Error", "internal");
      return json(200, "{\"access_token\":\"" + *token + "\",\"token_type\":\"Bearer\"," +
                           "\"expires_in\":" + std::to_string(options_.token_ttl_seconds) +
                           ",\"user_id\":\"" + escape(principal->user_id) + "\"}");
    }
    if (action == "logout" && request.method == "POST") {
      std::string token;
      if (field(request.body, "access_token", token)) {
        (void)options_.store->revoke_token(token);
      }
      return json(204, "");
    }
    return problem(404, "Not Found", "not_found");
  }

  auto principal = authenticate(request);
  if (!principal) {
    return problem(401, "Unauthorized", "unauthenticated", principal.error().message());
  }
  const Principal& who = *principal;

  if (resource == "me" && request.method == "GET") {
    return json(200, "{\"user_id\":\"" + escape(who.user_id) + "\",\"tenant_id\":\"" +
                         escape(who.tenant_id) + "\",\"role\":\"" + escape(who.role) + "\"}");
  }

  if (resource == "devices") {
    if (request.method == "POST") {
      std::string name;
      std::string platform;
      if (!field(request.body, "name", name)) name = "device";
      if (!field(request.body, "platform", platform)) platform = "linux";
      auto device = options_.store->create_device(who, name, platform);
      if (!device) return problem(500, "Internal Server Error", "internal");
      return json(201, "{\"id\":\"" + escape(device->id) + "\",\"name\":\"" +
                           escape(device->name) + "\",\"platform\":\"" +
                           escape(device->platform) + "\"}");
    }
    if (request.method == "GET") {
      auto devices = options_.store->list_devices(who);
      if (!devices) return problem(500, "Internal Server Error", "internal");
      std::string body = "{\"data\":[";
      bool first = true;
      for (const Device& device : *devices) {
        if (!first) body += ',';
        first = false;
        body += "{\"id\":\"" + escape(device.id) + "\",\"name\":\"" + escape(device.name) +
                "\",\"platform\":\"" + escape(device.platform) + "\",\"public_key\":\"" +
                escape(device.public_key_hex) + "\"}";
      }
      body += "]}";
      return json(200, body);
    }
    if (request.method == "PUT" && parts.size() >= 5 && parts[4] == "key") {
      std::string key;
      if (!field(request.body, "public_key", key)) {
        return problem(400, "Bad Request", "invalid_argument", "public_key is required");
      }
      const Status status = options_.store->set_device_key(who, parts[3], key);
      if (!status) {
        const bool missing = status.code() == ErrorCode::kNotFound;
        return problem(missing ? 404 : 422, missing ? "Not Found" : "Unprocessable Entity",
                       missing ? "not_found" : "config_unsupported", status.message());
      }
      return json(204, "");
    }
    return problem(405, "Method Not Allowed", "method_not_allowed");
  }

  if (resource == "peers") {
    if (request.method == "POST") {
      std::string device_id;
      if (!field(request.body, "device_id", device_id)) {
        return problem(400, "Bad Request", "invalid_argument", "device_id is required");
      }
      auto peer = options_.store->create_peer(who, device_id);
      if (!peer) {
        const bool missing = peer.error().code() == ErrorCode::kNotFound;
        return problem(missing ? 404 : 422, missing ? "Not Found" : "Unprocessable Entity",
                       "config_unsupported", peer.error().message());
      }
      return json(201, "{\"id\":\"" + escape(peer->id) + "\",\"device_id\":\"" +
                           escape(peer->device_id) + "\",\"addresses\":[\"" + escape(peer->ipv4) +
                           "/32\",\"" + escape(peer->ipv6) + "/128\"],\"status\":\"" +
                           escape(peer->status) + "\"}");
    }
    if (request.method == "GET" && parts.size() == 3) {
      auto peers = options_.store->list_peers(who);
      if (!peers) return problem(500, "Internal Server Error", "internal");
      std::string body = "{\"data\":[";
      bool first = true;
      for (const Peer& peer : *peers) {
        if (!first) body += ',';
        first = false;
        body += "{\"id\":\"" + escape(peer.id) + "\",\"status\":\"" + escape(peer.status) +
                "\",\"addresses\":[\"" + escape(peer.ipv4) + "/32\",\"" + escape(peer.ipv6) +
                "/128\"]}";
      }
      body += "]}";
      return json(200, body);
    }
    if (parts.size() >= 4) {
      const std::string& peer_id = parts[3];
      if (request.method == "GET" && parts.size() == 4) {
        auto peer = options_.store->get_peer(who, peer_id);
        if (!peer) return problem(404, "Not Found", "not_found");
        return json(200, "{\"id\":\"" + escape(peer->id) + "\",\"status\":\"" +
                             escape(peer->status) + "\",\"addresses\":[\"" + escape(peer->ipv4) +
                             "/32\",\"" + escape(peer->ipv6) + "/128\"]}");
      }
      if (request.method == "GET" && parts.size() == 5 && parts[4] == "config") {
        auto conf = options_.store->render_client_conf(who, peer_id);
        if (!conf) return problem(404, "Not Found", "not_found", conf.error().message());
        return text(200, *conf);
      }
      if (request.method == "DELETE" && parts.size() == 4) {
        const Status status = options_.store->delete_peer(who, peer_id);
        if (!status) return problem(404, "Not Found", "not_found");
        return json(204, "");
      }
    }
    return problem(405, "Method Not Allowed", "method_not_allowed");
  }

  if (resource == "servers" && request.method == "GET") {
    auto nodes = options_.store->nodes();
    if (!nodes) return problem(500, "Internal Server Error", "internal");
    std::string body = "{\"data\":[";
    bool first = true;
    for (const NodeInfo& node : *nodes) {
      if (!first) body += ',';
      first = false;
      body += "{\"id\":\"" + escape(node.id) + "\",\"region\":\"" + escape(node.region) +
              "\",\"endpoint\":\"" + escape(node.host) + ":" + std::to_string(node.port) +
              "\",\"public_key\":\"" + escape(node.public_key_hex) + "\",\"status\":\"active\"}";
    }
    body += "]}";
    return json(200, body);
  }

  if (resource == "nodes" && request.method == "POST") {
    NodeInfo node;
    std::string port;
    if (!field(request.body, "host", node.host) ||
        !field(request.body, "public_key", node.public_key_hex)) {
      return problem(400, "Bad Request", "invalid_argument", "host and public_key are required");
    }
    if (!field(request.body, "id", node.id)) node.id = "srv_default";
    if (!field(request.body, "region", node.region)) node.region = "local";
    node.port = field(request.body, "port", port)
                    ? static_cast<std::uint16_t>(std::atoi(port.c_str()))
                    : 51820;
    const Status status = options_.store->add_node(node);
    if (!status) {
      const bool exists = status.code() == ErrorCode::kAlreadyExists;
      return problem(exists ? 409 : 422, exists ? "Conflict" : "Unprocessable Entity",
                     exists ? "already_exists" : "config_unsupported", status.message());
    }
    return json(201, "{\"id\":\"" + escape(node.id) + "\"}");
  }

  return problem(404, "Not Found", "not_found");
}

}  // namespace vpn::api
