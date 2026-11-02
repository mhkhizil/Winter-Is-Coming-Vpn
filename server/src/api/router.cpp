// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/api/router.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iterator>

#include "vpn/common/bytes.hpp"
#include "vpn/common/result_helpers.hpp"
#include "vpn/notify/smtp.hpp"

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
          // Masked to 8 bits: GCC then proves "%04x" cannot overflow this buffer.
          char buffer[8] = {};
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(c) & 0xFFU);
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

// --- login throttling -------------------------------------------------------
namespace {
constexpr std::uint32_t kMaxLoginFailures = 5;
constexpr std::int64_t kLoginWindowMs = 15 * 60 * 1000;
constexpr std::size_t kMaxLoginEntries = 4096;
}  // namespace

bool Router::login_locked(const std::string& email) const {
  const std::lock_guard<std::mutex> lock(login_mutex_);
  const auto it = login_attempts_.find(email);
  return it != login_attempts_.end() && it->second.locked_until_ms > now_ms();
}

void Router::login_failed(const std::string& email) {
  const std::lock_guard<std::mutex> lock(login_mutex_);
  // Bounded like the rate-limit buckets: keyed by client-supplied identity.
  if (login_attempts_.size() >= kMaxLoginEntries) login_attempts_.clear();
  LoginState& state = login_attempts_[email];
  const std::int64_t now = now_ms();
  if (state.window_start_ms == 0 || now - state.window_start_ms > kLoginWindowMs) {
    state.failures = 0;
    state.window_start_ms = now;
  }
  ++state.failures;
  if (state.failures >= kMaxLoginFailures) state.locked_until_ms = now + kLoginWindowMs;
}

void Router::login_succeeded(const std::string& email) {
  const std::lock_guard<std::mutex> lock(login_mutex_);
  login_attempts_.erase(email);
}

bool Router::allow(const std::string& client_ip) {
  const std::lock_guard<std::mutex> lock(buckets_mutex_);
  const std::int64_t now = now_ms();

  // The bucket table is keyed by client address, so it must be bounded: an
  // attacker rotating source addresses would otherwise grow it without limit (one
  // Bucket per address, forever - a slow but unbounded leak). Evict idle buckets
  // first, and only clear wholesale as a last resort.
  constexpr std::size_t kMaxBuckets = 4096;
  constexpr std::int64_t kIdleMs = 60000;
  if (buckets_.size() >= kMaxBuckets) {
    for (auto it = buckets_.begin(); it != buckets_.end();) {
      it = (now - it->second.last_refill_ms > kIdleMs) ? buckets_.erase(it) : std::next(it);
    }
    if (buckets_.size() >= kMaxBuckets) buckets_.clear();
  }

  Bucket& bucket = buckets_[client_ip];
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

namespace {
// Entitlement helpers (ADR-0010): money is collected out of band, so the only
// thing the service knows is "this account is paid up until <timestamp>".
constexpr std::int64_t kSecondsPerDay = 86400;

std::string access_status(const AccessGrant& grant, std::int64_t now) {
  if (grant.status != "active") return grant.status;  // disabled by an administrator
  if (grant.expires_at != 0 && grant.expires_at <= now) return "expired";
  return "active";
}

std::string user_json(const UserRecord& user, std::int64_t now) {
  std::int64_t days_left = 0;
  if (user.access.expires_at != 0) {
    const std::int64_t remaining = user.access.expires_at - now;
    days_left = remaining > 0 ? (remaining + kSecondsPerDay - 1) / kSecondsPerDay : 0;
  }
  return "{\"id\":\"" + escape(user.id) + "\",\"email\":\"" + escape(user.email) +
         "\",\"role\":\"" + escape(user.role) + "\",\"plan\":\"" + escape(user.access.plan) +
         "\",\"status\":\"" + access_status(user.access, now) +
         "\",\"expires_at\":" + std::to_string(user.access.expires_at) +
         ",\"days_left\":" + std::to_string(days_left) + "}";
}

int status_for(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kPermissionDenied: return 403;
    case ErrorCode::kNotFound: return 404;
    case ErrorCode::kAlreadyExists: return 409;
    case ErrorCode::kInvalidArgument: return 400;
    case ErrorCode::kMalformed: return 400;
    default: return 500;
  }
}
}  // namespace

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
      // Refuse BEFORE hashing the password: a locked account must not cost a
      // PBKDF2 run, and a credential-stuffing run must not get CPU for free. Note
      // the throttle is per account, not per IP - the attacker rotates addresses,
      // the account being attacked does not rotate.
      if (login_locked(email)) {
        return problem(429, "Too Many Requests", "too_many_attempts",
                       "too many failed attempts; try again in 15 minutes");
      }
      auto principal = options_.store->authenticate(email, password);
      if (!principal) {
        login_failed(email);
        return problem(401, "Unauthorized", "unauthenticated", "invalid credentials");
      }
      login_succeeded(email);
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
    const std::int64_t now = std::time(nullptr);
    const AccessGrant grant = options_.store->access_grant(who.user_id);
    return json(200, "{\"user_id\":\"" + escape(who.user_id) + "\",\"tenant_id\":\"" +
                         escape(who.tenant_id) + "\",\"role\":\"" + escape(who.role) +
                         "\",\"access\":" + user_json(UserRecord{who.user_id, who.tenant_id, "",
                                                                 who.role, grant}, now) +
                         "}");
  }

  // --- administration: accounts and paid access (ADR-0010) -------------------
  //
  // Money is collected out of band (transfer, cash, whatever), and an
  // administrator records the result here. Creating an account requires a
  // duration; when it runs out the account can no longer obtain a configuration
  // or a peer, and the data plane stops forwarding for it.
  if (resource == "admin") {
    if (who.role != "admin") {
      return problem(403, "Forbidden", "permission_denied", "administrator role required");
    }
    const std::int64_t now = std::time(nullptr);

    const auto code_for = [](int status) {
      switch (status) {
        case 409: return "already_exists";
        case 404: return "not_found";
        case 403: return "permission_denied";
        case 400: return "invalid_argument";
        default: return "internal";
      }
    };
    const auto fail = [&](int status, const std::string& detail) {
      const char* title = "Bad Request";
      if (status == 409) title = "Conflict";
      else if (status == 404) title = "Not Found";
      else if (status == 403) title = "Forbidden";
      else if (status >= 500) title = "Internal Server Error";
      return problem(status, title, code_for(status), detail);
    };

    // `months` (30-day months, the way operators sell this) or `days`.
    const auto duration = [&](std::int64_t& out, std::string& plan) {
      std::string raw;
      if (field(request.body, "months", raw)) {
        const long months = std::strtol(raw.c_str(), nullptr, 10);
        if (months < 1 || months > 120) return false;
        out = static_cast<std::int64_t>(months) * 30;
        plan = std::to_string(months) + "m";
        return true;
      }
      if (field(request.body, "days", raw)) {
        const long days = std::strtol(raw.c_str(), nullptr, 10);
        if (days < 1 || days > 3650) return false;
        out = static_cast<std::int64_t>(days);
        plan = std::to_string(days) + "d";
        return true;
      }
      out = 30;  // default: one month
      plan = "1m";
      return true;
    };

    if (parts.size() >= 4 && parts[3] == "users") {
      if (parts.size() == 4 && request.method == "POST") {
        std::string email;
        std::string password;
        std::string role;
        std::string explicit_plan;
        if (!field(request.body, "email", email) || !field(request.body, "password", password)) {
          return fail(400, "email and password are required");
        }
        (void)field(request.body, "role", role);
        (void)field(request.body, "plan", explicit_plan);
        std::int64_t days = 30;
        std::string plan;
        if (!duration(days, plan)) return fail(400, "months must be 1..120 (or days 1..3650)");
        if (!explicit_plan.empty()) plan = explicit_plan;
        const auto created = options_.store->create_user(
            who, email, password, role, now + days * kSecondsPerDay, plan);
        if (!created) return fail(status_for(created.error().code()), created.error().message());
        return json(201, user_json(*created, now));
      }
      if (parts.size() == 4 && request.method == "GET") {
        const auto users = options_.store->list_users(who);
        if (!users) return fail(status_for(users.error().code()), users.error().message());
        std::string body = "{\"data\":[";
        bool first = true;
        for (const UserRecord& user : *users) {
          if (!first) body += ',';
          first = false;
          body += user_json(user, now);
        }
        body += "]}";
        return json(200, body);
      }
      if (parts.size() == 5 && request.method == "GET") {
        const auto user = options_.store->get_user(who, parts[4]);
        if (!user) return fail(status_for(user.error().code()), user.error().message());
        return json(200, user_json(*user, now));
      }
      // POST /api/v1/admin/users/{id}/access  {"months":6}  -> extend
      if (parts.size() == 6 && request.method == "POST" && parts[5] == "access") {
        std::int64_t days = 30;
        std::string plan;
        std::string explicit_plan;
        (void)field(request.body, "plan", explicit_plan);
        if (!duration(days, plan)) return fail(400, "months must be 1..120 (or days 1..3650)");
        if (!explicit_plan.empty()) plan = explicit_plan;
        // Extending adds to whatever is left: paying early must never lose days.
        const AccessGrant current = options_.store->access_grant(parts[4]);
        const std::int64_t base = current.expires_at > now ? current.expires_at : now;
        const auto updated =
            options_.store->grant_access(who, parts[4], base + days * kSecondsPerDay, plan);
        if (!updated) return fail(status_for(updated.error().code()), updated.error().message());
        return json(200, user_json(*updated, now));
      }
      // POST /api/v1/admin/users/{id}/password {"password":"..."} -> reset
      if (parts.size() == 6 && request.method == "POST" && parts[5] == "password") {
        std::string next;
        if (!field(request.body, "password", next)) return fail(400, "password is required");
        const Status status = options_.store->reset_password(who, parts[4], next);
        if (!status) return fail(status_for(status.code()), status.message());
        return json(204, "");
      }
      // POST /api/v1/admin/users/{id}/revoke -> immediate lockout
      if (parts.size() == 6 && request.method == "POST" && parts[5] == "revoke") {
        const Status status = options_.store->revoke_access(who, parts[4]);
        if (!status) return fail(status_for(status.code()), status.message());
        return json(204, "");
      }
    }

    // POST /api/v1/admin/reminders/run?days=7,1&dry_run=1
    //
    // Idempotent: an account is marked per bucket, so this can run from cron every
    // day without spamming anyone. Query parameters (not a JSON body) because the
    // values are plain numbers and the command is meant to be curl-able.
    if (parts.size() >= 4 && parts[3] == "reminders") {
      if (request.method != "POST") return problem(405, "Method Not Allowed", "not_allowed");
      const auto query_value = [&](const char* name) -> std::string {
        const std::string needle = std::string{name} + "=";
        const std::size_t at = request.query.find(needle);
        if (at == std::string::npos) return {};
        std::size_t end = request.query.find('&', at);
        if (end == std::string::npos) end = request.query.size();
        return request.query.substr(at + needle.size(), end - (at + needle.size()));
      };

      std::string spec = query_value("days");
      if (spec.empty()) spec = "7,1";
      const bool dry_run = query_value("dry_run") == "1" || query_value("dry_run") == "true" ||
                           options_.smtp_dry_run;

      notify::SmtpConfig smtp;
      smtp.host = options_.smtp_host;
      smtp.port = options_.smtp_port;
      smtp.from = options_.smtp_from;
      smtp.username = options_.smtp_username;
      smtp.password = options_.smtp_password;
      smtp.dry_run = dry_run;
      if (smtp.host.empty()) {
        return problem(503, "Service Unavailable", "not_configured",
                       "smtp is not configured: set [smtp] host/from in the vpnd config");
      }

      int sent = 0;
      int failed = 0;
      std::string detail;
      std::size_t cursor = 0;
      while (cursor <= spec.size()) {
        const std::size_t comma = spec.find(',', cursor);
        const std::string item =
            spec.substr(cursor, comma == std::string::npos ? std::string::npos : comma - cursor);
        cursor = comma == std::string::npos ? spec.size() + 1 : comma + 1;
        const long days = std::strtol(item.c_str(), nullptr, 10);
        if (days < 1 || days > 365) continue;
        const std::string bucket = std::to_string(days) + "d";
        const auto expiring = options_.store->accounts_expiring_within(who, days, bucket);
        if (!expiring) return fail(status_for(expiring.error().code()), expiring.error().message());
        for (const auto& account : *expiring) {
          notify::Message message;
          message.to = account.email;
          message.subject = "Your VPN access ends in " + std::to_string(days) + " day(s)";
          message.body = "Hello,\n\nYour VPN access (plan " + account.user.access.plan +
                         ") ends in " + std::to_string(days) +
                         " day(s).\n\nTo keep using the service, renew with your provider. "
                         "Your existing configuration keeps working until then.\n";
          const Status status = notify::send(smtp, message);
          if (status.ok()) {
            ++sent;
            (void)options_.store->mark_reminder_sent(who, account.user.id, bucket);
          } else {
            ++failed;
            detail += (detail.empty() ? "" : "; ") + account.email + ": " + status.message();
          }
        }
      }
      std::string body = "{\"sent\":" + std::to_string(sent) + ",\"failed\":" +
                         std::to_string(failed) + ",\"dry_run\":" + (dry_run ? "true" : "false");
      if (!detail.empty()) body += ",\"errors\":\"" + escape(detail) + "\"";
      body += "}";
      return json(failed == 0 ? 200 : 502, body);
    }

    return problem(404, "Not Found", "not_found");
  }

  // GET /api/v1/dp/config?node=<id> -> the peer table a node should run, rendered
  // as the TOML subset `vpn-dp` already parses (ADR-0011). Administrator only: it
  // contains every peer's public key.
  if (resource == "dp") {
    if (who.role != "admin") {
      return problem(403, "Forbidden", "permission_denied", "administrator role required");
    }
    if (!(parts.size() >= 4 && parts[3] == "config") || request.method != "GET") {
      return problem(404, "Not Found", "not_found");
    }
    std::string node;
    const std::size_t at = request.query.find("node=");
    if (at != std::string::npos) {
      std::size_t end = request.query.find('&', at);
      if (end == std::string::npos) end = request.query.size();
      node = request.query.substr(at + 5, end - (at + 5));
    }
    const auto rendered = options_.store->render_dp_config(who, node);
    if (!rendered) {
      return problem(status_for(rendered.error().code()),
                     rendered.error().code() == ErrorCode::kUnavailable ? "Service Unavailable"
                                                                       : "Internal Server Error",
                     "internal", rendered.error().message());
    }
    return text(200, *rendered);
  }

  if (resource == "me" && request.method == "POST" && parts.size() >= 4 && parts[3] == "password") {
    std::string current;
    std::string next;
    if (!field(request.body, "current_password", current) ||
        !field(request.body, "new_password", next)) {
      return problem(400, "Bad Request", "invalid_argument",
                     "current_password and new_password are required");
    }
    const Status status = options_.store->change_password(who, current, next);
    if (!status) {
      if (status.code() == ErrorCode::kUnauthenticated) {
        return problem(401, "Unauthorized", "unauthenticated", status.message());
      }
      return problem(status.code() == ErrorCode::kInvalidArgument ? 400 : 500,
                     status.code() == ErrorCode::kInvalidArgument ? "Bad Request"
                                                                  : "Internal Server Error",
                     status.code() == ErrorCode::kInvalidArgument ? "invalid_argument"
                                                                  : "internal",
                     status.message());
    }
    return json(204, "");
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
        // Expired or revoked access is not a bad request: the client must renew.
        // 403 + `access_expired` is what a UI keys on to show "your plan ended".
        if (peer.error().code() == ErrorCode::kPermissionDenied) {
          return problem(403, "Forbidden", "access_expired", peer.error().message());
        }
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
        if (!conf) {
          if (conf.error().code() == ErrorCode::kPermissionDenied) {
            return problem(403, "Forbidden", "access_expired", conf.error().message());
          }
          return problem(404, "Not Found", "not_found", conf.error().message());
        }
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
