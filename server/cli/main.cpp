// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// vpnctl - command-line client for the vpnd REST API.
//
// Deliberately dependency-free (like the server): a blocking HTTP/1.1 client over
// POSIX/Winsock sockets, no libcurl. Each command is a thin wrapper over one
// documented endpoint, so the CLI cannot drift from docs/api/openapi.yaml.
//
//   vpnctl login --email a@b.c --password s
//   vpnctl me | devices [list|create] | peers [list|create|delete] | servers
//   vpnctl config <peer-id>          (prints a wg-quick file)
//   vpnctl devices set-key <id> --key <hex>
//
// The token comes from --token, then $VPN_TOKEN, then the file written by login
// ($VPN_TOKEN_FILE, else ~/.vpn/token).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = std::uintptr_t;
using IoResult = int;
using IoSize = int;
constexpr SocketHandle kNoSocket = static_cast<SocketHandle>(~0ULL);
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
using SocketHandle = int;
using IoResult = ssize_t;
using IoSize = std::size_t;
constexpr SocketHandle kNoSocket = -1;
#endif

namespace {

struct Url {
  std::string host{"127.0.0.1"};
  std::uint16_t port{8080};
};

void close_socket(SocketHandle fd) noexcept {
#if defined(_WIN32)
  ::closesocket(fd);
#else
  ::close(fd);
#endif
}

[[nodiscard]] bool net_init() noexcept {
#if defined(_WIN32)
  static bool done = false;
  if (!done) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    done = true;
  }
#endif
  return true;
}

bool send_all(SocketHandle fd, std::string_view data) noexcept {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const IoResult n =
        ::send(fd, data.data() + sent, static_cast<IoSize>(data.size() - sent), 0);
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

[[nodiscard]] Url parse_url(const std::string& text) {
  Url url;
  std::string rest = text;
  if (rest.rfind("https://", 0) == 0) {
    rest = rest.substr(8);
    url.port = 443;
  } else if (rest.rfind("http://", 0) == 0) {
    rest = rest.substr(7);
  }
  const std::size_t slash = rest.find('/');
  if (slash != std::string::npos) rest.resize(slash);
  const std::size_t colon = rest.rfind(':');
  if (colon != std::string::npos) {
    url.port = static_cast<std::uint16_t>(std::strtoul(rest.c_str() + colon + 1, nullptr, 10));

    url.host = rest.substr(0, colon);
  } else {
    url.host = rest;
  }
  if (url.host.empty()) url.host = "127.0.0.1";
  return url;
}

}  // namespace

namespace {

struct Reply {
  int status{0};
  std::string body{};
};

// One request per connection (the server closes it), bounded response size.
[[nodiscard]] Reply http_request(const Url& url, std::string_view method, std::string_view path,
                                 std::string_view token, std::string_view body) {
  Reply reply;
  if (!net_init()) {
    std::fprintf(stderr, "error: cannot initialise sockets\n");
    return reply;
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* addresses = nullptr;
  const std::string service = std::to_string(url.port);
  if (::getaddrinfo(url.host.c_str(), service.c_str(), &hints, &addresses) != 0) {
    std::fprintf(stderr, "error: cannot resolve %s\n", url.host.c_str());
    return reply;
  }

  SocketHandle fd = kNoSocket;
  for (addrinfo* it = addresses; it != nullptr; it = it->ai_next) {
    fd = static_cast<SocketHandle>(::socket(it->ai_family, it->ai_socktype, it->ai_protocol));
    if (fd == kNoSocket) continue;
    // socklen_t is unsigned on Linux and int on Windows; casting to a fixed type
    // here is what -Wsign-conversion objects to.
#if defined(_WIN32)
    const int addr_len = static_cast<int>(it->ai_addrlen);
#else
    const socklen_t addr_len = static_cast<socklen_t>(it->ai_addrlen);
#endif
    if (::connect(fd, it->ai_addr, addr_len) == 0) break;
    close_socket(fd);
    fd = kNoSocket;
  }
  ::freeaddrinfo(addresses);
  if (fd == kNoSocket) {
    std::fprintf(stderr, "error: cannot connect to %s:%u (is vpnd running?)\n",
                 url.host.c_str(), static_cast<unsigned>(url.port));
    return reply;
  }

  std::string request;
  request += method;
  request += ' ';
  request += path;
  request += " HTTP/1.1\r\nHost: ";
  request += url.host;
  request += "\r\nUser-Agent: vpnctl/0.1\r\nAccept: application/json\r\n";
  if (!token.empty()) {
    request += "Authorization: Bearer ";
    request += token;
    request += "\r\n";
  }
  if (!body.empty()) {
    request += "Content-Type: application/json\r\nContent-Length: ";
    request += std::to_string(body.size());
    request += "\r\n";
  }
  request += "Connection: close\r\n\r\n";
  request += body;

  if (!send_all(fd, request)) {
    std::fprintf(stderr, "error: send failed\n");
    close_socket(fd);
    return reply;
  }

  std::string raw;
  char chunk[4096];
  for (;;) {
    const IoResult n = ::recv(fd, chunk, static_cast<IoSize>(sizeof(chunk)), 0);
    if (n <= 0) break;
    raw.append(chunk, static_cast<std::size_t>(n));
    if (raw.size() > (8U << 20U)) break;
  }
  close_socket(fd);

  const std::size_t header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    std::fprintf(stderr, "error: malformed response from the server\n");
    return reply;
  }
  reply.body = raw.substr(header_end + 4);
  const std::size_t sp = raw.find(' ');
  if (sp != std::string::npos) reply.status = std::atoi(raw.c_str() + sp + 1);
  return reply;
}

// Flat JSON string extraction. The CLI only reads top-level string fields, so a
// full parser would be a dependency (or hundreds of lines) for no benefit.
[[nodiscard]] std::string json_string(const std::string& body, std::string_view key) {
  const std::string needle = "\"" + std::string{key} + "\":\"";
  const std::size_t at = body.find(needle);
  if (at == std::string::npos) return {};
  std::size_t i = at + needle.size();
  std::string out;
  while (i < body.size() && body[i] != '"') {
    if (body[i] == '\\' && i + 1 < body.size()) {
      ++i;
      out.push_back(body[i] == 'n' ? '\n' : body[i]);
      ++i;
      continue;
    }
    out.push_back(body[i]);
    ++i;
  }
  return out;
}

// Numeric (unquoted) JSON field, e.g. "days_left":12.
[[nodiscard]] std::string json_number(const std::string& body, std::string_view key) {
  const std::string needle = "\"" + std::string{key} + "\":";
  const std::size_t at = body.find(needle);
  if (at == std::string::npos) return {};
  std::size_t i = at + needle.size();
  std::string out;
  while (i < body.size() && (body[i] == '-' || (body[i] >= '0' && body[i] <= '9'))) {
    out.push_back(body[i]);
    ++i;
  }
  return out;
}

// --- token storage ---------------------------------------------------------

[[nodiscard]] std::string token_path() {
  if (const char* explicit_path = std::getenv("VPN_TOKEN_FILE")) return explicit_path;
  const char* home = std::getenv("HOME");
  if (home == nullptr) home = std::getenv("USERPROFILE");
  if (home == nullptr) return ".vpn-token";
  return std::string{home} + "/.vpn/token";
}

[[nodiscard]] std::string read_token() {
  if (const char* env_token = std::getenv("VPN_TOKEN")) return env_token;
  const std::string path = token_path();
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return {};
  std::string token;
  char buffer[512];
  while (std::fgets(buffer, sizeof(buffer), file) != nullptr) token += buffer;
  std::fclose(file);
  while (!token.empty() && (token.back() == '\n' || token.back() == '\r' || token.back() == ' ')) {
    token.pop_back();
  }
  return token;
}

bool write_token(const std::string& token) {
  const std::string path = token_path();
  std::FILE* file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) {
    std::fprintf(stderr, "warning: cannot write %s; pass --token next time\n", path.c_str());
    return false;
  }
  std::fputs(token.c_str(), file);
  std::fputc('\n', file);
  std::fclose(file);
#if !defined(_WIN32)
  (void)::chmod(path.c_str(), S_IRUSR | S_IWUSR);  // the token is a bearer credential
#endif
  return true;
}

}  // namespace


namespace {

[[nodiscard]] std::string arg_value(int argc, char** argv, const char* name) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return {};
}

// The first non-option argument after the command (`index` 0 is the command).
[[nodiscard]] std::string positional(int argc, char** argv, int index) {
  int seen = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string_view token{argv[i]};
    if (token.rfind("--", 0) == 0) {
      if (i + 1 < argc && std::string_view{argv[i + 1]}.rfind("--", 0) != 0) ++i;
      continue;
    }
    if (seen == index) return std::string{token};
    ++seen;
  }
  return {};
}

void usage() {
  std::fputs(
      "vpnctl - control-plane client\n\n"
      "Usage: vpnctl <command> [options]\n\n"
      "  login --email <email> --password <password>   obtain and store a token\n"
      "  me                                            who am I\n"
      "  devices [list]                                list devices\n"
      "  devices create --name <name> [--platform p]   create a device\n"
      "  devices set-key <device-id> --key <hex>       register a device public key\n"
      "  peers [list]                                  list peers\n"
      "  peers create --device <device-id>             allocate a peer (IP + config)\n"
      "  peers delete <peer-id>                        delete a peer\n"
      "  config <peer-id>                              print the wg-quick config\n"
      "  servers                                       list available nodes\n"
      "  nodes add --host <host> --public-key <hex>    register a data-plane node\n"
      "            [--region r] [--port p] [--id id]\n"
      "\nOptions:\n"
      "  --api <url>     base URL (default: $VPN_API or http://127.0.0.1:8080)\n"
      "  --token <jwt>   access token (default: $VPN_TOKEN or ~/.vpn/token)\n",
      stderr);
}

// Renders a server-side problem+json body as a one-line error.
int fail(const Reply& reply) {
  std::string message = "error: HTTP " + std::to_string(reply.status);
  const std::string title = json_string(reply.body, "title");
  const std::string detail = json_string(reply.body, "detail");
  if (!title.empty()) message += " " + title;
  if (!detail.empty()) message += ": " + detail;
  if (title.empty() && detail.empty()) message += " " + reply.body;
  std::fprintf(stderr, "%s\n", message.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {  // NOLINT(bugprone-exception-escape)
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string command{argv[1]};
  if (command == "--help" || command == "-h" || command == "help") {
    usage();
    return 0;
  }

  std::string api = arg_value(argc, argv, "--api");
  if (api.empty()) {
    const char* from_env = std::getenv("VPN_API");
    api = from_env != nullptr ? from_env : "http://127.0.0.1:8080";
  }
  const Url url = parse_url(api);
  std::string token = arg_value(argc, argv, "--token");
  if (token.empty()) token = read_token();

  if (command == "login") {
    const std::string email = arg_value(argc, argv, "--email");
    const std::string password = arg_value(argc, argv, "--password");
    if (email.empty() || password.empty()) {
      std::fprintf(stderr, "error: --email and --password are required\n");
      return 2;
    }
    const std::string body =
        R"({"email":")" + email + R"(","password":")" + password + R"("})";
    const Reply reply = http_request(url, "POST", "/api/v1/auth/login", {}, body);
    if (reply.status != 200) return fail(reply);
    const std::string access = json_string(reply.body, "access_token");
    if (access.empty()) {
      std::fprintf(stderr, "error: the server returned no access_token\n");
      return 1;
    }
    (void)write_token(access);
    std::printf("logged in as %s (token stored in %s)\n",
                json_string(reply.body, "user_id").c_str(), token_path().c_str());
    return 0;
  }

  if (token.empty()) {
    std::fprintf(stderr, "error: no access token; run `vpnctl login` or pass --token\n");
    return 2;
  }

  const auto get = [&](const std::string& path) {
    return http_request(url, "GET", path, token, {});
  };

  if (command == "me") {
    const Reply reply = get("/api/v1/me");
    if (reply.status != 200) return fail(reply);
    const std::string access = reply.body.substr(reply.body.find("\"access\":") == std::string::npos
                                                     ? 0
                                                     : reply.body.find("\"access\":"));
    std::printf("user    %s\ntenant  %s\nrole    %s\nplan    %s\nstatus  %s\nleft    %s days\n",
                json_string(reply.body, "user_id").c_str(),
                json_string(reply.body, "tenant_id").c_str(),
                json_string(reply.body, "role").c_str(), json_string(access, "plan").c_str(),
                json_string(access, "status").c_str(), json_number(access, "days_left").c_str());
    return 0;
  }

  if (command == "servers") {
    const Reply reply = get("/api/v1/servers");
    if (reply.status != 200) return fail(reply);
    std::printf("%s\n", reply.body.c_str());
    return 0;
  }

  if (command == "devices") {
    const std::string action = positional(argc, argv, 1);
    if (action == "create") {
      std::string name = arg_value(argc, argv, "--name");
      std::string platform = arg_value(argc, argv, "--platform");
      if (name.empty()) name = "device";
      if (platform.empty()) platform = "linux";
      const std::string body =
          R"({"name":")" + name + R"(","platform":")" + platform + R"("})";
      const Reply reply = http_request(url, "POST", "/api/v1/devices", token, body);
      if (reply.status != 201) return fail(reply);
      std::printf("%s\n", json_string(reply.body, "id").c_str());
      return 0;
    }
    if (action == "set-key") {
      const std::string id = positional(argc, argv, 2);
      const std::string key = arg_value(argc, argv, "--key");
      if (id.empty() || key.empty()) {
        std::fprintf(stderr, "error: usage: vpnctl devices set-key <device-id> --key <hex>\n");
        return 2;
      }
      const Reply reply = http_request(url, "PUT", "/api/v1/devices/" + id + "/key", token,
                                      R"({"public_key":")" + key + R"("})");
      if (reply.status != 204 && reply.status != 200) return fail(reply);
      std::printf("device %s key registered\n", id.c_str());
      return 0;
    }
    const Reply reply = get("/api/v1/devices");
    if (reply.status != 200) return fail(reply);
    std::printf("%s\n", reply.body.c_str());
    return 0;
  }
  if (command == "peers") {
    const std::string action = positional(argc, argv, 1);
    if (action == "create") {
      const std::string device = arg_value(argc, argv, "--device");
      if (device.empty()) {
        std::fprintf(stderr, "error: usage: vpnctl peers create --device <device-id>\n");
        return 2;
      }
      const Reply reply = http_request(url, "POST", "/api/v1/peers", token,
                                      R"({"device_id":")" + device + R"("})");
      if (reply.status != 201) return fail(reply);
      std::printf("%s\n", reply.body.c_str());
      return 0;
    }
    if (action == "delete") {
      const std::string id = positional(argc, argv, 2);
      if (id.empty()) {
        std::fprintf(stderr, "error: usage: vpnctl peers delete <peer-id>\n");
        return 2;
      }
      const Reply reply = http_request(url, "DELETE", "/api/v1/peers/" + id, token, {});
      if (reply.status != 204 && reply.status != 200) return fail(reply);
      std::printf("peer %s deleted\n", id.c_str());
      return 0;
    }
    const Reply reply = get("/api/v1/peers");
    if (reply.status != 200) return fail(reply);
    std::printf("%s\n", reply.body.c_str());
    return 0;
  }

  if (command == "config") {
    const std::string id = positional(argc, argv, 1);
    if (id.empty()) {
      std::fprintf(stderr, "error: usage: vpnctl config <peer-id>\n");
      return 2;
    }
    const Reply reply = get("/api/v1/peers/" + id + "/config");
    if (reply.status != 200) return fail(reply);
    std::printf("%s", reply.body.c_str());
    return 0;
  }

  if (command == "admin") {
    const std::string action = positional(argc, argv, 1);
    const std::string sub = positional(argc, argv, 2);

    // Shared: {"months":N} or {"days":N}
    const auto duration_body = [&]() {
      std::string body = "{";
      const std::string months = arg_value(argc, argv, "--months");
      const std::string days = arg_value(argc, argv, "--days");
      const std::string plan = arg_value(argc, argv, "--plan");
      bool first = true;
      if (!months.empty()) {
        body += "\"months\":" + months;
        first = false;
      } else if (!days.empty()) {
        body += "\"days\":" + days;
        first = false;
      }
      if (!plan.empty()) {
        if (!first) body += ',';
        body += "\"plan\":\"" + plan + "\"";
      }
      body += "}";
      return body;
    };

    if (action == "users" && sub == "add") {
      const std::string email = arg_value(argc, argv, "--email");
      const std::string password = arg_value(argc, argv, "--password");
      if (email.empty() || password.empty()) {
        std::fprintf(stderr,
                     "error: usage: vpnctl admin users add --email <e> --password <p> "
                     "[--months N | --days N] [--role user]\n");
        return 2;
      }
      std::string body = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"";
      const std::string role = arg_value(argc, argv, "--role");
      if (!role.empty()) body += ",\"role\":\"" + role + "\"";
      const std::string months = arg_value(argc, argv, "--months");
      const std::string days = arg_value(argc, argv, "--days");
      const std::string plan = arg_value(argc, argv, "--plan");
      if (!months.empty()) body += ",\"months\":" + months;
      if (!days.empty()) body += ",\"days\":" + days;
      if (!plan.empty()) body += ",\"plan\":\"" + plan + "\"";
      body += "}";
      const Reply reply = http_request(url, "POST", "/api/v1/admin/users", token, body);
      if (reply.status != 201) return fail(reply);
      std::printf("%s\n", reply.body.c_str());
      return 0;
    }

    if (action == "users" && sub.empty()) {
      const Reply reply = get("/api/v1/admin/users");
      if (reply.status != 200) return fail(reply);
      const std::string body = reply.body;
      // One line per account: id, email, plan, status, days left, expiry.
      std::size_t pos = 0;
      while ((pos = body.find("\"email\":\"", pos)) != std::string::npos) {
        const std::size_t start = pos == 0 ? 0 : body.rfind('{', pos);
        const std::size_t end = body.find('}', pos);
        if (end == std::string::npos) break;
        const std::string record = body.substr(start == std::string::npos ? pos : start,
                                               end - (start == std::string::npos ? pos : start) + 1);
        std::printf("%-34s %-28s %-6s %-9s %4s days left\n",
                    json_string(record, "id").c_str(), json_string(record, "email").c_str(),
                    json_string(record, "plan").c_str(), json_string(record, "status").c_str(),
                    json_number(record, "days_left").c_str());
        pos = end;
      }
      return 0;
    }

    if ((action == "grant" || action == "extend") && !sub.empty()) {
      const Reply reply = http_request(url, "POST", "/api/v1/admin/users/" + sub + "/access", token,
                                      duration_body());
      if (reply.status != 200) return fail(reply);
      std::printf("extended: %s now expires (%s, %s days left)\n",
                  json_string(reply.body, "email").c_str(),
                  json_string(reply.body, "plan").c_str(),
                  json_number(reply.body, "days_left").c_str());
      return 0;
    }

    if (action == "revoke" && !sub.empty()) {
      const Reply reply = http_request(url, "POST", "/api/v1/admin/users/" + sub + "/revoke", token,
                                      "{}");
      if (reply.status != 204 && reply.status != 200) return fail(reply);
      std::printf("access revoked for %s\n", sub.c_str());
      return 0;
    }

    std::fprintf(stderr,
                 "error: usage:\n"
                 "  vpnctl admin users add --email <e> --password <p> [--months N|--days N]\n"
                 "  vpnctl admin users\n"
                 "  vpnctl admin grant <user-id> [--months N|--days N]\n"
                 "  vpnctl admin revoke <user-id>\n");
    return 2;
  }

  if (command == "nodes") {
    const std::string action = positional(argc, argv, 1);
    std::string host = arg_value(argc, argv, "--host");
    std::string public_key = arg_value(argc, argv, "--public-key");
    if (action != "add" || host.empty() || public_key.empty()) {
      std::fprintf(stderr,
                   "error: usage: vpnctl nodes add --host <host> --public-key <hex> "
                   "[--region <r>] [--port <p>] [--id <id>]\n");
      return 2;
    }
    std::string body = R"({"host":")" + host + R"(","public_key":")" + public_key + R"(")";
    const std::string region = arg_value(argc, argv, "--region");
    if (!region.empty()) body += R"(,"region":")" + region + R"(")";
    const std::string id = arg_value(argc, argv, "--id");
    if (!id.empty()) body += R"(,"id":")" + id + R"(")";
    const std::string port = arg_value(argc, argv, "--port");
    if (!port.empty()) body += R"(,"port":)" + port;
    body += "}";
    const Reply reply = http_request(url, "POST", "/api/v1/nodes", token, body);
    if (reply.status != 201) return fail(reply);
    std::printf("node %s registered\n", json_string(reply.body, "id").c_str());
    return 0;
  }

  std::fprintf(stderr, "error: unknown command '%s'\n\n", command.c_str());
  usage();
  return 2;
}
