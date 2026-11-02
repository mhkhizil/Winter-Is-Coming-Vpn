// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Wire-level regression tests for the M0 control-plane server. These cover the
// defects the hardening review found: unbounded Prometheus label cardinality, the
// soft header limit, undelivered error responses, and shutdown latency while a
// client is stalled in the middle of a request.
#include "test_support.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "vpn/controlplane/http_server.hpp"
#include "vpn/obs/metrics.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using TestSocket = SOCKET;
constexpr TestSocket kNoSocket = INVALID_SOCKET;
using SocketLength = int;  // Winsock send/recv take an int
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using TestSocket = int;
constexpr TestSocket kNoSocket = -1;
using SocketLength = std::size_t;  // POSIX send/recv take a size_t
#endif

namespace {

void close_test_socket(TestSocket fd) noexcept {
#if defined(_WIN32)
  ::closesocket(fd);
#else
  ::close(fd);
#endif
}

void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// Minimal blocking client with a hard receive timeout, so a regression fails a
// test instead of hanging the suite.
class TestClient {
 public:
  TestClient(std::uint16_t port, int timeout_secs = 5) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ == kNoSocket) return;
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(timeout_secs * 1000);
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{};
    tv.tv_sec = timeout_secs;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connected_ = ::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
  }

  ~TestClient() {
    if (fd_ != kNoSocket) close_test_socket(fd_);
  }

  TestClient(const TestClient&) = delete;
  TestClient& operator=(const TestClient&) = delete;

  [[nodiscard]] bool connected() const noexcept { return connected_; }

  bool send(std::string_view data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
      const auto n = ::send(fd_, data.data() + sent, static_cast<SocketLength>(data.size() - sent), 0);
      if (n <= 0) return false;
      sent += static_cast<std::size_t>(n);
    }
    return true;
  }

  [[nodiscard]] std::string read_reply() {
    std::string out;
    char buf[1024];
    while (true) {
      const auto n = ::recv(fd_, buf, static_cast<SocketLength>(sizeof(buf)), 0);
      if (n <= 0) break;
      out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
  }

  [[nodiscard]] std::string request(std::string_view bytes) {
    if (!send(bytes)) return {};
    return read_reply();
  }

  void shutdown_write() {
#if defined(_WIN32)
    ::shutdown(fd_, SD_SEND);
#else
    ::shutdown(fd_, SHUT_WR);
#endif
  }

 private:
  TestSocket fd_{kNoSocket};
  bool connected_{false};
};

struct RunningServer {
  explicit RunningServer(std::uint32_t timeout_secs = 5) { start(timeout_secs); }

  // Server with an explicit TLS-termination policy (ADR-0009).
  RunningServer(std::uint32_t timeout_secs,
                vpn::controlplane::HttpServer::Options::TlsPolicy tls) {
    options_.tls = std::move(tls);
    start(timeout_secs);
  }

  void start(std::uint32_t timeout_secs) {
    options_.bind = vpn::Endpoint{"127.0.0.1", 0};
    options_.request_timeout_secs = timeout_secs;
    server_ = std::make_unique<vpn::controlplane::HttpServer>(options_, health_, metrics_);
    if (!server_->listen().ok()) return;
    port_ = server_->bound_port();
    thread_ = std::thread([this] {
      serve_status_ = server_->serve();
      serve_finished_.store(true);
    });
    for (int i = 0; i < 200 && !health_.accepting_connections.load(); ++i) sleep_ms(5);
    started_ = true;
  }

  ~RunningServer() { stop(); }

  void stop() {
    if (!server_) return;
    server_->stop();
    if (thread_.joinable()) thread_.join();
    server_.reset();
  }

  [[nodiscard]] bool started() const noexcept { return started_; }
  [[nodiscard]] bool serve_finished() const noexcept { return serve_finished_.load(); }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] vpn::obs::Metrics& metrics() noexcept { return metrics_; }
  [[nodiscard]] const vpn::Status& serve_status() const noexcept { return serve_status_; }
  [[nodiscard]] vpn::controlplane::HttpServer& server() noexcept { return *server_; }

  // Declaration order matters: the server keeps references to health_/metrics_,
  // so those must outlive it.
  vpn::obs::Metrics metrics_{};
  vpn::controlplane::HealthState health_{};
  vpn::controlplane::HttpServer::Options options_{};
  std::unique_ptr<vpn::controlplane::HttpServer> server_{};
  std::thread thread_{};
  std::atomic<bool> serve_finished_{false};
  vpn::Status serve_status_{};
  std::uint16_t port_{0};
  bool started_{false};
};

[[nodiscard]] std::string metric_route_values(const std::string& exposition) {
  std::string out;
  const std::string needle = "route=\"";
  for (std::size_t at = exposition.find(needle); at != std::string::npos;
       at = exposition.find(needle, at + needle.size())) {
    const std::size_t begin = at + needle.size();
    const std::size_t end = exposition.find('"', begin);
    if (end == std::string::npos) break;
    out += exposition.substr(begin, end - begin) + '|';
  }
  return out;
}

[[nodiscard]] std::vector<std::string> split_values(const std::string& packed) {
  std::vector<std::string> out;
  std::size_t begin = 0;
  while (begin < packed.size()) {
    const std::size_t end = packed.find('|', begin);
    if (end == std::string::npos) break;
    out.push_back(packed.substr(begin, end - begin));
    begin = end + 1;
  }
  return out;
}

[[nodiscard]] std::size_t distinct_values(const std::string& packed) {
  const auto values = split_values(packed);
  std::size_t distinct = 0;
  for (std::size_t i = 0; i < values.size(); ++i) {
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) {
      if (values[j] == values[i]) duplicate = true;
    }
    if (!duplicate) ++distinct;
  }
  return distinct;
}

}  // namespace

TEST(HttpServer, serves_healthz_with_the_hardening_headers) {
  RunningServer server;
  CHECK_MSG(server.started(), "server did not start");
  TestClient client(server.port());
  CHECK_MSG(client.connected(), "connect failed");
  const std::string reply = client.request("GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 200 OK", 0) == 0, "unexpected reply:\n" + reply);
  CHECK_MSG(reply.find("Connection: close\r\n") != std::string::npos, "no Connection: close");
  CHECK_MSG(reply.find("X-Content-Type-Options: nosniff") != std::string::npos, "no nosniff");
  CHECK_MSG(reply.find("\"status\":\"ok\"") != std::string::npos, "unexpected body");
}

TEST(HttpServer, head_sends_headers_only_but_keeps_content_length) {
  RunningServer server;
  TestClient get_client(server.port());
  const std::string get_reply = get_client.request("GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  TestClient head_client(server.port());
  const std::string head_reply =
      head_client.request("HEAD /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(head_reply.rfind("HTTP/1.1 200 OK", 0) == 0, "unexpected reply:\n" + head_reply);
  const std::size_t sep = head_reply.find("\r\n\r\n");
  CHECK_MSG(sep != std::string::npos && sep + 4 == head_reply.size(),
            "HEAD must not send a body, got:\n" + head_reply);
  const std::string marker = "Content-Length: ";
  const std::size_t at = get_reply.find(marker);
  const std::size_t hat = head_reply.find(marker);
  CHECK(hat != std::string::npos);
  if (at == std::string::npos || hat == std::string::npos) return;
  CHECK_EQ(get_reply.substr(at, get_reply.find("\r\n", at) - at),
           head_reply.substr(hat, head_reply.find("\r\n", hat) - hat));
}

TEST(HttpServer, method_not_allowed_carries_an_allow_header) {
  RunningServer server;
  TestClient client(server.port());
  const std::string reply = client.request("POST /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 405", 0) == 0, "unexpected reply:\n" + reply);
  CHECK_MSG(reply.find("Allow: GET, HEAD") != std::string::npos, "missing Allow header");
}

TEST(HttpServer, response_reaches_the_client_even_when_a_body_was_sent) {
  RunningServer server;
  TestClient client(server.port());
  std::string request = "POST /healthz HTTP/1.1\r\nHost: t\r\nContent-Length: 200000\r\n\r\n";
  request.append(200000, 'z');
  const std::string reply = client.request(request);
  // Closing with unread input used to reset the connection and discard the
  // response entirely, so the client saw nothing.
  CHECK_MSG(reply.rfind("HTTP/1.1 405", 0) == 0,
            "error response was lost when unread request bytes were pending:\n" + reply);
}

TEST(HttpServer, oversized_header_is_rejected_with_431) {
  RunningServer server;
  TestClient client(server.port(), 5);
  std::string request = "GET /healthz HTTP/1.1\r\nX-Filler: ";
  request.append(9000, 'A');
  request += "\r\n\r\n";
  const std::string reply = client.request(request);
  CHECK_MSG(reply.rfind("HTTP/1.1 431", 0) == 0,
            "a 9 KiB header must be refused, got:\n" +
                reply.substr(0, std::min<std::size_t>(reply.size(), 120)));
}

TEST(HttpServer, malformed_request_lines_are_rejected_with_400) {
  RunningServer server;
  struct Case {
    const char* name;
    const char* payload;
  };
  const Case cases[] = {
      {"http 0.9", "GET /healthz\r\n\r\n"},
      {"empty target", "GET  /healthz HTTP/1.1\r\n\r\n"},
      {"garbage", "BOGUS\r\n\r\n"},
      {"empty line", "\r\n\r\n"},
  };
  for (const auto& c : cases) {
    TestClient client(server.port());
    const std::string reply = client.request(c.payload);
    CHECK_MSG(reply.rfind("HTTP/1.1 400", 0) == 0,
              std::string("case '") + c.name + "' should be 400, got:\n" + reply);
  }
}

TEST(HttpServer, absolute_form_request_target_is_routed) {
  RunningServer server;
  TestClient client(server.port());
  const std::string reply = client.request(
      "GET http://example.invalid/healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 200", 0) == 0,
            "absolute-form target must be accepted (RFC 9112 3.2.2), got:\n" + reply);
}

TEST(HttpServer, metrics_route_label_is_bounded) {
  RunningServer server;
  for (int i = 0; i < 40; ++i) {
    TestClient client(server.port());
    (void)client.request("GET /scan-" + std::to_string(i) + " HTTP/1.1\r\nHost: t\r\n\r\n");
  }
  TestClient scraper(server.port());
  const std::string reply = scraper.request("GET /metrics HTTP/1.1\r\nHost: t\r\n\r\n");
  const std::string routes = metric_route_values(reply);
  CHECK_MSG(!routes.empty(), "no route labels in the exposition:\n" + reply);
  const std::size_t distinct = distinct_values(routes);
  CHECK_MSG(distinct <= 8, "route label is unbounded: " + std::to_string(distinct) +
                               " distinct values after 40 scans");
  CHECK_MSG(reply.find("route=\"other\"") != std::string::npos,
            "unknown routes must be bucketed into \"other\":\n" + reply);
}

TEST(HttpServer, metrics_method_label_is_bounded) {
  RunningServer server;
  for (int i = 0; i < 10; ++i) {
    TestClient client(server.port());
    (void)client.request("M" + std::to_string(i) + " /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  }
  TestClient scraper(server.port());
  const std::string reply = scraper.request("GET /metrics HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.find("method=\"other\"") != std::string::npos,
            "unknown methods must be bucketed into \"other\":\n" + reply);
  CHECK(distinct_values(metric_route_values(reply)) <= 8);
}

TEST(HttpServer, second_listener_on_the_same_port_is_refused) {
  RunningServer first;
  CHECK_MSG(first.started(), "first server did not start");

  vpn::obs::Metrics metrics;
  vpn::controlplane::HealthState health;
  vpn::controlplane::HttpServer::Options options;
  options.bind = vpn::Endpoint{"127.0.0.1", first.port()};
  vpn::controlplane::HttpServer second{options, health, metrics};
  const vpn::Status status = second.listen();
  CHECK_MSG(!status.ok(), "a second listener bound 127.0.0.1:" +
                              std::to_string(first.port()) +
                              " while the first was running (address hijacking)");
  CHECK_MSG(status.to_string().find("127.0.0.1") != std::string::npos,
            "bind failure must name the address, got: " + status.to_string());
}

TEST(HttpServer, stop_returns_promptly_while_a_client_is_stalled) {
  RunningServer server;
  CHECK_MSG(server.started(), "server did not start");

  // Half a request line: the accept loop is now blocked in recv() with the
  // configured request timeout, exactly like a slowloris client.
  TestClient stalled(server.port(), 30);
  CHECK_MSG(stalled.connected(), "connect failed");
  CHECK(stalled.send("GET /healthz HT"));
  sleep_ms(300);

  const auto started_at = std::chrono::steady_clock::now();
  server.server().stop();
  // Measure until the accept loop has actually returned: that is what bounds
  // SIGTERM -> process exit, not the stop() call itself.
  while (!server.serve_finished() &&
         std::chrono::steady_clock::now() - started_at < std::chrono::seconds(10)) {
    sleep_ms(5);
  }
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - started_at)
                      .count();
  CHECK_MSG(server.serve_finished(), "serve() never returned after stop()");
  std::printf("    stop() -> serve() returned after %lld ms (budget 2000 ms)\n",
              static_cast<long long>(ms));
  CHECK_MSG(ms < 2000, "stop() -> serve() return took " + std::to_string(ms) +
                           " ms with a stalled client (this is SIGTERM latency)");
}


// --- TLS termination policy (ADR-0009) --------------------------------------
//
// vpnd never terminates TLS itself: the edge proxy does, and asserts the original
// scheme in X-Forwarded-Proto. These tests pin the fail-closed behaviour, because
// a misconfigured proxy silently serving the API in cleartext is exactly the
// failure mode this policy exists to prevent.

TEST(TlsPolicy, plaintext_api_request_is_refused) {
  vpn::controlplane::HttpServer::Options::TlsPolicy tls;
  tls.require_https = true;
  tls.trusted_proxies = {"127.0.0.1/32"};
  RunningServer server{5, tls};
  CHECK_MSG(server.started(), "server did not start");
  TestClient client(server.port());
  CHECK_MSG(client.connected(), "connect failed");
  const std::string reply = client.request("GET /api/v1/me HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 403 Forbidden", 0) == 0, "expected 403, got:\n" + reply);
  CHECK_MSG(reply.find("HTTPS Required") != std::string::npos, "no problem title");
}

TEST(TlsPolicy, health_endpoints_stay_reachable_over_plain_http) {
  vpn::controlplane::HttpServer::Options::TlsPolicy tls;
  tls.require_https = true;
  tls.trusted_proxies = {"127.0.0.1/32"};
  RunningServer server{5, tls};
  CHECK_MSG(server.started(), "server did not start");
  for (const char* path : {"/healthz", "/readyz", "/metrics"}) {
    TestClient client(server.port());
    CHECK_MSG(client.connected(), "connect failed");
    const std::string reply =
        client.request(std::string{"GET "} + path + " HTTP/1.1\r\nHost: t\r\n\r\n");
    CHECK_MSG(reply.rfind("HTTP/1.1 200 OK", 0) == 0,
              std::string{"expected 200 for "} + path + ", got:\n" + reply);
  }
}

TEST(TlsPolicy, untrusted_peer_cannot_forge_x_forwarded_proto) {
  vpn::controlplane::HttpServer::Options::TlsPolicy tls;
  tls.require_https = true;
  tls.trusted_proxies = {};  // nothing is trusted: the header is not evidence
  RunningServer server{5, tls};
  CHECK_MSG(server.started(), "server did not start");
  TestClient client(server.port());
  CHECK_MSG(client.connected(), "connect failed");
  const std::string reply = client.request(
      "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nX-Forwarded-Proto: https\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 403 Forbidden", 0) == 0,
            "a direct client must not be able to claim https, got:\n" + reply);
}

TEST(TlsPolicy, trusted_proxy_makes_https_requests_pass_and_gets_hsts) {
  vpn::controlplane::HttpServer::Options::TlsPolicy tls;
  tls.require_https = true;
  tls.hsts = true;
  tls.hsts_max_age_secs = 600;
  tls.trusted_proxies = {"127.0.0.0/8"};  // CIDR, not an exact address
  RunningServer server{5, tls};
  CHECK_MSG(server.started(), "server did not start");
  TestClient client(server.port());
  CHECK_MSG(client.connected(), "connect failed");
  const std::string reply = client.request(
      "GET /healthz HTTP/1.1\r\nHost: t\r\nX-Forwarded-Proto: https\r\n\r\n");
  CHECK_MSG(reply.rfind("HTTP/1.1 200 OK", 0) == 0, "expected 200, got:\n" + reply);
  CHECK_MSG(reply.find("Strict-Transport-Security: max-age=600") != std::string::npos,
            "no HSTS header on a TLS request");
}

TEST(TlsPolicy, hsts_is_absent_when_the_request_did_not_arrive_over_tls) {
  vpn::controlplane::HttpServer::Options::TlsPolicy tls;
  tls.hsts = true;
  tls.trusted_proxies = {"127.0.0.0/8"};
  RunningServer server{5, tls};
  CHECK_MSG(server.started(), "server did not start");
  TestClient client(server.port());
  CHECK_MSG(client.connected(), "connect failed");
  const std::string reply = client.request("GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n");
  CHECK_MSG(reply.find("Strict-Transport-Security") == std::string::npos,
            "HSTS must not be sent on a cleartext response");
}

