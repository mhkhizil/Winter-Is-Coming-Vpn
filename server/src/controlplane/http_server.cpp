// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/controlplane/http_server.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "vpn/common/log.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifndef VPN_VERSION
#define VPN_VERSION "0.0.0"
#endif

namespace vpn::controlplane {
namespace {

#if defined(_WIN32)
using SocketHandle = SOCKET;
using SockLen = int;
using IoSize = int;
using IoResult = int;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
using SockLen = ::socklen_t;
using IoSize = std::size_t;
using IoResult = ssize_t;
constexpr SocketHandle kInvalidSocket = -1;
#endif

void close_socket(SocketHandle fd) noexcept {
#if defined(_WIN32)
  if (fd != kInvalidSocket) ::closesocket(fd);
#else
  if (fd >= 0) ::close(fd);
#endif
}

[[nodiscard]] bool socket_failed(SocketHandle fd) noexcept { return fd == kInvalidSocket; }

// One-time WSA startup on Windows; a no-op elsewhere.
[[nodiscard]] Status ensure_net_initialized() {
  static std::once_flag once;
  static Status result;
  std::call_once(once, [] {
#if defined(_WIN32)
    WSADATA data{};
    if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      result = Status{ErrorCode::kInternal, "WSAStartup failed"};
    }
#endif
  });
  return result;
}

[[nodiscard]] std::uint64_t unix_now() noexcept {
  return static_cast<std::uint64_t>(std::time(nullptr));
}

void set_socket_timeouts(SocketHandle fd, std::uint32_t secs) noexcept {
#if defined(_WIN32)
  DWORD timeout_ms = static_cast<DWORD>(secs * 1000U);
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                     static_cast<int>(sizeof(timeout_ms)));
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                     static_cast<int>(sizeof(timeout_ms)));
#else
  timeval tv{};
  tv.tv_sec = static_cast<time_t>(secs);
  tv.tv_usec = 0;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, static_cast<SockLen>(sizeof(tv)));
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, static_cast<SockLen>(sizeof(tv)));
#endif
}

[[nodiscard]] std::string peer_ip(SocketHandle fd) {
  sockaddr_storage addr{};
  SockLen len = static_cast<SockLen>(sizeof(addr));
  if (::getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return {};
  char host[NI_MAXHOST] = {};
  if (::getnameinfo(reinterpret_cast<sockaddr*>(&addr), len, host, sizeof(host), nullptr, 0,
                    NI_NUMERICHOST) != 0) {
    return {};
  }
  return host;
}

// Last socket error as text. Used only to explain a failed bind/listen, so that
// "port already in use" is not reported as "no usable address".
[[nodiscard]] std::string last_socket_error() {
#if defined(_WIN32)
  const int code = ::WSAGetLastError();
  switch (code) {
    case WSAEADDRINUSE: return "address already in use (WSAEADDRINUSE)";
    case WSAEACCES: return "permission denied (WSAEACCES)";
    case WSAEADDRNOTAVAIL: return "address not available (WSAEADDRNOTAVAIL)";
    default: return "Winsock error " + std::to_string(code);
  }
#else
  return std::string{::strerror(errno)};
#endif
}

[[nodiscard]] int last_socket_error_code() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

[[nodiscard]] bool was_interrupted(int err) noexcept {
#if defined(_WIN32)
  return err == WSAEINTR;
#else
  return err == EINTR;
#endif
}

// Half-close instead of an abrupt close: closing a socket with unread input
// makes the stack emit RST, which can discard the response we just wrote.
void shutdown_send(SocketHandle fd) noexcept {
#if defined(_WIN32)
  (void)::shutdown(fd, SD_SEND);
#else
  (void)::shutdown(fd, SHUT_WR);
#endif
}

// Flushes and shuts down the connection, tolerating short writes. Returns false
// on error; never loops on a socket that refuses to drain.
[[nodiscard]] bool send_all(SocketHandle fd, std::string_view data) noexcept {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const auto n = ::send(fd, data.data() + sent, static_cast<IoSize>(data.size() - sent), 0);
    if (n <= 0) {
      if (n < 0 && was_interrupted(last_socket_error_code())) continue;
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

// Reads and discards what the peer already sent, so the queued response is not
// destroyed by an abortive close: closing a socket with unread input makes the
// stack send RST, and a peer that receives RST discards the response it had
// already buffered (Windows: WSAECONNABORTED, no data).
//
// The loop runs until the peer's FIN, an error, or the time budget expires -
// *not* until "nothing is pending", because a client still inside sendall()
// looks idle for a moment and we would then close on top of its in-flight data.
// Only requests that leave unread bytes pay the budget.
void drain_input(SocketHandle fd, std::chrono::milliseconds budget, std::size_t max_bytes) {
#if defined(_WIN32)
  DWORD slice = 50;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&slice),
                     sizeof(slice));
#else
  timeval tv{};
  tv.tv_sec = 0;
  tv.tv_usec = 50 * 1000;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, static_cast<SockLen>(sizeof(tv)));
#endif
  char sink[4096];
  std::size_t drained = 0;
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (drained < max_bytes && std::chrono::steady_clock::now() < deadline) {
    const auto n = ::recv(fd, sink, static_cast<IoSize>(sizeof(sink)), 0);
    if (n > 0) {
      drained += static_cast<std::size_t>(n);
      continue;
    }
    if (n == 0) return;  // peer closed: closing now is clean
    // Would-block/timed-out: the peer is still connected and quiet; keep
    // waiting inside the budget (each iteration costs at most the 50 ms slice).
  }
}

// Bytes already queued by the peer; 0 means nothing to drain.
[[nodiscard]] std::size_t pending_input(SocketHandle fd) noexcept {
#if defined(_WIN32)
  u_long available = 0;
  if (::ioctlsocket(fd, FIONREAD, &available) != 0) return 0;
  return static_cast<std::size_t>(available);
#else
  int available = 0;
  if (::ioctl(fd, FIONREAD, &available) != 0) return 0;
  return static_cast<std::size_t>(available);
#endif
}

// Largest declared body this server is willing to discard (1 MiB). Bodies are
// never interpreted - only skipped - so this is purely a "do not lose the
// response" allowance.
constexpr std::size_t kMaxDrainedBody = 1U << 20U;

// Reads Content-Length from an already-buffered header block. The value is used
// only to decide how many bytes to throw away before closing; it never changes
// routing or any other behaviour. Returns 0 when absent or larger than
// kMaxDrainedBody (i.e. "unknown, fall back to a bounded drain").
[[nodiscard]] std::size_t declared_content_length(std::string_view header_block) noexcept {
  std::string lower{header_block};
  for (char& c : lower) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  const std::string_view needle{"\r\ncontent-length:"};
  const std::size_t at = lower.find(needle);
  if (at == std::string::npos) return 0;
  std::size_t i = at + needle.size();
  while (i < lower.size() && (lower[i] == ' ' || lower[i] == '\t')) ++i;
  std::size_t value = 0;
  std::size_t digits = 0;
  while (i < lower.size() && lower[i] >= '0' && lower[i] <= '9' && digits < 12) {
    value = value * 10 + static_cast<std::size_t>(lower[i] - '0');
    ++i;
    ++digits;
  }
  if (digits == 0) return 0;
  return value > kMaxDrainedBody ? 0 : value;
}

[[nodiscard]] const char* reason_phrase(int status) noexcept {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "Unknown";
  }
}

// Serialises a response. HEAD gets identical headers and no body, which is what
// RFC 9110 9.3.2 requires (Content-Length describes the would-be body).
[[nodiscard]] std::string build_response(int status, std::string_view content_type,
                                         std::string_view body, bool is_head) {
  const std::string length = std::to_string(body.size());
  std::string out;
  out.reserve(body.size() + length.size() + 256);
  out += "HTTP/1.1 " + std::to_string(status) + ' ';
  out += reason_phrase(status);
  out += "\r\nServer: vpnd/" VPN_VERSION;
  out += "\r\nContent-Type: ";
  out += content_type;
  out += "\r\nContent-Length: ";
  out += length;
  out += "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff";
  if (status == 405) out += "\r\nAllow: GET, HEAD";
  out += "\r\nConnection: close\r\n\r\n";
  if (!is_head) out += body;
  return out;
}

[[nodiscard]] std::string problem_body(int status, std::string_view title) {
  return std::string{"{\"type\":\"about:blank\",\"title\":\""} + std::string{title} +
         "\",\"status\":" + std::to_string(status) + "}";
}

// Error responses raised before routing (400/408/431) carry the same hardening
// headers as routed responses.
void send_problem(SocketHandle fd, int status, std::string_view title) {
  const std::string body = problem_body(status, title);
  (void)send_all(fd, build_response(status, "application/problem+json", body, false));
}

// Bounded label vocabulary. Only routes this server actually has keep their own
// series; everything else collapses into "other", so a scanner walking random
// URLs cannot create unbounded Prometheus series (or grow the sample vector,
// whose lookup is linear in the number of samples).
[[nodiscard]] std::string_view canonical_route(std::string_view path) noexcept {
  if (path == "/" || path == "/healthz" || path == "/readyz" || path == "/metrics") return path;
  return "other";
}

[[nodiscard]] std::string_view canonical_method(std::string_view method) noexcept {
  if (method == "GET" || method == "HEAD" || method == "POST" || method == "PUT" ||
      method == "DELETE" || method == "PATCH" || method == "OPTIONS") {
    return method;
  }
  return "other";
}

// RFC 9112 3.2.2: a server should accept absolute-form request targets, which is
// what a proxy or load balancer sends.
[[nodiscard]] std::string strip_absolute_form(const std::string& target) {
  const std::size_t scheme = target.find("://");
  if (scheme == std::string::npos) return target;
  const std::size_t authority_end = target.find_first_of("/?", scheme + 3);
  if (authority_end == std::string::npos) return "/";
  if (target[authority_end] == '?') return "/" + target.substr(authority_end);
  return target.substr(authority_end);
}

}  // namespace

HttpServer::HttpServer(Options options, HealthState& health, obs::Metrics& metrics)
    : options_(std::move(options)), health_(health), metrics_(metrics), listen_fd_(-1) {}

HttpServer::~HttpServer() {
  stop();
  if (listen_fd_ >= 0) {
    close_socket(static_cast<SocketHandle>(listen_fd_));
    listen_fd_ = -1;
  }
}

Status HttpServer::listen() {
  if (const Status st = ensure_net_initialized(); !st.ok()) return st;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  const bool wildcard = options_.bind.is_wildcard();
  const std::string port = std::to_string(options_.bind.port);
  const char* node = wildcard ? nullptr : options_.bind.host.c_str();

  addrinfo* results = nullptr;
  if (::getaddrinfo(node, port.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status{ErrorCode::kUnavailable,
                  "cannot resolve bind address " + options_.bind.to_string()};
  }

  Status result{ErrorCode::kUnavailable, "no usable address for " + options_.bind.to_string()};
  for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
    SocketHandle fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (socket_failed(fd)) continue;

#if defined(_WIN32)
    // SO_REUSEADDR on Windows lets *another* process bind the same address, which
    // is address hijacking. SO_EXCLUSIVEADDRUSE is the correct choice there.
    int exclusive = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
#else
    // On POSIX this only allows rebinding a port in TIME_WAIT, which is what we
    // want after a restart; it never lets a second live listener take the port.
    int reuse = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, static_cast<SockLen>(sizeof(reuse)));
#endif

    if (it->ai_family == AF_INET6) {
      // Default IPV6_V6ONLY differs per platform (1 on Windows, 0 on Linux). Pin
      // it to 0 so a "::" wildcard listener also serves IPv4-mapped clients.
      int v6only = 0;
      (void)::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                         reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }

    if (::bind(fd, it->ai_addr, static_cast<SockLen>(it->ai_addrlen)) != 0) {
      result = Status{ErrorCode::kUnavailable,
                      "cannot bind " + options_.bind.to_string() + ": " + last_socket_error()};
      close_socket(fd);
      continue;
    }
    if (::listen(fd, 128) != 0) {
      result = Status{ErrorCode::kUnavailable,
                      "cannot listen on " + options_.bind.to_string() + ": " +
                          last_socket_error()};
      close_socket(fd);
      continue;
    }

    sockaddr_storage bound{};
    SockLen bound_len = static_cast<SockLen>(sizeof(bound));
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
      if (bound.ss_family == AF_INET) {
        bound_port_ = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
      } else if (bound.ss_family == AF_INET6) {
        bound_port_ = ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
      }
    }

    listen_fd_ = static_cast<int>(fd);
    result = Status{};
    break;
  }
  ::freeaddrinfo(results);

  if (!result.ok()) return result;

  log::info("http listening", "bind",
            options_.bind.to_string() + " (port " + std::to_string(bound_port_) + ")");
  return Status{};
}

void HttpServer::stop() noexcept {
  stopping_.store(true, std::memory_order_relaxed);
  health_.shutting_down.store(true, std::memory_order_relaxed);
  // Wake a handler that is blocked in recv() on a stalled client, so shutdown
  // latency does not depend on http.request_timeout_secs.
  const auto fd = active_client_.load(std::memory_order_relaxed);
  if (fd != -1) {
#if defined(_WIN32)
    (void)::shutdown(static_cast<SocketHandle>(fd), SD_BOTH);
#else
    (void)::shutdown(static_cast<SocketHandle>(fd), SHUT_RDWR);
#endif
  }
}

Status HttpServer::serve() {
  if (listen_fd_ < 0) {
    return Status{ErrorCode::kInternal, "serve() called before listen()"};
  }
  health_.accepting_connections.store(true, std::memory_order_relaxed);

  // Fixed worker pool: the accept loop never runs application code, so a slow
  // or stalled client can only occupy its own worker.
  const std::uint32_t worker_count =
      options_.max_concurrent_connections == 0 ? 1U : options_.max_concurrent_connections;
  workers_.reserve(worker_count);
  for (std::uint32_t i = 0; i < worker_count; ++i) {
    workers_.emplace_back([this] { run_worker(); });
  }
  log::info("http worker pool started", "workers", std::to_string(worker_count));

  const auto listener = static_cast<SocketHandle>(listen_fd_);

  while (!stopping_.load(std::memory_order_relaxed)) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(listener, &read_set);
    timeval wait{};
    wait.tv_sec = 0;
    wait.tv_usec = 100000;  // 100 ms so the stop flag is honoured promptly

    const int ready = ::select(static_cast<int>(listener) + 1, &read_set, nullptr, nullptr, &wait);
    if (ready == 0) continue;
    if (ready < 0) {
#if defined(_WIN32)
      const bool interrupted = ::WSAGetLastError() == WSAEINTR;
#else
      const bool interrupted = errno == EINTR;
#endif
      if (interrupted) continue;
      if (!stopping_.load(std::memory_order_relaxed)) {
        log::error("select() failed on the control-plane listener");
      }
      break;
    }

    sockaddr_storage peer{};
    SockLen peer_len = static_cast<SockLen>(sizeof(peer));
    const SocketHandle client = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (socket_failed(client)) {
      if (stopping_.load(std::memory_order_relaxed)) break;
      // EMFILE/ENFILE leave the listener readable, so an immediate retry would
      // spin at 100% CPU. Back off briefly instead.
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      continue;
    }

    bool accepted = false;
    {
      const std::lock_guard<std::mutex> lock(queue_mutex_);
      // Bounded queue: past 4x the pool size we shed load instead of growing
      // without limit (a plain SYN flood must not become an OOM).
      if (queue_.size() < static_cast<std::size_t>(worker_count) * 4U) {
        queue_.push_back(PendingConnection{static_cast<std::intptr_t>(client)});
        active_connections_.fetch_add(1, std::memory_order_relaxed);
        accepted = true;
      }
    }
    if (!accepted) {
      static constexpr char kBusy[] =
          "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n"
          "Connection: close\r\n\r\n";
      (void)::send(client, kBusy, static_cast<IoSize>(sizeof(kBusy) - 1), 0);
      close_socket(client);
      health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
      metrics_.inc_counter("vpn_http_requests_shed_total");
      continue;
    }
    queue_cv_.notify_one();
  }

  // Stop and join the pool. Workers finish their current request first, and any
  // connection still queued is closed by its worker on the way out.
  {
    const std::lock_guard<std::mutex> lock(queue_mutex_);
    pool_stop_ = true;
  }
  queue_cv_.notify_all();
  for (auto& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  workers_.clear();

  health_.accepting_connections.store(false, std::memory_order_relaxed);
  return Status{};
}

void HttpServer::run_worker() noexcept {
  for (;;) {
    PendingConnection conn{};
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this] { return pool_stop_ || !queue_.empty(); });
      if (queue_.empty()) {
        if (pool_stop_) return;
        continue;
      }
      conn = queue_.front();
      queue_.pop_front();
    }

    const auto fd = static_cast<SocketHandle>(conn.fd);
    // Best-effort tracking for shutdown: with a pool this is the most recently
    // started request, which is enough to unblock a stuck recv() promptly.
    active_client_.store(conn.fd, std::memory_order_relaxed);
    handle_connection(conn.fd);
    active_client_.store(-1, std::memory_order_relaxed);
    close_socket(fd);
    active_connections_.fetch_sub(1, std::memory_order_relaxed);
  }
}

void HttpServer::handle_connection(std::intptr_t client_fd) {
  const auto fd = static_cast<SocketHandle>(client_fd);
  set_socket_timeouts(fd, options_.request_timeout_secs);

  std::string buffer;
  buffer.reserve(1024);
  char chunk[1024];

  // Absolute deadline for the whole header block. SO_RCVTIMEO alone does not
  // bound anything: it is reset by every byte, so a client trickling one byte
  // per second never times out and, with a single-threaded accept loop, blocks
  // every other request for as long as it likes.
  const std::uint32_t timeout_secs =
      options_.request_timeout_secs == 0 ? 1U : options_.request_timeout_secs;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_secs);

  std::size_t header_end = std::string::npos;
  std::size_t scanned = 0;
  bool timed_out = false;
  while (true) {
    // Wait for readability in short slices instead of one long blocking recv():
    // that is what lets stop() interrupt a stalled client on every platform
    // (shutdown() from another thread does not reliably wake a blocked recv on
    // Winsock), and it keeps the shutdown path independent of the socket timeout.
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    timeval wait{};
    wait.tv_sec = 0;
    wait.tv_usec = 100000;  // 100 ms
#if defined(_WIN32)
    const int ready = ::select(0, &read_set, nullptr, nullptr, &wait);
#else
    const int ready = ::select(static_cast<int>(fd) + 1, &read_set, nullptr, nullptr, &wait);
#endif
    if (ready < 0) {
      if (was_interrupted(last_socket_error_code())) continue;
      health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (ready == 0) {
      if (stopping_.load(std::memory_order_relaxed)) return;  // shutting down
      if (std::chrono::steady_clock::now() >= deadline) {
        timed_out = true;
        break;
      }
      continue;
    }

    const IoResult got = ::recv(fd, chunk, static_cast<IoSize>(sizeof(chunk)), 0);
    if (got == 0) {
      // Peer closed. Count it only when it abandoned a request in flight.
      if (!buffer.empty()) health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (got < 0) {
      const int err = last_socket_error_code();
      if (was_interrupted(err)) continue;
      if (std::chrono::steady_clock::now() >= deadline) {
        timed_out = true;
        break;
      }
      health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    buffer.append(chunk, static_cast<std::size_t>(got));
    // Rescan only the new tail, so this stays O(n) instead of O(n^2).
    header_end = buffer.find("\r\n\r\n", scanned > 3 ? scanned - 3 : 0);
    scanned = buffer.size();
    if (header_end != std::string::npos) break;
    if (buffer.size() > options_.max_header_bytes) {
      send_problem(fd, 431, "Request Header Fields Too Large");
      health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
      shutdown_send(fd);
      return;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      timed_out = true;
      break;
    }
  }

  if (timed_out) {
    send_problem(fd, 408, "Request Timeout");
    health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
    shutdown_send(fd);
    return;
  }

  // The terminator can arrive in the same read that crosses the limit, so the
  // size has to be re-checked once it is found; otherwise a 9 KiB header is
  // accepted with an 8 KiB configured limit.
  if (header_end + 4 > options_.max_header_bytes) {
    send_problem(fd, 431, "Request Header Fields Too Large");
    health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
    shutdown_send(fd);
    return;
  }

  // Request line: METHOD SP request-target SP HTTP-version
  const std::size_t line_end = buffer.find("\r\n");
  const std::string request_line = buffer.substr(0, line_end);
  const std::size_t sp1 = request_line.find(' ');
  const std::size_t sp2 = sp1 == std::string::npos ? std::string::npos : request_line.find(' ', sp1 + 1);
  const std::string version =
      sp2 == std::string::npos ? std::string{} : request_line.substr(sp2 + 1);

  // Reject HTTP/0.9 (no version), empty method/target, double SP and a
  // non-HTTP version token instead of quietly routing a nonsense path.
  if (sp1 == std::string::npos || sp2 == std::string::npos || sp1 == 0 || sp2 == sp1 + 1 ||
      version.rfind("HTTP/", 0) != 0) {
    send_problem(fd, 400, "Bad Request");
    health_.requests_rejected.fetch_add(1, std::memory_order_relaxed);
    shutdown_send(fd);
    return;
  }

  HttpRequest request;
  request.method = request_line.substr(0, sp1);
  std::string target = strip_absolute_form(request_line.substr(sp1 + 1, sp2 - sp1 - 1));
  request.client_ip = peer_ip(fd);
  const std::size_t qmark = target.find('?');
  if (qmark != std::string::npos) {
    request.query = target.substr(qmark + 1);
    target.resize(qmark);
  }
  request.path = std::move(target);

  // Capture a bounded request body for the REST layer. Larger bodies are not
  // read (the API never accepts them): the connection closes after the response.
  constexpr std::size_t kMaxRequestBody = 8192;
  const std::size_t body_offset = header_end + 4;
  const std::size_t content_length =
      declared_content_length(std::string_view{buffer}.substr(0, body_offset));
  if (content_length > 0 && content_length <= kMaxRequestBody) {
    while (buffer.size() < body_offset + content_length) {
      const IoResult got = ::recv(fd, chunk, static_cast<IoSize>(sizeof(chunk)), 0);
      if (got <= 0) break;
      buffer.append(chunk, static_cast<std::size_t>(got));
    }
    if (buffer.size() >= body_offset + content_length) {
      request.body = buffer.substr(body_offset, content_length);
    }
  }

  // Authorization header (raw value); the router parses the scheme.
  {
    const std::string header_block = buffer.substr(0, header_end);
    std::string lower = header_block;
    for (char& ch : lower) {
      if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    const std::string needle = "\r\nauthorization:";
    const std::size_t at = lower.find(needle);
    if (at != std::string::npos) {
      std::size_t start = at + needle.size();
      while (start < header_block.size() &&
             (header_block[start] == ' ' || header_block[start] == '\t')) {
        ++start;
      }
      std::size_t end = header_block.find("\r\n", start);
      if (end == std::string::npos) end = header_block.size();
      request.authorization = header_block.substr(start, end - start);
    }
  }
  const HttpResponse response = route(request);
  const bool is_head = request.method == "HEAD";

  health_.requests_total.fetch_add(1, std::memory_order_relaxed);
  // Label values come from a fixed vocabulary, never from the raw request: a
  // scanner hitting /random-<uuid> must not create a Prometheus series (and a
  // Sample entry) per request, which is both unbounded cardinality and an
  // unbounded linear scan in the registry.
  metrics_.inc_counter("vpn_http_requests_total",
                       {{"route", std::string{canonical_route(request.path)}},
                        {"method", std::string{canonical_method(request.method)}},
                        {"status", std::to_string(response.status)}});

  (void)send_all(fd, build_response(response.status, response.content_type, response.body,
                                   is_head));
  // Half-close, then discard the rest of the request body before closing.
  // Closing a socket with unread input makes the stack send RST, and a peer that
  // receives RST throws away the response it had already buffered, so the client
  // sees nothing (Windows: WSAECONNABORTED). The body is never parsed: a declared
  // Content-Length only tells us how many bytes to skip, and unknown/oversized
  // bodies fall back to a bounded drain.
  shutdown_send(fd);
  const std::size_t drain_offset = header_end + 4;
  const std::size_t already_read = buffer.size() > drain_offset ? buffer.size() - drain_offset : 0;
  const std::size_t declared =
      declared_content_length(std::string_view{buffer}.substr(0, drain_offset));
  std::size_t to_drain = 0;
  if (declared > already_read) {
    to_drain = declared - already_read;
  } else if (pending_input(fd) > 0) {
    to_drain = kMaxDrainedBody;
  }
  if (to_drain > 0) {
    drain_input(fd, std::chrono::milliseconds(250), to_drain);
  }
}

std::string HttpServer::json_escape(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (const char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20U) {
          char buf[8] = {};
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

HttpResponse HttpServer::debug_route(const HttpRequest& request) {
  const auto problem = [](int status, const char* title) {
    HttpResponse r;
    r.status = status;
    r.content_type = "application/problem+json";
    r.body = std::string{"{\"type\":\"about:blank\",\"title\":\""} + title +
             "\",\"status\":" + std::to_string(status) + ",\"code\":\"not_found\"}";
    return r;
  };
  if (request.method != "GET" && request.method != "HEAD") {
    return problem(405, "Method Not Allowed");
  }

  const std::uint64_t started = health_.started_at_unix.load(std::memory_order_relaxed);
  const std::uint64_t now = unix_now();
  const std::uint64_t uptime = now > started ? now - started : 0;

  if (request.path == "/debug/stats") {
    HttpResponse r;
    r.body = std::string{"{\"uptime_seconds\":"} + std::to_string(uptime) +
             ",\"requests_total\":" +
             std::to_string(health_.requests_total.load(std::memory_order_relaxed)) +
             ",\"requests_rejected\":" +
             std::to_string(health_.requests_rejected.load(std::memory_order_relaxed)) +
             ",\"active_connections\":" + std::to_string(active_connections()) +
             ",\"max_connections\":" + std::to_string(options_.max_concurrent_connections) +
             ",\"config_generation\":" +
             std::to_string(health_.config_generation.load(std::memory_order_relaxed)) +
             ",\"listen\":\"" + json_escape(options_.bind.to_string()) + "\"" +
             ",\"metrics_only\":" + (options_.metrics_only ? "true" : "false") + "}";
    return r;
  }
  if (request.path == "/debug/version") {
    HttpResponse r;
    r.body = std::string{"{\"service\":\""} + json_escape(options_.service_name) +
             "\",\"version\":\"" VPN_VERSION "\",\"wire\":\"1\"}";
    return r;
  }
  return problem(404, "Not Found");
}

HttpResponse HttpServer::route(const HttpRequest& request) {
  const auto problem = [](int status, const char* title, const char* code) {
    HttpResponse r;
    r.status = status;
    r.content_type = "application/problem+json";
    r.body = std::string{"{\"type\":\"about:blank\",\"title\":\""} + title +
             "\",\"status\":" + std::to_string(status) + ",\"code\":\"" + code + "\"}";
    return r;
  };

  const bool is_builtin = request.path == "/healthz" || request.path == "/readyz" ||
                          request.path == "/metrics" ||
                          (!options_.metrics_only && request.path == "/");

  if (is_builtin) {
    if (request.method != "GET" && request.method != "HEAD") {
      return problem(405, "Method Not Allowed", "method_not_allowed");
    }
    const std::uint64_t started = health_.started_at_unix.load(std::memory_order_relaxed);
    const std::uint64_t now = unix_now();
    const std::uint64_t uptime = now > started ? now - started : 0;

    if (request.path == "/healthz") {
      HttpResponse r;
      r.body = std::string{"{\"status\":\"ok\",\"service\":\""} +
               json_escape(options_.service_name) + "\",\"version\":\"" VPN_VERSION
               "\",\"uptime_seconds\":" + std::to_string(uptime) + "}";
      return r;
    }

    if (request.path == "/readyz") {
      HttpResponse r;
      const bool draining = health_.shutting_down.load(std::memory_order_relaxed);
      const bool accepting = health_.accepting_connections.load(std::memory_order_relaxed);
      if (draining) {
        r.status = 503;
        r.body = R"({"status":"draining","reason":"shutdown in progress"})";
      } else if (!accepting) {
        r.status = 503;
        r.body = R"({"status":"starting","reason":"listener not ready"})";
      } else {
        r.body = std::string{"{\"status\":\"ready\",\"version\":\"" VPN_VERSION
                             "\",\"uptime_seconds\":"} +
                 std::to_string(uptime) + ",\"config_generation\":" +
                 std::to_string(health_.config_generation.load(std::memory_order_relaxed)) +
                 ",\"checks\":{\"http\":\"ok\"}}";
      }
      return r;
    }

    if (request.path == "/metrics") {
      HttpResponse r;
      r.content_type = "text/plain; version=0.0.4; charset=utf-8";
      r.body = metrics_.render();
      return r;
    }

    HttpResponse r;
    r.body = std::string{"{\"service\":\""} + json_escape(options_.service_name) +
             "\",\"endpoints\":[\"/healthz\",\"/readyz\",\"/metrics\"";
    if (options_.dev_mode) r.body += ",\"/debug/stats\",\"/debug/version\"";
    r.body += "]}";
    return r;
  }

  // The metrics listener serves nothing else: it is meant to be scraped from a
  // private network, and must never expose the API by accident.
  if (options_.metrics_only) {
    return problem(404, "Not Found", "not_found");
  }

  if (options_.dev_mode && request.path.rfind("/debug/", 0) == 0) {
    return debug_route(request);
  }

  // REST API (mounted by main via set_router). Methods other than GET/HEAD are
  // legitimate here, which is why the 405 check above is scoped to built-ins.
  if (router_) {
    return router_(request);
  }

  return problem(404, "Not Found", "not_found");
}

}  // namespace vpn::controlplane

