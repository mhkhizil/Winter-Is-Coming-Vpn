// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// vpn-dp - the data plane daemon.
//
// Scope of this binary: a *static, file configured* WireGuard-compatible server.
// It terminates handshakes, authenticates peers against a list of allowed public
// keys, decrypts transport packets onto a TUN device, and encrypts packets read
// from the TUN back to the owning peer. No database, no API: that is deliberate,
// so it can run as a single static binary on an edge node.
//
// Linux is the production target (TUN + forwarding). On other platforms the TUN
// code compiles to a stub that reports "unsupported", which still lets the
// handshake and transport paths be exercised.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "vpn/common/bytes.hpp"
#include "vpn/common/endian.hpp"
#include "vpn/common/result.hpp"
#include "vpn/crypto/x25519.hpp"
#include "vpn/wire/noise.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cstdlib>
#include <netdb.h>      // addrinfo / getaddrinfo for `--config-url`
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(__linux__)
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#endif
#endif

#ifndef VPN_VERSION
#define VPN_VERSION "0.0.0"
#endif

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::Bytes;
using vpn::MutableByteSpan;

std::atomic<bool> g_stop{false};
std::atomic<bool> g_reload{false};

extern "C" void on_signal(int /*sig*/) { g_stop.store(true); }

extern "C" void on_sighup(int /*sig*/) {
  // systemctl reload vpn-datad: re-read the config file in the main loop.
  g_reload.store(true);
}

// --- key decoding -----------------------------------------------------------
// Keys are written as 64 hex characters. (WireGuard's base64 is a UI detail; the
// control plane will emit whichever the client wants.)
bool decode_key(const std::string& text, Bytes<32>& out) {
  if (text.size() != 64) return false;
  return vpn::from_hex(text, MutableByteSpan{out.data(), out.size()});
}

// --- configuration ----------------------------------------------------------
struct AllowedPrefix {
  std::uint32_t network{0};  // host byte order
  std::uint8_t bits{32};
};

struct PeerConfig {
  std::string name{};
  vpn::crypto::X25519PublicKey public_key{};
  std::vector<AllowedPrefix> allowed{};
  // 0 = never expires. Otherwise a unix timestamp: when paid access lapses the
  // handshake is refused and transport packets are dropped, so a client that
  // still has its configuration stops working the moment the subscription ends
  // (ADR-0010). The control plane is the source of truth for this value.
  std::int64_t expires_at{0};
};

struct Config {
  vpn::crypto::X25519PrivateKey private_key{};
  vpn::crypto::X25519PublicKey public_key{};
  std::string listen{"0.0.0.0:51820"};
  std::string tun{"wg0"};
  std::string address{};
  std::uint16_t mtu{1420};
  std::vector<PeerConfig> peers{};
};

// Unix seconds. Used only for access expiry checks.
std::int64_t unix_now() noexcept { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string trim(const std::string& s) {
  std::size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return {};
  std::size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::string unquote(const std::string& s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return s.substr(1, s.size() - 2);
  return s;
}

// Parses "10.66.0.2/32" into a prefix. IPv4 only; IPv6 peer routing is a TODO
// that is called out in docs/ROADMAP.md rather than silently mishandled.
bool parse_prefix(const std::string& text, AllowedPrefix& out) {
  const std::size_t slash = text.find('/');
  const std::string ip = slash == std::string::npos ? text : text.substr(0, slash);
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
  out.network = ntohl(addr.s_addr);
  if (slash == std::string::npos) {
    out.bits = 32;
    return true;
  }
  const int bits = std::atoi(text.c_str() + slash + 1);
  if (bits < 0 || bits > 32) return false;
  out.bits = static_cast<std::uint8_t>(bits);
  const std::uint32_t mask =
      bits == 0 ? 0U : (0xFFFFFFFFU << static_cast<unsigned>(32 - bits));
  out.network &= mask;
  return true;
}


vpn::Result<Config> load_config(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return vpn::make_error(vpn::ErrorCode::kNotFound, "cannot open " + path);
  }
  Config cfg;
  bool in_interface = false;
  PeerConfig current{};
  bool have_peer = false;

  char line[512];
  while (std::fgets(line, sizeof(line), f) != nullptr) {
    const std::string raw = trim(line);
    if (raw.empty() || raw[0] == '#') continue;

    if (raw == "[interface]") {
      in_interface = true;
      continue;
    }
    if (raw == "[[peer]]") {
      if (have_peer) cfg.peers.push_back(current);
      current = PeerConfig{};
      have_peer = true;
      in_interface = false;
      continue;
    }
    const std::size_t eq = raw.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = trim(raw.substr(0, eq));
    const std::string value = unquote(trim(raw.substr(eq + 1)));

    if (in_interface) {
      if (key == "private_key") {
        std::string hex = value;
        if (!decode_key(hex, cfg.private_key)) {
          std::fclose(f);
          return vpn::make_error(vpn::ErrorCode::kInvalidArgument,
                                 "private_key must be 64 hex characters");
        }
      } else if (key == "listen") {
        cfg.listen = value;
      } else if (key == "tun") {
        cfg.tun = value;
      } else if (key == "address") {
        cfg.address = value;
      } else if (key == "mtu") {
        cfg.mtu = static_cast<std::uint16_t>(std::atoi(value.c_str()));
      }
    } else if (have_peer) {
      if (key == "name") {
        current.name = value;
      } else if (key == "public_key") {
        if (!decode_key(value, current.public_key)) {
          std::fclose(f);
          return vpn::make_error(vpn::ErrorCode::kInvalidArgument,
                                 "public_key must be 64 hex characters");
        }
      } else if (key == "expires_at") {
        // Unix seconds. Absent or 0 means "never expires" (staff / trial-less).
        current.expires_at = static_cast<std::int64_t>(std::strtoll(value.c_str(), nullptr, 10));
      } else if (key == "allowed_ips") {
        // TOML array: ["10.66.0.1/32"] (or a bare comma-separated list).
        std::string list = value;
        if (!list.empty() && list.front() == '[') list.erase(0, 1);
        if (!list.empty() && list.back() == ']') list.pop_back();
        std::size_t start = 0;
        while (start <= list.size()) {
          const std::size_t comma = list.find(',', start);
          std::string item = trim(list.substr(start, comma == std::string::npos
                                                         ? std::string::npos
                                                         : comma - start));
          item = unquote(item);
          if (!item.empty()) {
            AllowedPrefix prefix{};
            if (!parse_prefix(item, prefix)) {
              std::fclose(f);
              return vpn::make_error(vpn::ErrorCode::kInvalidArgument,
                                     "bad allowed_ips entry: " + item);
            }
            current.allowed.push_back(prefix);
          }
          if (comma == std::string::npos) break;
          start = comma + 1;
        }
      }
    }
  }
  if (have_peer) cfg.peers.push_back(current);
  std::fclose(f);

  if (vpn::is_zero(vpn::as_span(cfg.private_key))) {
    return vpn::make_error(vpn::ErrorCode::kInvalidArgument, "interface.private_key is required");
  }
  if (!vpn::crypto::x25519_base(cfg.public_key, cfg.private_key)) {
    return vpn::make_error(vpn::ErrorCode::kInternal, "cannot derive the server public key");
  }
  return cfg;
}

// --- UDP socket -------------------------------------------------------------
#if defined(_WIN32)
using Socket = SOCKET;
constexpr Socket kInvalidSocket = INVALID_SOCKET;
using SendSize = int;
#else
using Socket = int;
constexpr Socket kInvalidSocket = -1;
// Winsock takes int lengths, POSIX takes size_t: one alias keeps -Wsign-conversion
// quiet on both platforms without scattering casts.
using SendSize = std::size_t;
#endif

struct UdpSocket {
  Socket fd{kInvalidSocket};

  ~UdpSocket() {
#if defined(_WIN32)
    if (fd != kInvalidSocket) ::closesocket(fd);
#else
    if (fd >= 0) ::close(fd);
#endif
  }

  bool open(const std::string& listen, std::string& error) {
    const std::size_t colon = listen.rfind(':');
    if (colon == std::string::npos) {
      error = "listen must be host:port";
      return false;
    }
    const std::string host = listen.substr(0, colon);
    const std::string port = listen.substr(colon + 1);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(std::atoi(port.c_str())));
    if (host.empty() || host == "0.0.0.0") {
      addr.sin_addr.s_addr = INADDR_ANY;
    } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
      error = "listen host is not an IPv4 address: " + host;
      return false;
    }

    fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == kInvalidSocket) {
      error = "socket() failed";
      return false;
    }
#if defined(_WIN32)
    // Exclusive use: on Windows SO_REUSEADDR would let another process steal the
    // port, which for a VPN endpoint is a hijack primitive.
    const BOOL exclusive = TRUE;
    (void)::setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
#else
    const int reuse = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      error = "bind() failed on " + listen;
      return false;
    }
    return true;
  }
};


bool prefix_contains(const AllowedPrefix& prefix, std::uint32_t address) {
  const std::uint32_t mask =
      prefix.bits == 0 ? 0U : (0xFFFFFFFFU << static_cast<unsigned>(32 - prefix.bits));
  return (address & mask) == (prefix.network & mask);
}

// --- TUN device -------------------------------------------------------------
class Tun {
 public:
  ~Tun() {
#if defined(__linux__)
    if (fd_ >= 0) ::close(fd_);
#endif
  }

  [[nodiscard]] bool available() const noexcept { return fd_ >= 0; }
  [[nodiscard]] int fd() const noexcept { return fd_; }

  bool open(const std::string& name, std::string& error) {
#if defined(__linux__)
    if (name.empty() || name == "none") {
      error = "tun disabled by configuration";
      return false;
    }
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
      error = "cannot open /dev/net/tun (needs CAP_NET_ADMIN)";
      return false;
    }
    ifreq request{};
    // Copy explicitly instead of snprintf("%s"): GCC cannot prove the name fits
    // into ifr_name (IFNAMSIZ bytes) and -Wformat-truncation is fatal here.
    if (name.size() >= sizeof(request.ifr_name)) {
      error = "tun name is longer than IFNAMSIZ-1";
      return false;
    }
    std::memcpy(request.ifr_name, name.c_str(), name.size() + 1);
    request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    if (::ioctl(fd_, TUNSETIFF, &request) < 0) {
      error = "TUNSETIFF failed";
      return false;
    }
    return true;
#else
    (void)name;
    error = "TUN is only implemented on Linux; handshakes still work";
    return false;
#endif
  }

  [[nodiscard]] long read_packet(Byte* buffer, std::size_t capacity) {
#if defined(__linux__)
    if (fd_ < 0) return -1;
    const ssize_t n = ::read(fd_, buffer, capacity);
    if (n < 0) return -1;
    return static_cast<long>(n);
#else
    (void)buffer;
    (void)capacity;
    return -1;
#endif
  }

  bool write_packet(ByteSpan packet) {
#if defined(__linux__)
    if (fd_ < 0) return false;
    const ssize_t n = ::write(fd_, packet.data(), packet.size());
    return n == static_cast<ssize_t>(packet.size());
#else
    (void)packet;
    return false;
#endif
  }

 private:
  int fd_{-1};
};

// --- runtime ----------------------------------------------------------------
struct Peer {
  PeerConfig config{};
  vpn::wire::TransportSession session{};
  sockaddr_storage endpoint{};
  int endpoint_len{0};
  bool established{false};
  std::uint64_t rx_packets{0};
  std::uint64_t tx_packets{0};
};

struct Statistics {
  std::uint64_t handshakes_ok{0};
  std::uint64_t handshakes_rejected{0};
  std::uint64_t transport_in{0};
  std::uint64_t transport_out{0};
  std::uint64_t dropped{0};
  // Packets refused because the peer's paid access lapsed (ADR-0010).
  std::uint64_t transport_dropped{0};
};

void print_usage() {
  std::printf(
      "vpn-dp %s - WireGuard-compatible data plane (static config)\n\n"
      "Usage:\n"
      "  vpn-dp --config <path>     run the tunnel\n"
      "  vpn-dp --genkey            print a fresh key pair (hex)\n"
      "  vpn-dp --help\n\n"
      "Requires CAP_NET_ADMIN and /dev/net/tun on Linux. Peers are authenticated\n"
      "against the [[peer]] list in the config file - there is no database.\n",
      VPN_VERSION);
}

int generate_key() {
  vpn::crypto::X25519KeyPair pair{};
  if (!vpn::crypto::x25519_generate(pair)) {
    std::fprintf(stderr, "error: the OS random source failed\n");
    return 3;
  }
  std::printf("private_key = %s\npublic_key  = %s\n",
              vpn::to_hex(vpn::as_span(pair.private_key)).c_str(),
              vpn::to_hex(vpn::as_span(pair.public_key)).c_str());
  return 0;
}

}  // namespace

// --- control-plane pull (ADR-0011) ------------------------------------------
//
// The control plane renders the peer table in the *same* TOML subset this file
// already parses, so `--config-url` needs no second format and no JSON parser.
// Only the [[peer]] blocks come from the control plane: the [interface] block
// (private key, listen, tun) stays local, because a node's private key must never
// travel.
//
// Only http:// is accepted. TLS is terminated by a local relay (stunnel on
// 127.0.0.1) or the control plane is reached over a private network, exactly as in
// ADR-0009: this binary has no TLS stack, and it will not grow one.
constexpr Socket kNoMediaSocket = static_cast<Socket>(-1);

void close_media_socket(Socket fd) noexcept {
#if defined(_WIN32)
  ::closesocket(fd);
#else
  ::close(fd);
#endif
}

std::string g_effective_config;

bool http_get(const std::string& url, const std::string& token, std::string& body,
              std::string& error) {
  const std::string scheme = "http://";
  if (url.rfind(scheme, 0) != 0) {
    error = "only http:// URLs are supported (terminate TLS in a local relay)";
    return false;
  }
  const std::string rest = url.substr(scheme.size());
  const std::size_t slash = rest.find('/');
  const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  const std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
  std::string host = authority;
  std::string port = "80";
  const std::size_t colon = authority.rfind(':');
  if (colon != std::string::npos) {
    host = authority.substr(0, colon);
    port = authority.substr(colon + 1);
  }
  if (host.empty()) {
    error = "bad URL: no host";
    return false;
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
#if defined(_WIN32)
  // The first pull can happen before main() reaches WSAStartup.
  static bool wsa_ready = false;
  if (!wsa_ready) {
    WSADATA data{};
    if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      error = "WSAStartup failed";
      return false;
    }
    wsa_ready = true;
  }
#endif
  addrinfo* addresses = nullptr;
  if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses) != 0) {
    error = "cannot resolve " + host;
    return false;
  }
  Socket fd = kNoMediaSocket;
  for (addrinfo* it = addresses; it != nullptr; it = it->ai_next) {
    fd = static_cast<Socket>(::socket(it->ai_family, it->ai_socktype, it->ai_protocol));
    if (fd == kNoMediaSocket) continue;
#if defined(_WIN32)
    const int addr_len = static_cast<int>(it->ai_addrlen);
#else
    const socklen_t addr_len = static_cast<socklen_t>(it->ai_addrlen);
#endif
    if (::connect(fd, it->ai_addr, addr_len) == 0) break;
    close_media_socket(fd);
    fd = kNoMediaSocket;
  }
  ::freeaddrinfo(addresses);
  if (fd == kNoMediaSocket) {
    error = "cannot connect to " + host + ":" + port;
    return false;
  }

  std::string request = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n";
  if (!token.empty()) request += "Authorization: Bearer " + token + "\r\n";
  request += "Connection: close\r\n\r\n";
  if (::send(fd, request.data(), static_cast<SendSize>(request.size()), 0) <= 0) {
    error = "send failed";
    close_media_socket(fd);
    return false;
  }
  std::string raw;
  char chunk[4096];
  for (;;) {
    const auto n = ::recv(fd, chunk, static_cast<SendSize>(sizeof(chunk)), 0);
    if (n <= 0) break;
    raw.append(chunk, static_cast<std::size_t>(n));
    if (raw.size() > (4U << 20U)) break;
  }
  close_media_socket(fd);

  const std::size_t header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    error = "malformed response";
    return false;
  }
  const std::string head = raw.substr(0, header_end);
  const std::size_t space = head.find(' ');
  const int status = space == std::string::npos ? 0 : std::atoi(head.c_str() + space + 1);
  if (status != 200) {
    error = "control plane returned HTTP " + std::to_string(status);
    return false;
  }
  body = raw.substr(header_end + 4);
  return true;
}

// Writes the local [interface] block followed by the peers from the control plane
// to `<config>.remote`, and points the reload path at that file.
bool pull_peers(const std::string& url, const std::string& token, const std::string& local_path,
                std::string& error) {
  std::string fetched;
  if (!http_get(url, token, fetched, error)) return false;

  std::string merged;
  std::FILE* local = std::fopen(local_path.c_str(), "rb");
  if (local == nullptr) {
    error = "cannot read " + local_path;
    return false;
  }
  char buffer[4096];
  std::size_t read = 0;
  while ((read = std::fread(buffer, 1, sizeof(buffer), local)) > 0) merged.append(buffer, read);
  std::fclose(local);

  // Everything from the first peer block onwards is replaced by the remote table.
  const std::size_t first_peer = merged.find("[[peer]]");
  if (first_peer != std::string::npos) merged.resize(first_peer);

  merged += "# --- peers pulled from the control plane ---\n";
  merged += fetched;
  if (merged.empty() || merged.back() != '\n') merged += "\n";

  g_effective_config = local_path + ".remote";
  std::FILE* out = std::fopen(g_effective_config.c_str(), "wb");
  if (out == nullptr) {
    error = "cannot write " + g_effective_config;
    return false;
  }
  std::fwrite(merged.data(), 1, merged.size(), out);
  std::fclose(out);
  return true;
}

int main(int argc, char** argv) {
  std::string config_path;
  std::string config_url;
  std::string control_plane_token;
  int refresh_secs = 60;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      print_usage();
      return 0;
    }
    if (arg == "--print-version") {
      std::printf("vpn-dp %s (wire v1)\n", VPN_VERSION);
      return 0;
    }
    if (arg == "--genkey") return generate_key();
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
      continue;
    }
    if (arg == "--config-url" && i + 1 < argc) {
      config_url = argv[++i];
      continue;
    }
    if (arg == "--token" && i + 1 < argc) {
      control_plane_token = argv[++i];
      continue;
    }
    if (arg == "--refresh" && i + 1 < argc) {
      refresh_secs = std::atoi(argv[++i]);
      if (refresh_secs < 0) refresh_secs = 0;
      continue;
    }
    std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
    return 2;
  }
  if (config_path.empty()) {
    std::fprintf(stderr, "error: --config <path> is required\n");
    return 2;
  }

  const char* token_from_env = std::getenv("VPN_DP_TOKEN");
  if (control_plane_token.empty() && token_from_env != nullptr) {
    control_plane_token = token_from_env;
  }

  g_effective_config = config_path;
  if (!config_url.empty()) {
    std::string pull_error;
    if (!pull_peers(config_url, control_plane_token, config_path, pull_error)) {
      std::fprintf(stderr, "error: cannot pull peers from %s: %s\n", config_url.c_str(),
                   pull_error.c_str());
      return 2;
    }
    std::printf("peers pulled from %s\n", config_url.c_str());
    std::fflush(stdout);
  }

  auto loaded = load_config(g_effective_config);
  if (!loaded) {
    std::fprintf(stderr, "error: %s\n", loaded.error().to_string().c_str());
    return 2;
  }
  const Config cfg = *loaded;

#if defined(_WIN32)
  WSADATA wsa{};
  if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    std::fprintf(stderr, "error: WSAStartup failed\n");
    return 3;
  }
#endif

  UdpSocket socket;
  std::string error;
  if (!socket.open(cfg.listen, error)) {
    std::fprintf(stderr, "error: %s\n", error.c_str());
    return 3;
  }

  Tun tun;
  if (!tun.open(cfg.tun, error)) {
    std::fprintf(stderr, "warning: %s (packets will be counted, not forwarded)\n",
                 error.c_str());
  }

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
#if defined(SIGHUP)
  // `systemctl reload vpn-datad` sends SIGHUP: re-read the config file and apply
  // peer changes without dropping established tunnels.
  std::signal(SIGHUP, on_sighup);
#endif

  std::vector<Peer> peers;
  peers.reserve(cfg.peers.size());
  for (const PeerConfig& pc : cfg.peers) {
    Peer peer;
    peer.config = pc;
    peers.push_back(peer);
  }

  std::printf("vpn-dp listening on %s | server_pub=%s | peers=%zu | tun=%s\n",
              cfg.listen.c_str(),
              vpn::to_hex(vpn::as_span(cfg.public_key)).substr(0, 16).c_str(), peers.size(),
              tun.available() ? cfg.tun.c_str() : "disabled");
  // Line-buffered output: an operator piping the log must see the banner now, not
  // when the process happens to fill a buffer.
  std::fflush(stdout);

  const vpn::crypto::X25519KeyPair server_keys{cfg.private_key, cfg.public_key};
  Statistics stats{};
  Byte datagram[65536];
  Byte inner[65536];
  auto next_refresh =
      std::chrono::steady_clock::now() + std::chrono::seconds(refresh_secs > 0 ? refresh_secs : 3600);

  while (!g_stop.load()) {
    // Periodic pull from the control plane (ADR-0011): new and expired peers are
    // picked up without anyone touching this node. A failed pull keeps the last
    // known good table: losing the control plane must never drop live tunnels.
    if (refresh_secs > 0 && !config_url.empty()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= next_refresh) {
        next_refresh = now + std::chrono::seconds(refresh_secs);
        std::string pull_error;
        if (pull_peers(config_url, control_plane_token, config_path, pull_error)) {
          g_reload.store(true);
        } else {
          std::fprintf(stderr, "warning: peer pull failed (keeping the current table): %s\n",
                       pull_error.c_str());
        }
      }
    }
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket.fd, &read_set);
    Socket highest = socket.fd;
    if (tun.available()) {
      const Socket tun_fd = static_cast<Socket>(tun.fd());
      FD_SET(tun_fd, &read_set);
      if (tun_fd > highest) highest = tun_fd;
    }
    timeval wait{};
    wait.tv_sec = 0;
    wait.tv_usec = 200000;
    const int ready = ::select(static_cast<int>(highest) + 1, &read_set, nullptr, nullptr, &wait);
    if (ready <= 0) continue;

    if (g_reload.exchange(false)) {
      auto reloaded = load_config(g_effective_config);
      if (!reloaded) {
        std::fprintf(stderr, "warning: config reload failed: %s\n",
                     reloaded.error().to_string().c_str());
      } else {
        // Apply peer changes in place: an established session survives a reload as
        // long as its public key is still allowed, so a changed allowed_ips list
        // never drops a working tunnel.
        std::vector<Peer> updated;
        updated.reserve(reloaded->peers.size());
        for (const PeerConfig& pc : reloaded->peers) {
          Peer peer;
          peer.config = pc;
          for (Peer& existing : peers) {
            if (vpn::equals(vpn::as_span(existing.config.public_key),
                            vpn::as_span(pc.public_key))) {
              peer = existing;   // keeps the session, counters and endpoint
              peer.config = pc;  // but takes the new name / allowed_ips
              break;
            }
          }
          updated.push_back(peer);
        }
        peers.swap(updated);
        std::printf("configuration reloaded: %zu peer(s)\n", peers.size());
      }
    }
    if (FD_ISSET(socket.fd, &read_set)) {
      sockaddr_storage from{};
      socklen_t from_len = sizeof(from);
      // `recvfrom` returns ssize_t on POSIX and int on Windows; `auto` keeps both
      // exact. Naming it `int` truncated the value and is a -Wshorten-64-to-32
      // error on the Linux build.
      const auto received =
          ::recvfrom(socket.fd, reinterpret_cast<char*>(datagram),
                     static_cast<SendSize>(sizeof(datagram)), 0, reinterpret_cast<sockaddr*>(&from),
                     &from_len);
      if (received > 0) {
        const ByteSpan packet{datagram, static_cast<std::size_t>(received)};
        const auto header = vpn::wire::decode(packet);

        if (header && header->type == vpn::wire::MessageType::kHandshakeInitiation) {
          auto responder = vpn::wire::NoiseIk::responder(server_keys);
          vpn::crypto::X25519PublicKey learned{};
          Peer* owner = nullptr;
          if (responder && responder->consume_initiation(packet, learned)) {
            for (Peer& peer : peers) {
              if (vpn::equals(vpn::as_span(peer.config.public_key), vpn::as_span(learned))) {
                owner = &peer;
                break;
              }
            }
          }
          if (owner != nullptr) {
            // Paid access lapses on the server side, not on the client's honour:
            // an already-installed client gets its handshake refused, so the
            // tunnel cannot outlive the subscription (ADR-0010).
            if (owner->config.expires_at != 0 && owner->config.expires_at <= unix_now()) {
              ++stats.handshakes_rejected;
              std::printf("peer %s rejected: access expired\n", owner->config.name.c_str());
              std::fflush(stdout);
              continue;
            }
            Byte response[128];
            if (responder->create_response(MutableByteSpan{response, sizeof(response)})) {
              (void)::sendto(socket.fd, reinterpret_cast<const char*>(response),
                             static_cast<SendSize>(vpn::wire::kHandshakeResponseSize), 0,
                             reinterpret_cast<const sockaddr*>(&from), from_len);
              if (owner->session.init(responder->keys()).ok()) {
                owner->endpoint = from;
                owner->endpoint_len = static_cast<int>(from_len);
                owner->established = true;
                ++stats.handshakes_ok;
                std::printf("peer %s established (local index %u)\n",
                            owner->config.name.c_str(), owner->session.local_index());
                std::fflush(stdout);
              }
            }
          } else {
            ++stats.handshakes_rejected;  // unknown public key or bad mac1
          }
          continue;
        }

        if (header && header->type == vpn::wire::MessageType::kTransportData) {
          const std::uint32_t index = header->transport.receiver_index;
          for (Peer& peer : peers) {
            if (!peer.established || peer.session.local_index() != index) continue;
            // Drop traffic from a lapsed peer even if the session was set up
            // before it expired.
            if (peer.config.expires_at != 0 && peer.config.expires_at <= unix_now()) {
              ++stats.transport_dropped;
              continue;
            }
            auto opened = peer.session.open(MutableByteSpan{datagram, packet.size()});
            if (!opened) break;
            ++stats.transport_in;
            ++peer.rx_packets;
            if (peer.rx_packets == 1) {
              // Operational signal (no payload content): proves the transport keys
              // agree end to end, which is what an interop test needs to assert.
              std::printf("peer %s: first transport packet accepted (%zu bytes inner)\n",
                          peer.config.name.c_str(), opened->size());
              std::fflush(stdout);
            }
            peer.endpoint = from;  // authenticated: safe to follow the peer
            peer.endpoint_len = static_cast<int>(from_len);
            if (!opened->empty() && tun.available()) (void)tun.write_packet(*opened);
            break;
          }
          continue;
        }
        ++stats.dropped;
      }
    }

    if (tun.available() && FD_ISSET(static_cast<Socket>(tun.fd()), &read_set)) {
      const long length = tun.read_packet(inner, sizeof(inner));
      if (length >= 20) {  // minimum IPv4 header
        const std::uint32_t destination = vpn::load_be32(inner + 16);
        for (Peer& peer : peers) {
          if (!peer.established || peer.endpoint_len == 0) continue;
          bool owned = false;
          for (const AllowedPrefix& prefix : peer.config.allowed) {
            if (prefix_contains(prefix, destination)) {
              owned = true;
              break;
            }
          }
          if (!owned) continue;
          Byte out[65536];
          const std::size_t sealed = peer.session.seal(
              MutableByteSpan{out, sizeof(out)}, ByteSpan{inner, static_cast<std::size_t>(length)});
          if (sealed > 0) {
            (void)::sendto(socket.fd, reinterpret_cast<const char*>(out),
                           static_cast<SendSize>(sealed), 0,
                           reinterpret_cast<const sockaddr*>(&peer.endpoint),
                           static_cast<socklen_t>(peer.endpoint_len));
            ++stats.transport_out;
            ++peer.tx_packets;
          }
          break;
        }
      }
    }
  }

  std::printf("\nvpn-dp stopping: handshakes=%llu rejected=%llu in=%llu out=%llu dropped=%llu\n",
              static_cast<unsigned long long>(stats.handshakes_ok),
              static_cast<unsigned long long>(stats.handshakes_rejected),
              static_cast<unsigned long long>(stats.transport_in),
              static_cast<unsigned long long>(stats.transport_out),
              static_cast<unsigned long long>(stats.dropped));
  for (const Peer& peer : peers) {
    std::printf("  peer %-16s rx=%llu tx=%llu %s\n", peer.config.name.c_str(),
                static_cast<unsigned long long>(peer.rx_packets),
                static_cast<unsigned long long>(peer.tx_packets),
                peer.established ? "established" : "never connected");
  }
  return 0;
}

