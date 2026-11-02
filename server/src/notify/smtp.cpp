// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#include "vpn/notify/smtp.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = std::uintptr_t;
using IoSize = int;
constexpr SocketHandle kNoSocket = static_cast<SocketHandle>(~0ULL);
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
using IoSize = std::size_t;
constexpr SocketHandle kNoSocket = -1;
#endif

namespace vpn::notify {
namespace {

constexpr const char* kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64(std::string_view input) {
  std::string out;
  out.reserve((input.size() + 2) / 3 * 4);
  std::size_t i = 0;
  while (i + 2 < input.size()) {
    const std::uint32_t block =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8U) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]));
    out.push_back(kBase64Alphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(block >> 12U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(block >> 6U) & 0x3FU]);
    out.push_back(kBase64Alphabet[block & 0x3FU]);
    i += 3;
  }
  if (i + 1 == input.size()) {
    const std::uint32_t block =
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U;
    out.push_back(kBase64Alphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(block >> 12U) & 0x3FU]);
    out += "==";
  } else if (i + 2 == input.size()) {
    const std::uint32_t block =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8U);
    out.push_back(kBase64Alphabet[(block >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(block >> 12U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(block >> 6U) & 0x3FU]);
    out.push_back('=');
  }
  return out;
}

void close_socket(SocketHandle fd) noexcept {
#if defined(_WIN32)
  ::closesocket(fd);
#else
  ::close(fd);
#endif
}

bool net_init() noexcept {
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
    const auto n =
        ::send(fd, data.data() + sent, static_cast<IoSize>(data.size() - sent), 0);
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

// Reads a (possibly multi-line) SMTP reply; `code` is the first three digits.
// RFC 5321 4.2.1: a line continues while the fourth character is '-'.
bool read_reply(SocketHandle fd, int& code, std::string& text) {
  text.clear();
  code = 0;
  for (int lines = 0; lines < 100; ++lines) {
    char c = 0;
    std::string line;
    for (;;) {
      const auto n = ::recv(fd, &c, static_cast<IoSize>(1), 0);
      if (n <= 0) return false;
      if (c == '\n') break;
      if (c != '\r') line.push_back(c);
      if (line.size() > 4096) return false;
    }
    if (lines == 0) {
      if (line.size() < 3) return false;
      code = std::atoi(line.substr(0, 3).c_str());
      if (code == 0) return false;
    }
    text += line;
    text.push_back('|');
    if (line.size() >= 4 && line[3] != '-') return true;
  }
  return false;
}

// Runs one command and requires the expected reply code.
Status command(SocketHandle fd, std::string_view line, int expected, const char* step) {
  if (!send_all(fd, std::string{line} + "\r\n")) {
    return Status{ErrorCode::kUnavailable, std::string{step} + ": send failed"};
  }
  int code = 0;
  std::string text;
  if (!read_reply(fd, code, text)) {
    return Status{ErrorCode::kUnavailable, std::string{step} + ": no reply"};
  }
  if (code != expected) {
    return Status{ErrorCode::kUnavailable,
                  std::string{step} + ": SMTP " + std::to_string(code) + " " + text};
  }
  return Status{};
}

}  // namespace

std::string render_message(const SmtpConfig& config, const Message& message) {
  std::string out;
  out += "From: " + config.from + "\r\n";
  out += "To: " + message.to + "\r\n";
  out += "Subject: " + message.subject + "\r\n";
  out += "MIME-Version: 1.0\r\n";
  out += "Content-Type: text/plain; charset=utf-8\r\n";
  out += "Content-Transfer-Encoding: 8bit\r\n\r\n";
  // Dot-stuffing (RFC 5321 4.5.2): a line starting with '.' gets a second one,
  // otherwise the relay would treat it as the end of DATA.
  bool line_start = true;
  for (const char c : message.body) {
    if (line_start && c == '.') out.push_back('.');
    out.push_back(c);
    line_start = c == '\n';
  }
  if (!out.empty() && out.back() != '\n') out += "\r\n";
  return out;
}

Status send(const SmtpConfig& config, const Message& message) {
  if (config.host.empty()) {
    return Status{ErrorCode::kUnavailable, "smtp is not configured"};
  }
  if (config.from.empty() || message.to.empty()) {
    return Status{ErrorCode::kInvalidArgument, "smtp needs a sender and a recipient"};
  }
  if (config.dry_run) {
    // Render the message anyway: the dry run then proves the whole formatting
    // path works without a mail server.
    const std::string rendered = render_message(config, message);
    return Status{ErrorCode::kNone,
                  "dry run: " + std::to_string(rendered.size()) + " bytes for " + message.to};
  }
  if (!net_init()) {
    return Status{ErrorCode::kInternal, "cannot initialise sockets"};
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* addresses = nullptr;
  const std::string service = std::to_string(config.port);
  if (::getaddrinfo(config.host.c_str(), service.c_str(), &hints, &addresses) != 0) {
    return Status{ErrorCode::kUnavailable, "cannot resolve " + config.host};
  }
  SocketHandle fd = kNoSocket;
  for (addrinfo* it = addresses; it != nullptr; it = it->ai_next) {
    fd = static_cast<SocketHandle>(::socket(it->ai_family, it->ai_socktype, it->ai_protocol));
    if (fd == kNoSocket) continue;
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
    return Status{ErrorCode::kUnavailable,
                  "cannot connect to " + config.host + ":" + std::to_string(config.port)};
  }

  const auto finish = [&](const Status& status) {
    (void)send_all(fd, "QUIT\r\n");
    close_socket(fd);
    return status;
  };

  int code = 0;
  std::string text;
  if (!read_reply(fd, code, text) || code != 220) {
    return finish(Status{ErrorCode::kUnavailable, "no SMTP greeting"});
  }
  Status step = command(fd, "EHLO vpnd", 250, "EHLO");
  if (!step.ok()) return finish(step);

  if (!config.username.empty()) {
    step = command(fd, "AUTH LOGIN", 334, "AUTH");
    if (!step.ok()) return finish(step);
    step = command(fd, base64(config.username), 334, "AUTH user");
    if (!step.ok()) return finish(step);
    step = command(fd, base64(config.password), 235, "AUTH password");
    if (!step.ok()) return finish(step);
  }

  step = command(fd, "MAIL FROM:<" + config.from + ">", 250, "MAIL FROM");
  if (!step.ok()) return finish(step);
  step = command(fd, "RCPT TO:<" + message.to + ">", 250, "RCPT TO");
  if (!step.ok()) return finish(step);
  step = command(fd, "DATA", 354, "DATA");
  if (!step.ok()) return finish(step);

  const std::string payload = render_message(config, message) + ".\r\n";
  if (!send_all(fd, payload)) {
    return finish(Status{ErrorCode::kUnavailable, "DATA body: send failed"});
  }
  if (!read_reply(fd, code, text) || code != 250) {
    return finish(Status{ErrorCode::kUnavailable,
                         "message rejected: SMTP " + std::to_string(code) + " " + text});
  }
  return finish(Status{});
}

}  // namespace vpn::notify
