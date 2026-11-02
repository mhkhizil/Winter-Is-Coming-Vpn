// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Minimal SMTP client, for renewal reminders only.
//
// Deliberately plain SMTP with no TLS: exactly like the control-plane API
// (ADR-0009), transport security is the job of the thing in front of us. Here
// that is a local relay (postfix/exim/msmtp/mailhog on loopback, or a provider's
// submission port behind stunnel), which speaks TLS upstream and is far better at
// certificate handling than a hand-written client would be. vpnd therefore has no
// certificate store, no SNI and no cipher configuration to get wrong.
//
// Supported: EHLO, optional AUTH LOGIN, one message per connection. No pipelining,
// no attachments - the message is plain text and always will be.
#pragma once

#include <cstdint>
#include <string>

#include "vpn/common/result.hpp"

namespace vpn::notify {

struct SmtpConfig {
  std::string host{};  // empty => reminders are disabled
  std::uint16_t port{25};
  std::string from{};  // envelope + header sender
  std::string username{};
  std::string password{};
  std::uint32_t timeout_secs{10};
  // Parses and renders the message but sends nothing: used by tests and by
  // `--dry-run`, so the whole path is exercised without a mail server.
  bool dry_run{false};
};

struct Message {
  std::string to{};
  std::string subject{};
  std::string body{};
};

// Sends one message. Never throws; on failure the Status explains which SMTP
// step failed and what the server replied (secrets are not included).
[[nodiscard]] Status send(const SmtpConfig& config, const Message& message);

// Exposed for tests: the exact bytes written after DATA (headers + body, with
// dot-stuffing applied). No trailing ".\\r\\n" terminator.
[[nodiscard]] std::string render_message(const SmtpConfig& config, const Message& message);

}  // namespace vpn::notify
