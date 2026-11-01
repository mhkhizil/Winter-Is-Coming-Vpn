// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Configuration and endpoint gates. A config typo must fail the deploy, not
// silently fall back to a default that opens a port on the wrong interface.
#include <cstdlib>
#include <string>

#include "test_support.hpp"
#include "vpn/common/endpoint.hpp"
#include "vpn/config/config.hpp"

namespace {

void set_env(const char* name, const char* value) {
#if defined(_WIN32)
  (void)_putenv_s(name, value);
#else
  (void)::setenv(name, value, 1);
#endif
}

void clear_env(const char* name) {
#if defined(_WIN32)
  (void)_putenv_s(name, "");
#else
  (void)::unsetenv(name);
#endif
}

}  // namespace

TEST(endpoint, parses_ipv4_hostname_and_wildcard) {
  auto ipv4 = vpn::parse_endpoint("127.0.0.1:8080");
  CHECK(ipv4.has_value());
  if (ipv4) {
    CHECK_EQ(ipv4->host, std::string{"127.0.0.1"});
    CHECK_EQ(ipv4->port, static_cast<std::uint16_t>(8080));
    CHECK_EQ(ipv4->to_string(), std::string{"127.0.0.1:8080"});
  }

  auto host = vpn::parse_endpoint("localhost:443");
  CHECK(host.has_value());
  if (host) CHECK_EQ(host->port, static_cast<std::uint16_t>(443));

  auto wildcard = vpn::parse_endpoint(":9090");
  CHECK(wildcard.has_value());
  if (wildcard) {
    CHECK(wildcard->is_wildcard());
    CHECK_EQ(wildcard->port, static_cast<std::uint16_t>(9090));
  }
}

TEST(endpoint, parses_bracketed_ipv6) {
  auto v6 = vpn::parse_endpoint("[::1]:51820");
  CHECK(v6.has_value());
  if (v6) {
    CHECK_EQ(v6->host, std::string{"::1"});
    CHECK_EQ(v6->port, static_cast<std::uint16_t>(51820));
    CHECK_EQ(v6->to_string(), std::string{"[::1]:51820"});
  }
}

TEST(endpoint, rejects_invalid_endpoints) {
  CHECK(!vpn::parse_endpoint(""));
  CHECK(!vpn::parse_endpoint("127.0.0.1"));
  CHECK(!vpn::parse_endpoint("127.0.0.1:0"));
  CHECK(!vpn::parse_endpoint("127.0.0.1:70000"));
  CHECK(!vpn::parse_endpoint("127.0.0.1:http"));
  CHECK(!vpn::parse_endpoint("[::1:8080"));
  CHECK(!vpn::parse_endpoint("::1:8080"));   // must be bracketed
  CHECK(!vpn::parse_endpoint("bad host:80"));  // space is not a host character
}

TEST(config, parses_a_full_document) {
  const std::string text = R"(
# vpnd development config
environment = "development"
dev_mode = true

[log]
level = "debug"          # inline comment
format = "json"

[http]
bind = "127.0.0.1:8080"
request_timeout_secs = 15
max_header_bytes = 8192
)";
  auto cfg = vpn::config::parse(text);
  CHECK(cfg.has_value());
  if (!cfg) return;
  CHECK_EQ(cfg->environment, std::string{"development"});
  CHECK(cfg->dev_mode);
  CHECK_EQ(cfg->log.level, std::string{"debug"});
  CHECK_EQ(cfg->http.bind.port, static_cast<std::uint16_t>(8080));
  CHECK_EQ(cfg->http.request_timeout_secs, 15U);
  CHECK(vpn::config::validate(*cfg).ok());
}

TEST(config, defaults_are_valid_for_development) {
  auto cfg = vpn::config::parse("");
  CHECK(cfg.has_value());
  if (!cfg) return;
  CHECK_EQ(cfg->environment, std::string{"development"});
  CHECK(cfg->http.bind.port != 0);
  CHECK(vpn::config::validate(*cfg).ok());
}

TEST(config, unknown_keys_and_bad_values_are_errors) {
  CHECK(!vpn::config::parse("[http]\nbind = \"127.0.0.1\"\n"));
  CHECK(!vpn::config::parse("nonexistent_key = 1\n"));
  CHECK(!vpn::config::parse("dev_mode = maybe\n"));
  CHECK(!vpn::config::parse("[http]\nrequest_timeout_secs = -1\n"));
  CHECK(!vpn::config::parse("this line has no equals sign\n"));
}

TEST(config, production_requires_tls_and_no_dev_mode) {
  auto no_tls = vpn::config::parse("environment = \"production\"\n");
  CHECK(no_tls.has_value());
  if (no_tls) CHECK(!vpn::config::validate(*no_tls).ok());

  auto with_dev = vpn::config::parse(
      "environment = \"production\"\ndev_mode = true\n"
      "[tls]\ncert_file = \"a.pem\"\nkey_file = \"b.pem\"\n");
  CHECK(with_dev.has_value());
  if (with_dev) {
    const auto status = vpn::config::validate(*with_dev);
    CHECK(!status.ok());
    CHECK(status.code() == vpn::ErrorCode::kInvalidArgument);
  }

  auto ok_prod = vpn::config::parse(
      "environment = \"production\"\n[tls]\ncert_file = \"a.pem\"\nkey_file = \"b.pem\"\n");
  CHECK(ok_prod.has_value());
  if (ok_prod) CHECK(vpn::config::validate(*ok_prod).ok());
}

TEST(config, tls_files_must_be_provided_together) {
  auto cfg = vpn::config::parse("[tls]\ncert_file = \"a.pem\"\n");
  CHECK(cfg.has_value());
  if (cfg) CHECK(!vpn::config::validate(*cfg).ok());
}

TEST(config, environment_overrides_take_precedence) {
  auto cfg = vpn::config::parse("[http]\nbind = \"127.0.0.1:8080\"\n");
  CHECK(cfg.has_value());
  if (!cfg) return;

  set_env("VPN_HTTP_BIND", "0.0.0.0:9999");
  set_env("VPN_LOG_LEVEL", "warn");
  set_env("VPN_ENV", "staging");
  CHECK(vpn::config::apply_environment(*cfg).ok());
  CHECK_EQ(cfg->http.bind.port, static_cast<std::uint16_t>(9999));
  CHECK_EQ(cfg->log.level, std::string{"warn"});
  CHECK_EQ(cfg->environment, std::string{"staging"});

  set_env("VPN_DEV_MODE", "not-a-bool");
  CHECK(!vpn::config::apply_environment(*cfg).ok());

  clear_env("VPN_HTTP_BIND");
  clear_env("VPN_LOG_LEVEL");
  clear_env("VPN_ENV");
  clear_env("VPN_DEV_MODE");
}

TEST(config, printing_redacts_secrets) {
  auto cfg = vpn::config::parse(
      "admin_token = \"super-secret\"\n[tls]\ncert_file = \"a.pem\"\nkey_file = \"b.pem\"\n");
  CHECK(cfg.has_value());
  if (!cfg) return;
  const std::string rendered = vpn::config::to_string(*cfg);
  CHECK(rendered.find("super-secret") == std::string::npos);
  CHECK(rendered.find("<redacted>") != std::string::npos);
  CHECK(rendered.find("a.pem") != std::string::npos);
}
