// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Bootstrap role.
//
// The first account in an empty store used to be hardcoded to "owner", and "owner" is
// not an administrator - so a fresh deployment had nobody able to call /api/v1/admin/*
// or /api/v1/dp/config, which is every operation an operator needs. These cases pin the
// fix: the role is configurable, the default stays non-admin (a box must not come up with
// admin access by accident), and a nonsense role is refused loudly rather than stored.
#include <cstdlib>
#include <filesystem>
#include <string>

#include "test_support.hpp"
#include "vpn/api/store.hpp"

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

// A fresh store per case, so bootstrap actually runs (it only seeds an empty one).
std::string fresh_store_path(const char* name) {
  const auto dir = std::filesystem::temp_directory_path() / "vpn-bootstrap-tests" / name;
  std::error_code ignored;
  std::filesystem::remove_all(dir, ignored);
  std::filesystem::create_directories(dir, ignored);
  return (dir / "control.log").string();
}

vpn::api::StoreOptions options_for(const std::string& path) {
  vpn::api::StoreOptions options;
  options.path = path;
  return options;
}

}  // namespace

TEST(store_bootstrap, the_default_role_is_owner_not_admin) {
  set_env("VPN_BOOTSTRAP_EMAIL", "first@example.invalid");
  set_env("VPN_BOOTSTRAP_PASSWORD", "first-password");
  clear_env("VPN_BOOTSTRAP_ROLE");

  auto opened = vpn::api::Store::open(options_for(fresh_store_path("default")));
  CHECK(opened.has_value());
  if (!opened) return;

  auto principal = (*opened)->authenticate("first@example.invalid", "first-password");
  CHECK(principal.has_value());
  if (!principal) return;
  // Deliberate: a deployment must opt in to an administrator.
  CHECK_EQ(principal->role, std::string{"owner"});
}

TEST(store_bootstrap, admin_is_available_when_the_operator_asks_for_it) {
  set_env("VPN_BOOTSTRAP_EMAIL", "root@example.invalid");
  set_env("VPN_BOOTSTRAP_PASSWORD", "root-password");
  set_env("VPN_BOOTSTRAP_ROLE", "admin");

  auto opened = vpn::api::Store::open(options_for(fresh_store_path("admin")));
  CHECK(opened.has_value());
  if (!opened) return;

  auto principal = (*opened)->authenticate("root@example.invalid", "root-password");
  CHECK(principal.has_value());
  if (!principal) return;
  CHECK_EQ(principal->role, std::string{"admin"});

  // The role is what the admin endpoints key on, so prove one of them works with the
  // bootstrapped principal and fails with an owner. This is the check that would have
  // caught the original defect: the whole /admin surface was unreachable on a new box.
  auto users = (*opened)->list_users(*principal);
  CHECK(users.has_value());

  vpn::api::Principal owner;
  owner.user_id = "usr_owner";
  owner.tenant_id = "ten_default";
  owner.role = "owner";
  CHECK(!(*opened)->list_users(owner).has_value());
}

TEST(store_bootstrap, a_nonsense_role_is_refused_instead_of_stored) {
  set_env("VPN_BOOTSTRAP_EMAIL", "typo@example.invalid");
  set_env("VPN_BOOTSTRAP_PASSWORD", "typo-password");
  set_env("VPN_BOOTSTRAP_ROLE", "administrator");  // plausible, wrong

  auto opened = vpn::api::Store::open(options_for(fresh_store_path("typo")));
  // A typo silently producing a role nobody checks is exactly how a box ends up with an
  // account that can authenticate but administer nothing.
  CHECK(!opened.has_value());
  if (opened) return;
  CHECK_EQ(static_cast<int>(opened.error().code()),
           static_cast<int>(vpn::ErrorCode::kInvalidArgument));

  set_env("VPN_BOOTSTRAP_ROLE", "admin");  // leave the process clean for later cases
}
