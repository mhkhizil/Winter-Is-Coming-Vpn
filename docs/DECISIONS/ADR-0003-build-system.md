# ADR-0003 — CMake + Ninja + vcpkg manifest, C++20 baseline (C++23 where available)

* Status: accepted
* Date: 2026-11-01
* Deciders: server team

## Context
We need a build that (a) works on Windows for development, (b) produces a
production Linux binary with predictable dependencies, (c) gates CI in minutes,
and (d) is reviewable by humans.

## Decision
* **CMake ≥3.28** with `CMakePresets.json` (Ninja generator, `-Werror` presets).
* **Dependency-free M0** (`vpn_core` + `vpnd` build with no external packages).
* From M1: **vcpkg manifest mode** with a pinned `builtin-baseline`, a binary
  cache, and `tools/deps.lock` for reviewable version diffs.
  `-DVPN_USE_SYSTEM_DEPS=ON` for deb/rpm builds.
* **C++20 baseline**, compiled in C++23 mode when the toolchain supports
  `std::expected`. `vpn::Result<T>` hides which one is in use
  (`-DVPN_USE_CXX23=OFF` selects the built-in fallback), so we can drop back to
  C++20 without touching call sites.
* Unity builds **off**, IPO/LTO only in the `release` preset.

## Consequences
* Two things can drift: the vcpkg baseline and the system package versions. CI
  builds both ways; `tools/repro-compare.sh` compares artifact hashes.
* C++20 fallback means `vpn::Result` cannot use everything `std::expected` offers;
  the subset we use (`has_value`, `value`, `error`, `operator*`) is common.
* We accept a ~25 min cold vcpkg build on a new machine, mitigated by the binary
  cache (~4 min warm) and by M0 needing nothing at all.

## Alternatives rejected
* **FetchContent everywhere** — 30–40 min cold builds, no binary cache, and the
  dependency graph is invisible to review.
* **Conan** — recipe lag on BoringSSL/gRPC; we would be maintaining recipes.
* **Bazel** — excellent, but a large conceptual cost for a 5-person team and poor
  Windows ergonomics for MSVC + MinGW mixtures.
* **Meson** — fine technically, but weaker IDE/CI ecosystem for C++ on Windows.
