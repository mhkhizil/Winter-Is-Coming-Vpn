# Building

Status: **normative**. Two supported paths: native Linux (preferred, matches
production) and Windows-hosted (what this repo is currently developed on).

## 0. What M0 needs

**Nothing but a C++20 compiler and CMake ≥3.28.** No vcpkg, no network, no
vendored third-party code. If `cmake --preset default && cmake --build --preset
default` fails on a clean machine, that is a P0 bug in this repo.

## 1. Windows 11 + WSL2 (recommended for real work)

```powershell
wsl --install --no-distribution          # reboot when asked
wsl --update
wsl --set-default-version 2
wsl --install -d Ubuntu-24.04 --no-launch
wsl --manage Ubuntu-24.04 --move D:\wsl\Ubuntu-24.04   # keep the VHD off C:\
```

`%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=9GB
processors=8
swap=4GB
sparseVhd=true
```

Inside Ubuntu (`/etc/wsl.conf`):

```ini
[boot]
systemd=true
[interop]
appendWindowsPath=false
[automount]
options="metadata,uid=1000,gid=1000,umask=22,fmask=11"
```

Then:

```sh
sudo apt update && sudo apt install -y build-essential gcc-13 g++-13 clang-18 \
  cmake ninja-build ccache git curl pkg-config wireguard-tools nftables iproute2 \
  tcpdump gdb postgresql-client
git clone <your-remote> ~/src/vpn && cd ~/src/vpn     # NEVER build from /mnt/c
cmake --preset default && cmake --build --preset default --parallel 8
./build/default/server/vpn_unit_tests
```

Why not `/mnt/c`: 3–5× slower I/O, broken file permissions, and line-ending
surprises. Keep the clone on ext4 and open it with VS Code Remote-WSL.

## 2. Windows-native (quick checks only)

The data plane needs Linux (TUN, netlink, nftables), so Windows-native builds only
cover `vpn_core` + `vpnd`. Any of these work:

| Toolchain | Notes |
|---|---|
| MinGW-w64 GCC 13 (`g++` from winlibs/w64devkit) | claimed as the M0 verifying toolchain; **not reproduced during the production-readiness audit** (no compiler was available on the audit host), so treat `-Werror` greenness as CI-only evidence |
| LLVM/Clang 18 + MSVC STL | fine for `vpn_core` |
| MSVC 19.4x | `-DCMAKE_CXX_COMPILER=cl`; no `unistd.h` paths are used |

Manual build without CMake (fastest sanity check):

```powershell
g++ -std=c++23 -Wall -Wextra -Wpedantic -Werror -I server/include `
    server/src/common/endpoint.cpp server/src/common/log.cpp `
    server/src/crypto/blake2s.cpp server/src/crypto/ct.cpp `
    server/src/wire/message.cpp server/src/wire/replay_window.cpp `
    server/src/config/config.cpp server/src/obs/metrics.cpp `
    server/tests/unit/test_main.cpp server/tests/unit/test_blake2s.cpp `
    server/tests/unit/test_wire_message.cpp server/tests/unit/test_replay_window.cpp `
    server/tests/unit/test_config.cpp `
    -o build/vpn_unit_tests.exe
.\build\vpn_unit_tests.exe
```

## 3. CMake presets

| Preset | Compiler | Flags | Use |
|---|---|---|---|
| `default` | system | Release + `-Werror` | CI gate, local work |
| `debug` | system | Debug + ASan/UBSan | debugging memory bugs |
| `release` | system | Release + LTO | production artifacts |
| `coverage` | system | `--coverage` | gcovr report |
| `linux-gcc` | `g++-13` | as default | match production ABI |
| `linux-clang` | `clang++-18` | debug + sanitizers | fuzzing, clang-tidy |
| `windows-core` | MinGW | no data plane | Windows sanity checks |

## 4. Dependencies per milestone

| Milestone | Added dependency | Why |
|---|---|---|
| M1 | BoringSSL (pinned commit, static) | X25519, ChaCha20-Poly1305, HKDF, later ML-KEM |
| M1 | spdlog + fmt | non-allocating structured logging |
| M3 | Drogon, nlohmann/json, libpqxx, PostgreSQL 16, Redis 7 | control-plane API |
| M3 | protobuf + gRPC | control plane ↔ data plane |
| M2+ | googletest, Google Benchmark | integration + perf suites |

Managed by the vcpkg manifest with a pinned `builtin-baseline`, a binary cache,
and `tools/deps.lock` for reviewable diffs.

> **Not true yet (M0).** `vcpkg.json` exists and already declares the features
> above, but:
> * its `builtin-baseline` is the placeholder `0000…0000`, not a real commit —
>   `vcpkg install <feature>` will fail until it is pinned;
> * `tools/deps.lock` does not exist;
> * there is **no `VPN_USE_SYSTEM_DEPS` CMake option**. Earlier revisions of this
>   document told you to pass `-DVPN_USE_SYSTEM_DEPS=ON`; CMake ignores unknown
>   `-D` arguments silently, so it was a no-op. That option arrives with vcpkg.

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `std::expected` not found | nothing in this tree uses `std::expected`; `vpn::Result` is a hand-written type that is always used regardless of `VPN_USE_CXX23`. The option only selects `-std=c++20` vs `c++23`. | set `-DVPN_USE_CXX23=OFF` to build as C++20 |
| `Ninja not found` | preset requires Ninja | `apt install ninja-build` or `-G "Unix Makefiles"` |
| `TUNSETIFF: Operation not permitted` (M2) | missing `CAP_NET_ADMIN` | container needs `--cap-add NET_ADMIN --device /dev/net/tun` |
| `LLVM ERROR: out of memory` / `Allocation failed` during the build | zig's clang needs ~1-2 GB per translation unit; `--parallel` (all cores) exhausts RAM on a 16 GB machine | `pwsh -File scripts/build-local.ps1 -Jobs 1` (or 2) |
| Tests hang | firewall prompt on Windows | allow the test binary, or run in WSL |
