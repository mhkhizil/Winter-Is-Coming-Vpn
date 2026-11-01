# Roadmap

Status: **M0 + M1 + M3-core implemented** (API → store → peers → client config →
tunnel). The one unproven link is interop with the *official* WireGuard client: run
`sudo ./scripts/interop-test.sh` on a Linux box (see [INTEROP.md](INTEROP.md)).

## Implementation status (what exists today)

| Component | State | Evidence |
|---|---|---|
| `vpn::crypto` (BLAKE2s, X25519, ChaCha20-Poly1305, KDF, CSPRNG) | **done** | RFC 7693 / 7748 / 8439 vectors + Python cross-checks |
| `vpn::wire` (codec, mac1/mac2/cookie, replay window, Noise_IK, transport) | **done** | in-process handshake + 100-packet transport + replay tests |
| `vpn-dp` (UDP, peers, TUN, SIGHUP reload) | **done** | builds, binds, handshake path tested; TUN is Linux-only |
| `vpnd` (health/ready/metrics, worker pool, SIGHUP, `/debug`) | **done** | live smoke test |
| REST `/api/v1` + file-backed store | **done** | live end-to-end run (§ commit `f605cf3`) |
| Official-client interop | **NOT verified** | run `scripts/interop-test.sh` |
| TLS termination | **not implemented** | terminate at a proxy |
| PostgreSQL adapter, gRPC CP→DP, billing | not implemented | next increments |

## Original milestone plan

| M | Weeks | Scope | Blocking acceptance gate | State |
|---|---|---|---|---|
| **M0** | 1–2 | Repo, CMake/Ninja presets, CI, ADRs, `vpn_core` (BLAKE2s, wire codec, MAC/cookie, replay window, config, metrics), `vpnd` with `/healthz` `/readyz` `/metrics` | Clean build with `-Werror`; unit suite green; `vpnd` serves and shuts down cleanly | **code present — gate NOT met** (see M0 status below) |
| **M1** | 3–5 | BoringSSL bindings (X25519, ChaCha20-Poly1305, HKDF), Noise_IK handshake, keypair state machine, cookie/anti-DoS, handshake rate limiter | **200/200 interop** vs real `wireguard-go`; ≥4 000 responder handshakes/s/core; 24 h fuzz clean; wire v1.0 frozen | not started |
| **M2** | 6–9 | `vpn-dp`: TUN device, per-worker UDP sockets with `SO_REUSEPORT` + BPF steering, session table, replay, per-peer token bucket, nftables/VRF programming | ≥2.0 Gbps/core, 500 peers, <0.1 % legitimate drops under spoof flood, 0 heap allocations per packet | not started |
| **M3** | 10–14 | PostgreSQL schema + IPAM, REST v1 (OpenAPI), auth (Argon2id, JWT, refresh rotation), tenancy/RLS, gRPC config push + Ack, `vpnctl` | Config visible in DP ≤2 s; Ack p99 ≤250 ms; **no client private key in DB or logs** (grep gate) | not started |
| **M4** | 15–18 | Many tenants per node, default-deny peer ACL, hot reload without session loss, kernel-WireGuard backend for fallback | 0 cross-tenant packets in 10⁶; 0 session drops on config reload; if <1.5 Gbps/core → pivot to kernel-primary | not started |
| **M5** | 19–22 | HA control plane, PG HA + PITR, leader-elected IPAM, Helm chart, Prometheus/OTLP, SBOM + signed artifacts, deb/rpm | Killing the CP leader ⇒ 0 tunnel drops; 72 h soak with <1 MB/h RSS slope | not started |
| **M6** | 23–26 | 10⁹-exec fuzz campaign, external pentest, io_uring + GSO/GRO, reproducible builds, published client contract, v1.0 | No open critical/high findings; SLOs met on recorded hardware; byte-identical rebuilds | not started |

## M0 status: gate PASSED (build + tests), with named non-goals

**Verified on 2026-11-01** on Windows 11 with zig 0.16's bundled clang 21:

```
zig      : %USERPROFILE%\.local\toolchains\zig016\zig\ziglang\zig.exe (0.16.0)
cmake    : out\tools\cmake\cmake-3.30.5-windows-x86_64\bin\cmake.exe
-- vpn 0.1.0 | C++23 | Release | tests=ON | controlplane=ON | dataplane=OFF
[13/13] Linking CXX executable server\tests\vpn_unit_tests.exe
100% tests passed, 0 tests failed out of 2
OK - Release build + tests green
```

`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-align
-Wunused -Woverloaded-virtual -Wdouble-promotion -Wformat=2
-Wimplicit-fallthrough -Wnull-dereference -Werror` → **0 warnings from project
sources**.

### Defects found by the verification team, and their disposition

| # | Defect | Disposition |
|---|---|---|
| 1 | `compute_cookie()` hashed `ip_len + 2` bytes but stored the port at offset 16, so an IPv4 cookie ignored the source port | **fixed** (`server/src/wire/message.cpp`); pinned by hashlib-derived KATs |
| 2 | Replay window rejected a counter exactly 8128 behind the head (`>=` instead of `>`) | **fixed**; `replay.boundary_at_exactly_the_window_size` is always on |
| 3 | `ct::select()` returned `cond ? b : a` against its documented contract | **fixed**; three unconditional contract tests |
| 4 | "KNOWN-BUG" tests were compiled out behind a define no build set (and one block would not have compiled) | **removed**; the assertions are now unconditional |
| 5 | `Blake2s` constructor did not bound the key length before `memcpy` into a 64-byte buffer | **fixed** (clamped to 32) |
| 6 | `kRejectAfterMessages` was 1 below the reference value | **fixed** |
| 7 | `encode(TransportData)` returned a length that included 16 unwritten tag bytes | **fixed** (returns bytes written; tag region zeroed, documented) |
| 8 | `vpn_http_requests_total` used the raw request path as a label → unbounded series | **fixed** (`canonical_route`/`canonical_method`, 4 routes + `other`) |
| 9 | `SO_REUSEADDR` on Windows allowed local port hijack | **fixed** (`SO_EXCLUSIVEADDRUSE`) |
| 10 | SIGTERM took up to ~4.7 s because `stop()` only set a flag | **fixed** (15 ms measured) |
| 11 | Header-size limit could be bypassed when the terminator arrived in the same read | **fixed** |
| 12 | `endpoint.cpp` and `config.cpp` used `make_error` without including `result_helpers.hpp` | **fixed** |
| 13 | CMake emitted a literal `$(VPN_CLANG_TIDY)` and a malformed `-g3>` argument | **fixed** |

### Still open, by design (not M0 scope)

| Gap | Why it is acceptable now | Unblock |
|---|---|---|
| `metrics.bind` parsed but not bound | one listener keeps M0 auditable; it logs a warning | M3 (Drogon) |
| single-threaded accept loop | loopback / reverse-proxy deployment only | M3 |
| no TLS, no auth on `vpnd` | no tenant data is served yet | M3 |
| no tunnel / handshake | that is M1 | M1 |
| no ASan/MSan run, no fuzzing | Windows host, no sanitizer runtime | CI (ubuntu-24.04) |

```sh
# Reproduce the M0 gate:
pwsh -File scripts/build-local.ps1 -Jobs 1     # Windows, no MSVC needed
# or, on Linux:
cmake --preset default && cmake --build --preset default --parallel
ctest --preset default --output-on-failure     # expected: 100% tests passed
```

## Deliberately not built yet (and why)

| Not built | Why | Unblock condition |
|---|---|---|
| Android app | folder placeholder only (scope decision) | M3 API frozen + client contract published |
| iOS app | folder placeholder only (scope decision) | same |
| Obfuscation / censorship-resistance shim | changes the traffic profile, needs its own threat review | product decision + ADR |
| Post-quantum PSK | needs an audited ML-KEM implementation and client support | BoringSSL ML-KEM stable + client parity |
| Per-app split tunnelling (iOS) | Apple has no per-app exclusion API for `NEPacketTunnelProvider` | n/a — documented limitation |
| Windows/macOS clients | out of scope for v1 | product decision |

## First three demos

1. **M0 (current)**
   ```sh
   pwsh -File scripts/build-local.ps1 -Jobs 1     # Windows, zig toolchain
   ./out/build-release/server/tests/vpn_unit_tests.exe    # 66 tests, 0 failures
   ./out/build-release/server/vpnd.exe --bind 127.0.0.1:8080 &
   curl -s localhost:8080/readyz ; curl -s localhost:8080/metrics | head
   ```
2. **M1**: stock `wg` client in a container performs a handshake against `vpn-dp`,
   pings the node, and `curl ifconfig.me` shows the node's egress IP.
3. **M2/M3**: `POST /api/v1/devices` → `POST /api/v1/peers` → download `.conf` →
   connect → read byte counters → `DELETE` → peer disappears from the node.
