# vpn

**Status: pre-alpha (milestone M0). Nothing in this repository terminates a tunnel yet.**
It is not production-ready, it has never carried customer traffic, and it has no
interoperability result against any WireGuard® implementation. See
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the gates that must pass first.

The intended product is a multi-tenant VPN backend in modern C++: a userspace
server that will terminate **WireGuard®-compatible** tunnels (so we keep control
over cookies, roaming, per-peer quota and multi-tenant policy) and expose a
versioned REST/gRPC control plane for enrollment, peer lifecycle, subscriptions
and telemetry.

> Per [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §7, compatibility may only be claimed
> once the M1 interop gate passes. Until then the correct phrasing everywhere is
> **"WireGuard®-compatible — target, not yet verified"**.

| Layer | Language | Status |
|---|---|---|
| Server — control plane (`vpnd`) | C++20 | **M0 built and tested** — serves `/healthz`, `/readyz`, `/metrics` (health/L2 only; no API) |
| Server — wire protocol core (`vpn::wire`, `vpn::crypto`) | C++20 | **M0 built and tested** — BLAKE2s (RFC 7693 vectors), message codec, MAC1/MAC2/cookie derivation, replay window; 0 known defects |
| Server — data plane (`vpn-dp`) | C++20 | M2 — designed, **not implemented** (no source files exist) |
| Control-plane API (`/api/v1`) | — | M3 — spec only (`docs/api/openapi.yaml`), **not implemented** |
| `vpnctl` operator CLI | — | M3 — interface only (`server/cli/README.md`), **not implemented** |
| Android client | Kotlin | Folder placeholder only (`android/`) |
| iOS client | Swift | Folder placeholder only (`ios/`) |

Build status: Release, `-Werror`, clang 21 (via zig 0.16) — **0 warnings, 2/2 test
suites green** (`vpn_unit_tests`, `vpn_http_tests`). Reproduce with
`pwsh -File scripts/build-local.ps1 -Jobs 1`.

### What genuinely works today

* `vpnd` starts, serves `/healthz`, `/readyz`, `/metrics` and `/` on **one**
  HTTP listener, handles SIGINT/SIGTERM (≤15 ms measured) and exits 0.
* `vpn_core` builds as a dependency-free static library; its unit suite runs
  offline and is green.
* BLAKE2s-256 matches RFC 7693 Appendix B vectors (keyed, streaming, 560-case
  differential test against Python's `hashlib`), and every digest literal in the
  tests was re-derived independently.
* The wire codec round-trips all four message types, rejects malformed input
  (wrong size, unknown type, non-16-multiple payload, exhausted counter), and
  derives MAC1/MAC2/cookies to the documented byte ranges.

### What does not work today

* No tunnel, no handshake, no X25519, no AEAD, no TLS — all arrive at M1.
* `metrics.bind` / `--metrics-bind` is **parsed and ignored** (it now logs a
  warning): metrics are served on `http.bind`, not on a second port. Do not point
  scrape configs at `:9100`.
* No config reload (there is no SIGHUP handler), no `/debug` endpoints, no
  authentication: `admin_token` is parsed, redacted and length-validated, but no
  route consumes it yet.
* The HTTP listener is single-threaded: one slow client delays health responses up
  to `http.request_timeout_secs`. It is a loopback/reverse-proxy deployment, not a
  public-internet posture (`docs/ARCHITECTURE.md` §7).
* No database, no Redis, no REST API. `docs/API.md` and `docs/DATA_MODEL.md`
  describe M3 targets.

## Layout

```
docs/      Architecture, protocol, threat model, data model, API, runbooks, ADRs  <-- start here
server/    C++20 server: wire core, control plane, migrations (data plane is M2/empty)
android/   Kotlin client (placeholder)
ios/       Swift client (placeholder)
deploy/    compose, Dockerfiles, systemd units (Helm/Terraform/Ansible are empty placeholders)
scripts/   Developer bootstrap, seed, docs lint (demo/ is empty)
```

> `deploy/helm`, `deploy/terraform`, `deploy/ansible`, `deploy/secrets` and the
> `android/`, `ios/` trees contain nothing but `.gitkeep`/README placeholders.

## Read first

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — process model and component boundaries
2. [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire protocol we target
3. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what we defend against, and what we do not
4. [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) and [`docs/api/openapi.yaml`](docs/api/openapi.yaml)
5. [`docs/DECISIONS/`](docs/DECISIONS/) — every locked architectural decision, with rejected options
6. [`docs/BUILDING.md`](docs/BUILDING.md) — toolchain bootstrap (WSL2 + CMake + Ninja)
7. [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestone gates and the current M0 state

## Quick start (after bootstrapping a toolchain)

Requires CMake ≥3.28, Ninja and a C++20 compiler. No vcpkg, no network access at
build time, no vendored code. Presets put binaries under `build/<preset>/`.

```sh
make configure      # cmake --preset default
make build          # builds build/default/server/vpnd + vpn_unit_tests
make test           # ctest --preset default  (currently RED: see "known defects")
./build/default/server/vpnd --config deploy/compose/vpnd.dev.toml
curl -s localhost:8080/readyz    # {"status":"ready",...}
curl -s localhost:8080/metrics | head
```

> Presets put binaries under `build/<preset>/`. Earlier revisions of this file
> omitted the `<preset>` segment and gave a path that does not exist.

Health, readiness and metrics all share the `http.bind` listener (default
`127.0.0.1:8080`). The `[metrics] bind` key and `--metrics-bind` flag are
accepted but have no effect in M0.

`make dev` (docker compose) needs Docker; `make demo-m1` is currently broken
because `scripts/demo/m1.sh` does not exist — see the audit findings.

The M0 build has **no third-party dependencies at all** — `vcpkg.json` declares
`"dependencies": []` and every feature is M1+. Crypto that requires a vetted
implementation (X25519, ChaCha20-Poly1305, TLS) is bound at M1
behind the interfaces in `server/include/vpn/crypto/`; see
`docs/DECISIONS/ADR-0005-crypto-library.md`.

## Security

Do not open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

> WireGuard® is a registered trademark of Jason A. Donenfeld. This project is an independent
> implementation that **targets** wire compatibility and is not endorsed by or affiliated with the
> WireGuard project. Compatibility has **not** been verified against any reference implementation;
> the M1 gate in `docs/PROTOCOL.md` §7 is the precondition for that claim.
