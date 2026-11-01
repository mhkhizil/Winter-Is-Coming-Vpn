# vpn

**Status: server side implemented — API, store, control plane and tunnel all
build and run; interop with the official WireGuard client is the one gate not yet
executed (run `scripts/interop-test.sh`).**
`vpn-dp` is a runnable tunnel server (Noise_IK handshake, per-peer keys, TUN on
Linux, SIGHUP reload); `vpnd` serves the REST control plane (`/api/v1`) backed by a
file store, so no database is required. Not implemented: TLS termination (use a
proxy), PostgreSQL adapter, billing. See [`docs/ROADMAP.md`](docs/ROADMAP.md) and
[`docs/INTEROP.md`](docs/INTEROP.md).

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
| Server — tunnel (`vpn-dp`) | C++20 | **implemented** — Noise_IK handshake, transport session, replay window, peer table from config, TUN on Linux, `SIGHUP` reload |
| Server — wire protocol core (`vpn::wire`, `vpn::crypto`) | C++20 | **implemented** — BLAKE2s, X25519, ChaCha20-Poly1305, KDF, codec, MAC1/MAC2/cookie, replay window; RFC vectors green |
| Server — control plane (`vpnd`) | C++20 | **implemented** — REST `/api/v1`, file-backed store, worker pool, `/healthz` `/readyz` `/metrics` on separate ports, `SIGHUP`, `/debug` |
| Control-plane API (`/api/v1`) | C++20 | **implemented** — auth, devices, peers, config issuance, node catalog (see `docs/API.md` §0.1) |
| Official-client interop | — | **NOT verified** — run `scripts/interop-test.sh` on Linux |
| TLS termination | — | not implemented — terminate at a proxy |
| PostgreSQL adapter, gRPC CP→DP, billing, `vpnctl` | — | not implemented (next increments) |
| Android client | Kotlin | Folder placeholder only (`android/`) |
| iOS client | Swift | Folder placeholder only (`ios/`) |

Build status: Release, `-Werror`, clang 21 (via zig 0.16) — **0 warnings, 2/2 test
suites green** (`vpn_unit_tests` 104 assertions, `vpn_http_tests` 11), and all
sources cross-compile clean for `x86_64-linux-gnu` with `-Werror`.
Reproduce with `pwsh -File scripts/build-local.ps1 -Jobs 1`.

### What genuinely works today

* `vpn-dp` terminates a WireGuard handshake and carries encrypted transport
  packets; peers are authenticated against the `[[peer]]` list in `datad.toml`.
* `vpnd` serves `/healthz`, `/readyz`, `/metrics` (separate listener) and the whole
  `/api/v1` surface, verified end to end: login → device → key → node → peer →
  `wg-quick` config → delete → `401` without a token.
* Crypto is validated against the specifications: BLAKE2s (RFC 7693), X25519
  (RFC 7748 incl. the 1000-iteration vector and all small-order points),
  ChaCha20-Poly1305 (RFC 8439 §2.8.2 byte-exact), KDF/HMAC against Python.
* The wire codec round-trips all four message types, rejects malformed input, and
  the transport path rejects replayed, tampered and foreign packets.

### What does not work today

* Interop with the official WireGuard client is **not yet executed** — the one gate
  self-consistency cannot prove (`docs/INTEROP.md`).
* No TLS in the binary: run `vpnd` behind nginx/caddy/LB (`docs/DEPLOYMENT.md`).
* TUN forwarding is Linux-only; other platforms run handshake-only.
* No PostgreSQL adapter, no gRPC CP→DP channel, no billing, no `vpnctl`.

### Now implemented (previously listed as missing)

* **`metrics.bind` is a real listener.** `/metrics`, `/healthz` and `/readyz` are
  served on their own port and socket (`-Dmetrics_only` mode), so scrape traffic
  never shares the API socket and `:9100` can be firewalled separately.
* **The HTTP server is multi-threaded.** A fixed worker pool (`http.max_connections`,
  default 64) serves connections; the accept loop only enqueues, so a slow client
  occupies one worker instead of starving every request.
* **`SIGHUP` reloads the config** (`vpn_config_reload_total`, `config_generation`
  exposed on `/readyz`); bind/limit changes are reported as needing a restart
  rather than silently ignored.
* **`/debug/stats` and `/debug/version`** exist when `dev_mode` is on.

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
