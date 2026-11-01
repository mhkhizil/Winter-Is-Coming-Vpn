# Architecture

Status: **normative**. Owner: server team. Related: ADR-0001, ADR-0003, ADR-0004.

## 1. Why the server is split into three processes

| Process | Capabilities | Network | Talks to | Restart impact |
|---|---|---|---|---|
| `vpnd` (control plane) | **none** | M0: TCP `8080` only. M3 target: 8443/9443 (9100 is **never** bound — metrics share the HTTP port) | PostgreSQL, Redis, Stripe, clients — **none of these in M0** | API 503s; **tunnels unaffected** |
| `vpn-dp` (data plane) | `NET_ADMIN`, `NET_RAW` (dropped after setup) | UDP 51820 | `vpnd` over mTLS gRPC | tunnels drop — so it is drained, never killed |
| `vpnctl` (CLI) | none | talks to `vpnd` | operator | none |

The split exists for one reason each:

* **Privilege separation.** The process that parses untrusted JSON from the
  internet must never hold `CAP_NET_ADMIN`, and the process that parses
  untrusted UDP must never hold a database credential.
* **Blast radius.** A control-plane CVE must not be able to read client keys —
  it never has them (ADR-0008).
* **Upgrade independence.** We ship API changes weekly and data-plane changes
  monthly; independent binaries mean independent release cadences.

Rejected: a single monolith (fails all three), and microservices-per-tenant
(10× operational surface for a 5-engineer team).

## 2. Module boundaries in `server/`

```
vpn_core (static lib, dependency-free)
├── common/   result, bytes, endian, endpoint, log
├── crypto/   blake2s, ct  (+ BoringSSL wrappers from M1: aead, x25519, kdf)
├── wire/     constants, message codec, mac1/mac2, replay window, (M1) noise_ik
├── config/   typed config, env overrides, validation
└── obs/      metrics registry
vpnd    → links vpn_core, owns sockets/signals/threads
vpn-dp  → links vpn_core + dataplane/, owns TUN/UDP/netlink  (M2)
```

Rules enforced in review:
1. `vpn_core` may not open a socket, spawn a thread, read the clock indirectly,
   or touch a global. It is trivially unit-testable and fuzzable.
2. `vpn-dp` must not link `vpn_core`'s config/database code; it receives config
   as a protobuf snapshot over gRPC.
3. `vpnd` must never include a header from `dataplane/`.

## 3. Control plane ↔ data plane

```
vpnd ──(1) Watch stream: DesiredState{generation, sha256, peers[], policy}──▶ vpn-dp
     ◀─(2) Ack{generation, applied_at}─────────────────────────────────────
     ◀─(3) Report{counters, session_count} every 15 s──────────────────────
```

* Transport: gRPC over **mTLS**, agent-initiated (works behind NAT), 24 h SVID
  rotated automatically, URI SAN `spiffe://vpn.internal/node/{server_id}`.
* Reconciliation: **level-triggered**. The agent applies the whole snapshot,
  writes `state.json`, fsyncs, then acks. A failed apply does not advance
  `generation`; the server marks the node `degraded` after 3 failures.
* Rollback is a *new higher* generation carrying the old content. The agent
  rejects any generation `<=` what it already applied, which makes replay of an
  old snapshot impossible.
* Split brain: `server_agents(lease_id, lease_expires_at)`; a 30 s lease with
  10 s renewal. A second agent with the same node id triggers `Shutdown` on the
  older stream.
* If `vpnd` is unreachable the data plane **fails static**: existing peers keep
  working, no new peers are created, and it keeps serving for 7 days before
  refusing to start.

## 4. Runtime topology of `vpnd` (M0 → M3)

```
        ┌──────────── vpnd ────────────┐
:8443 ──│ HTTP (M0: hand-rolled)       │
        │  M3: Drogon + OpenAPI router │──▶ services/ ──▶ repositories/ ──▶ PostgreSQL
:9443 ──│ gRPC (M3: node agents)       │                     │
:9100 ──│ /metrics /healthz /readyz    │                     └──▶ Redis (cache, ratelimit)
        └──────────────────────────────┘
```

> **M0 note:** only the middle listener exists, it is the *single* `http.bind`
> listener (default `127.0.0.1:8080`), and it serves `/metrics`, `/healthz` and
> `/readyz`. Neither `:8443`, `:9443` nor `:9100` is bound by M0 code, and the
> right-hand dependencies (PostgreSQL, Redis) are not contacted at all.

Layer rule: **controller → service → repository**, one direction only.
Controllers validate and translate; services own transactions and business
rules; repositories own SQL. No SQL outside `repositories/`.

## 5. Threading model

* `vpnd` M0: one accept loop + one maintenance thread (uptime gauge). Deliberate:
  two threads are trivially auditable.
* `vpnd` M3: Drogon's epoll loop pool (1 loop per core), with **all blocking DB
  calls offloaded** to a worker pool; the epoll loop must never block.
* `vpn-dp` M2: N=cores pinned workers, `SCHED_FIFO 10`, `mlockall`, per-worker
  session tables, `SO_REUSEPORT` + BPF steering by `receiver_index`, and a
  2-thread crypto pool for handshakes so X25519 never stalls a worker.

## 6. Failure philosophy

| Failure | Behaviour |
|---|---|
| `vpnd` down | Tunnels keep working (fail-static); API returns 503; alerts fire at 60 s |
| Postgres down | API 503 after pool timeout; tunnels unaffected; no config churn |
| Redis down | Rate limiting degrades to in-process token buckets; revocation stays correct (DB is the source of truth) |
| One data-plane worker crashes | process exits, systemd restarts, clients re-handshake within 5–10 s |
| Node drained | Existing sessions get `suggested_endpoints`, make-before-break ≤180 s |
| Clock skew | TAI64N is a *per-peer counter*, never compared to wall clock; timers use `CLOCK_MONOTONIC_RAW` |

## 7. What M0 actually implements

`vpnd` with config resolution (file → env → flags), JSON logging, graceful
signal handling, `/healthz`, `/readyz`, `/metrics`, plus `vpn_core`'s BLAKE2s,
message codec, MAC/cookie derivation, replay window and config parser — all
covered by `vpn_unit_tests`. Everything else is designed and scheduled in
[ROADMAP.md](ROADMAP.md) and is **not** claimed to work.

Precise scope limits of the M0 process, so that nothing here overstates it:

| Aspect | M0 reality |
|---|---|
| Listeners | **Two** HTTP listeners: `http.bind` (API/health/metrics) and `metrics.bind` (`metrics_only` mode, so scrape traffic has its own socket and can be firewalled separately). |
| Ports 8443 / 9443 from §4 | Not bound. They are the TLS/API target. |
| Threads | The accept loop only enqueues; a fixed worker pool (`http.max_connections`, default 64) serves requests, so a slow client occupies one worker instead of stalling health checks. The queue is bounded (4x the pool) and sheds load with 503 rather than growing. |
| TLS | Not implemented. `tls.*` is parsed and `validate()` rejects production without cert/key paths, but **nothing terminates TLS** — put a proxy in front. |
| Auth | None yet. `admin_token` is parsed, redacted, length-validated, and `HttpServer::set_router()` is the mount point for the API layer. |
| Config reload | `SIGHUP` re-reads and validates the file: log level applies immediately, `vpn_config_reload_total` and `config_generation` are updated, and bind/limit changes are reported as needing a restart. |
| `/debug/*` | `/debug/stats` and `/debug/version` exist when `dev_mode` is true. |
| Readiness | Reflects only this process's own listener state (`accepting_connections`, `shutting_down`). There are no dependency checks because there are no dependencies. |
| Known defects | **None open in the core.** The cookie port binding, the replay-window boundary and the inverted `ct::select()` were found by the verification pass and fixed; their assertions are now always on (`docs/PROTOCOL.md` §4). `docs/PROTOCOL.md` §2.1 keeps the cookie derivation as the normative rule. |

The M0 gate (clean `-Werror` build + unit suite green) **is met**:
`scripts/build-local.ps1` builds Release with clang 21 via zig and runs both
suites (77 assertions across `vpn_unit_tests` and `vpn_http_tests`). What M0 does
*not* claim is a tunnel, TLS, auth or the API — see [ROADMAP.md](ROADMAP.md).
