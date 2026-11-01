# Threat model

Status: **normative**. Every claim below must be reproducible by a test or a
documented operational control. Related: ADR-0008, `SECURITY.md`.

## 1. Assets

| Asset | Where it lives | If compromised |
|---|---|---|
| Client static private keys | **client device only** (Keystore/Secure Enclave); never in our DB | identity theft of that device |
| Server static private key | node RAM, sealed to TPM 2.0 (PCR 7+14) | impersonation of the node to its clients |
| Session keys | node RAM only, zeroized on rotation | decryption of that session |
| Password hashes | PostgreSQL (Argon2id, peppered) | offline cracking (bounded by Argon2 cost) |
| Refresh tokens | hashed in `sessions` | session takeover until rotation |
| Aggregated usage counters | PostgreSQL | privacy inference (mitigated by aggregation only) |

## 2. STRIDE table

| Threat | Vector | Mitigation (implementation) |
|---|---|---|
| **Spoofing** | forged handshake from a spoofed source IP | stateless `mac1` check before any DH; per-source-IP token bucket; cookie reply under load |
| **Tampering** | modify a transport packet | AEAD tag over header+payload; counter inside the authenticated data |
| **Repudiation** | admin denies an action | append-only `audit_log` with actor, diff, request_id, impersonator |
| **Information disclosure** | DB dump | no client private keys exist server-side; server keys never persisted in plaintext; passwords Argon2id |
| **Denial of service** | handshake flood / spoofed flood | `mac1`+cookie path (M2), 8192-bit per-/32 rate limiter, fixed-size index table (no allocation on flood), cookie secrets rotated every 120 s |
| **Elevation of privilege** | SQL injection, IDOR | parameterised queries only, RLS (`SET LOCAL app.tenant_id`) as backstop, tenant id from token never from body |
| **Replay** | resend captured handshake/transport | TAI64N monotonic per peer + RFC 6479 counter window, updated **after** AEAD |
| **Key compromise (client)** | stolen device | 1 s fail-closed revocation, ≤5 devices/user, concurrent /24–/48 detection, Play Integrity / App Attest at enroll |
| **Key compromise (server)** | node seizure | TPM-sealed key, node removed from catalog in ≤1 min, clients rotate keys |
| **Malicious server operator** | insider reads traffic | architecture, not policy: RAM-only endpoints, no packet capture tooling in the image, reproducible image hash published, no lawful-intercept code path |
| **Tenant isolation breach** | one tenant reaching another | single-allowed-IPs trie per node with uniqueness enforced in CP *and* DP; property test: 0 cross-tenant packets in 10⁶ |

## 3. Explicitly out of scope (state it, do not market around it)

* **Traffic-analysis resistance.** We do not pad, shape or obfuscate. An observer
  sees IP addresses, packet sizes, timing and volumes. Censorship resistance is
  the optional outer shim (§`PROTOCOL` fallback 1) and is off by default.
* **Compromised client device.** If the OS is rooted, the tunnel content is
  readable by that device — that is inherent to a VPN.
* **Global passive adversary vs. static-static DH.** X25519 static keys are not
  post-quantum; only the ephemeral DH plus a hybrid PSK will be (§`PROTOCOL` 6).
* **Legal compulsion.** We cannot defeat a court order against the operator; our
  defence is that there is nothing to hand over (no-logs by construction).

## 4. Key hygiene rules

Enforcement status is stated per rule. **Do not describe a rule as "CI-enforced"
unless a gate in `.github/workflows/` actually fails on it** — several documents
in this repo did exactly that, which is a truthfulness defect, not a nit.

| # | Rule | Enforced today |
|---|---|---|
| 1 | `memcmp`/`==` on secret material is banned; use `vpn::ct::equal`. | **partly** — `ci-server.yml` greps `server/{src,include}` for `memcmp (`; it does not catch `==` on spans and does not catch `std::memcmp`. Review remains the real control. |
| 2 | `memset` on key material is banned; use `vpn::ct::cleanse` (volatile stores). | **no gate — and currently violated** by `server/src/crypto/blake2s.cpp:58,62,130` (`std::memset`/`std::memcpy` on the key block and hash state). Fix or formally except it. |
| 3 | Keys are passed as `ByteSpan` views, never copied into `std::string`. | review only; holding true so far. |
| 4 | Key pages are `mlock`ed, `MADV_DONTDUMP`, `MADV_WIPEONFORK`; the process sets `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`. | **not implemented** — no such syscalls exist in M0. Target for M1. (`vpn-datad.service` does set `LimitMEMLOCK=infinity`, which is a prerequisite only.) |
| 5 | Zero heap allocations on the packet path, proven by an `alloc_guard` that aborts if `operator new` is called during a test packet run. | **not implemented** — no `alloc_guard` exists anywhere; there is no packet path yet. Target for M2. |
| 6 | Never log, never serialise, never `str()` a key. Logging rules are enforced by a grep gate in CI over `server/src/**`. | **no such grep gate exists** in `.github/workflows/`. `vpn::log` has no key-shaped overloads and `config::to_string` redacts `admin_token`/`tls.key_file` (unit-tested), which is the only mechanical guarantee today. |

Note that `secure_zero` in `server/include/vpn/common/bytes.hpp` is a second,
independent volatile-store wipe alongside `ct::cleanse`; rule 2 should probably
name both.

## 5. Privacy defaults

* No per-connection logs. Aggregate counters only (bytes, sessions, handshakes).
* IP attribution is retained for **0 s** by default; an operator may enable a
  `session_ip` table with a hard 24 h TTL for abuse handling — off in prod.
* Data minimisation in the API: responses never include another tenant's ids.
* GDPR: deletion request = delete `users` row → cascade removes devices/peers;
  audit rows keep only ids and are pseudonymous.

## 6. Incident classes (see RUNBOOK.md for procedures)

| Class | Example | First action |
|---|---|---|
| S1 | server key suspected compromised | revoke node from catalog, rotate, notify |
| S2 | tenant isolation bug | freeze writes, drain node, preserve evidence |
| S3 | handshake flood | enable cookie mode, scale workers, rate-limit upstream |
| S4 | billing/auth outage | fail-static tunnels, status page, no config churn |
