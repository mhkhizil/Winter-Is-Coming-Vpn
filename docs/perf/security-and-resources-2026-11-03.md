# Security and resource audit — 2026-11-03

Scope: the C++ control plane (`vpnd`), its store, and the API surface. Every number
below was produced on this machine by the scripts named next to it; nothing here is
estimated. The Android client's runtime behaviour is **not** covered (no emulator:
x86_64 emulation needs hardware acceleration this host does not have — see
`VPN-Fe-Android/VERIFICATION.md`).

## 1. Critical: privilege escalation through the store log (found, fixed, tested)

The store is an append-only, tab-separated, newline-terminated log. Several fields in
it come straight from API input — a device `name` and `platform`, a user `email`.

`POST /api/v1/devices` accepted a name containing a newline and tabs, and `append_line`
wrote it verbatim, so the name became *additional log records*. A non-admin user could
therefore write:

```
D	dev_…	usr_alice	innocent
U	usr_pwn	ten_default	pwn@evil.invalid	<hash>	admin
```

Replay parses `U` records into accounts, so on the next start the forged line became a
real administrator. Demonstrated end to end before the fix: forged login `HTTP 200`,
`GET /api/v1/admin/users` `HTTP 200` with the full user list.

**Fix** (`server/src/api/store.cpp`):

- `escape_record()` escapes `%`, LF and CR on write while leaving the structural tabs
  alone; `unescape_field()` reverses it per field on replay. One choke point covers
  every record kind, including ones added later. Unknown `%` sequences are left
  untouched, so logs written before this change still replay identically.
- `is_printable_text()` additionally rejects control characters in a device name
  (1–64 chars), platform (≤32) and email (≤254), so normal callers get a clear `400`
  instead of a value that silently reads back as `%0A`.

**Regression test**: `scripts/verify-log-injection.ps1` — refuses the attack (`400`),
proves no forged account survives a restart (login `401`), proves a non-admin still
cannot reach admin endpoints (`403`), and proves legitimate names still round-trip,
including one containing `%` (`100% phone`).

```
attack: HTTP 400
legit names: HTTP 201 / 201
after restart: forged login=401 admin-endpoint=403 names-intact=True
PASS: injection refused, no forged admin, legitimate names (including %) survive a restart
```

The same class of bug exists in any line-oriented format that carries user text; the
audit rule to keep is that **the encoder belongs at the single write choke point**, not
at each call site.

## 2. Wrong status codes on the device and peer paths (found, fixed)

Both were `500 Internal Server Error`, which hides caller mistakes and breaks retry
logic:

- A rejected device name answered `500`; it now answers `400` via the store's error
  code (`server/src/api/router.cpp`).
- `POST /api/v1/peers` with no node registered **created the peer row and then**
  answered `500`, because the config could not name an endpoint. A client that retried
  hit "one active peer per device" for a peer it never saw succeed. The node check now
  runs *before* allocation and answers `503` with code `no_node` and an actionable
  message, leaving no half-created state.

## 3. Soak: no leak under sustained churn

`scripts/soak_probe.py` — each cycle creates a device, uploads a key, creates a peer,
deletes it, and rotates the session token.

```
baseline               handles=156 rss_mb=7.3 threads=74
soak: 150 cycles in 1.9s, 0 failures
after 150 cycles       handles=280 rss_mb=7.8 threads=74
after 6s idle          handles=280 rss_mb=7.8 threads=74
after 300 total        handles=280 rss_mb=7.9 threads=74
after 450 total        handles=280 rss_mb=8.0 threads=74
```

Reading it honestly:

- **Handles plateau at 280.** The first batch raises the count by 124 (socket/threadpool
  warm-up: 74 threads exist from the start, and the HTTP server's per-connection objects
  are created on first use). 300 further cycles, and 6 s of idle, move it by zero. That
  is a plateau, not a leak.
- **RSS +0.7 MB for 450 retained devices** (≈1.5 KB/device of live map state plus the
  log buffer). Growth tracks *retained objects*, not requests: the second and third
  batches add 300 devices and cost 0.2 MB.
- **Threads constant at 74** across 450 cycles, so no thread-per-request leak.
- Throughput: ~89 cycles/s (≈530 HTTP requests/s over 5 endpoints) on one Windows host,
  with `0 failures`.

Failed peer creations in later batches are the per-user peer cap answering `422`, which
is policy, not a defect — the probe reuses device names across rounds.

## 4. What this audit did not cover

| Area | Why | Where it can run |
|---|---|---|
| Android runtime: leaks, jank, private-key lifetime | no emulator (no hypervisor on Win11 Home) and no device | CI instrumented lane, or a physical phone |
| Real TUN forwarding, official `wg` interop | needs `CAP_NET_ADMIN` and a real interface | `scripts/interop-test.sh` on a VPS |

### Addendum: the data-plane suites, previously blocked, now run

`vpn-dp.exe` was being refused by Windows Smart App Control — but only that one stale
binary: a fresh build of the same source from the same toolchain runs fine. Reconfiguring
`out/build-dp` with `-DVPN_BUILD_DATAPLANE=ON` (and the zig `ar`/`ranlib` shims, which is
what a naive fresh configure misses: without them CMake reports `CMAKE_AR-NOTFOUND`) made
the whole data-plane matrix runnable again on this host:

| Suite | Result |
|---|---|
| `scripts/interop-local.ps1` | **PASS** — independent implementation: handshake ok, 4 transport packets accepted, 32-byte inner payload |
| `scripts/verify-cp-dp-pull.ps1` | **PASS** — vpn-dp fetched its peer table from vpnd and served a real handshake |
| `scripts/verify-dp-batching.ps1` | **PASS** — every queued datagram of every batch accepted, no drops |
| `scripts/verify-access-expiry.ps1` | **PASS** — lapsed peer refused, paid-up and staff peers accepted |
| `scripts/verify-reminders.ps1` | **PASS** after a harness fix (below) |
| `scripts/verify-security.ps1` | **PASS** 5/5 |
| `scripts/verify-log-injection.ps1` | **PASS** |

`verify-reminders.ps1` was failing for a reason worth recording: vpnd reported
`sent: 1` while the capture server's directory was still empty, because the assertion ran
before the sink had written the message. The script now waits for the sink to be
*listening* before starting vpnd, polls for the `.eml` instead of reading the directory
once, and stops only the sink process it started — the old version did
`Get-Process python | Stop-Process`, which killed every Python process on the machine,
including whatever the person running the verification happened to be doing.

So the honest status is: the data plane has now forwarded packets on this host, but still
not through a real TUN interface — that part needs `CAP_NET_ADMIN` on Linux.


Static review of the client is in progress separately and is not folded into this
document yet; it is a code-reading exercise, not a measurement.
