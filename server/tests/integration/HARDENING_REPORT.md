# vpnd control-plane: HTTP/daemon hardening review

Scope: `server/src/controlplane/http_server.cpp`, `server/include/vpn/controlplane/http_server.hpp`,
`server/src/controlplane/main.cpp`, `server/src/common/log.cpp`, `server/src/obs/metrics.cpp`.
Build: `zig c++ -std=c++23` (zig 0.16.0), Windows x86_64, `-Wall -Wextra` clean.
All evidence below is from real sockets against a real `vpnd` process.

## 0. Headline

The daemon **did not compile at all** and, once buildable, had one
scanner-triggerable unbounded-cardinality defect, one address-hijacking defect,
a header limit that admitted 9 KiB headers against an 8 KiB setting, a response
that was silently lost for any request with a body, and a shutdown path bounded
by the request timeout (10 s) instead of < 2 s.

| # | Defect | File:line (pre-fix) | Severity | State |
|---|--------|---------------------|----------|-------|
| 1 | `make_error()` used without including `result_helpers.hpp`; `vpnd` does not compile | `src/common/endpoint.cpp:79`, `src/config/config.cpp:92` | **Blocker** | Reported (out of scope to edit); worked around with `-include vpn/common/result_helpers.hpp` |
| 2 | String-literal concatenation across `std::string{...}`; `http_server.cpp` does not compile for any `VPN_VERSION` value | `src/controlplane/http_server.cpp:361`, `:378` | **Blocker** | **Fixed** |
| 3 | Unbounded `route` label from the raw request path (scanner grows Prometheus series and the linear `samples_` vector) | `http_server.cpp:285-288` | **High** | **Fixed** |
| 4 | `SO_REUSEADDR` on Windows lets a second process bind the same address (address hijacking; EADDRINUSE never reported) | `http_server.cpp:138-140` | **High** | **Fixed** (`SO_EXCLUSIVEADDRUSE`) |
| 5 | SIGTERM latency bounded by `request_timeout_secs` (10 s), not < 2 s: `stop()` only set a flag | `http_server.cpp:173-176` | **High** | **Fixed** (4707 ms → 15 ms) |
| 6 | Slowloris: `SO_RCVTIMEO` is per-`recv`, so a client dribbling one byte per second holds the single-threaded loop **forever** | `http_server.cpp:226-238` | **High** | **Fixed** (absolute header deadline; "never" → 10.1 s) |
| 7 | Response lost for requests with a body: closing with unread input sends RST and the peer discards the buffered response | `http_server.cpp:310-317` | **Medium** | **Fixed** (shutdown + bounded body skip) |
| 8 | `max_header_bytes` not enforced when the terminator arrives in the read that crosses the limit (9 KiB header → 200) | `http_server.cpp:240-252` | **Medium** | **Fixed** |
| 9 | Unbounded `method` label from the raw request method | `http_server.cpp:287` | **Medium** | **Fixed** |
| 10 | Histogram exposition emits `name{labels}_count` instead of `name_count{labels}` — invalid sample line | `metrics.cpp:161-168` | **Medium** | **Fixed** |
| 11 | Auto-discovered gauge typed as `counter` in `# TYPE` | `metrics.cpp:119-124` | **Medium** | **Fixed** (per-sample `Kind`) |
| 12 | `format_number()` casts NaN/Inf to `uint64_t` before checking — UB | `metrics.cpp:11-20` | **Medium** | **Fixed** |
| 13 | Same label set in a different order creates two series with one identity | `metrics.cpp:61-72` | **Medium** | **Fixed** (canonical label order) |
| 14 | Bind failure reported as "no usable address" — real cause (EADDRINUSE/EACCES) discarded | `http_server.cpp:133,142-149` | **Medium** | **Fixed** |
| 15 | `IPV6_V6ONLY` left to platform default: `--bind [::]:port` accepts IPv6 but IPv4 clients hang | `http_server.cpp:134-164` | **Medium** | **Fixed** (verified dual-stack) |
| 16 | Double space in the request line routes an empty target to 404 instead of 400; empty target/`HTTP/0.9`/bogus version accepted | `http_server.cpp:255-280` | **Low** | **Fixed** |
| 17 | Absolute-form request target → 404 (RFC 9112 §3.2.2 says accept it) | `http_server.cpp:273` | **Low** | **Fixed** |
| 18 | `recv` `EINTR`/`EAGAIN` treated as a protocol violation; peer close counted as "rejected" | `http_server.cpp:234-238` | **Low** | **Fixed** |
| 19 | 400/431 responses omitted `Server`/`X-Content-Type-Options` | `http_server.cpp:243-267` | **Low** | **Fixed** |
| 20 | Header terminator searched from offset 0 on every read → O(n²) for a 1 MiB `max_header_bytes` | `http_server.cpp:240` | **Low** | **Fixed** (rolling scan) |
| 21 | `accept()` failure (`EMFILE`) spins the loop at 100% CPU with no backoff | `http_server.cpp:212-215` | **Low** | **Fixed** (20 ms backoff) |
| 22 | Signal handlers installed *after* `listen()` | `main.cpp:206-215` | **Low** | **Fixed** |
| 23 | `metrics.bind` silently ignored (firewall 9100 and `/metrics` is still on 8080) | `main.cpp:200-209` | **Low** | **Fixed** (startup warning) |
| 24 | `--bind ":8080"` rejected with "host is empty" although `endpoint.hpp` documents it as "all interfaces" | `endpoint.cpp:50` | **Medium** | Reported (out of scope) |
| 25 | `listen_fd_` is an `int` holding a `SOCKET` (`UINT_PTR`) — latent truncation on Win64 | `http_server.hpp:88` | **Low** | Reported |
| 26 | No `Date` response header (RFC 9110 §6.6.1: SHOULD) | `build_response()` | **Low** | Reported |

## 1. Raw evidence

Every case below was executed by `server/tests/integration/raw_http_probe.py`,
`daemon_lifecycle.py`, `slowloris_probe.py`, and by
`server/tests/unit/test_http_server.cpp` / `test_metrics.cpp`.

### 1.1 Build blockers

```
$ zig c++ -std=c++23 ... src/common/endpoint.cpp ...
server/src/common/endpoint.cpp:76:12: error: use of undeclared identifier 'make_error'
```
`endpoint.cpp:7` even says "make_error() lives here, not in result.hpp (see
result_helpers.hpp)" — the include is simply missing. Same in `config.cpp:92`.

After the two syntax fixes in `http_server.cpp`:
```
$ zig c++ -std=c++23 -Wall -Wextra ... -o out/vpnd.exe      # exit 0, no warnings
```

### 1.2 Prometheus `route` cardinality (defects 3, 9)

```
pre-fix : routes before=8 after=48
          route values: ['', '/', '/healthz', '/metrics', '/nope', '/readyz',
                         '/scan-0-869296', '/scan-1-460593', ... ]
          methods before=9 after=19
FAIL  route label is bounded (<=8 distinct values)   distinct route values after 40 random paths = 48
FAIL  method label is bounded (<=8 distinct values)  distinct method values after 10 random methods = 19

post-fix: routes before=5 after=5
          route values: ['/', '/healthz', '/metrics', '/readyz', 'other']
          methods before=8 after=8
          method values: ['DELETE','GET','HEAD','OPTIONS','PATCH','POST','PUT','other']
PASS  route label is bounded (<=8 distinct values)   distinct route values after 40 random paths = 5
```
Unit test against the pre-fix source: `route label is unbounded: 40 distinct values after 40 scans`.

### 1.3 Address hijacking (defect 4)

```
pre-fix : FAIL  port in use exits 3 (runtime error)   exit='still-running'
          stderr={... "msg":"http listening","kv":{"bind":"127.0.0.1:57120"}}
          (the second vpnd bound the port that was already in use)

post-fix: PASS  port in use exits 3 (runtime error)   exit=3
          stderr={..."level":"error","msg":"failed to listen","kv":{"error":
          "unavailable: cannot bind 127.0.0.1:49358: address already in use (WSAEADDRINUSE)"}}
```

### 1.4 Shutdown latency (defect 5)

Measured exactly what the signal handler triggers (`stop()` → `serve()` returns):

```
pre-fix : FAIL  stop() -> serve() return took 4707 ms with a stalled client
post-fix:       stop() -> serve() returned after 15 ms (budget 2000 ms)
                [ OK ] HttpServer.stop_returns_promptly_while_a_client_is_stalled
```

### 1.5 Slowloris (defect 6)

One byte every 2 s, 14 s budget, concurrent `/healthz` every 250 ms:

```
pre-fix : server closed the dribbling connection at: NEVER (within budget)
          concurrent /healthz succeeded again at:     NEVER (within budget)
          RESULT: STILL BLOCKED after 14s - one client starves the daemon

post-fix: concurrent /healthz succeeded again at:     10.11s
          RESULT: recovered within 14s
```

### 1.6 Response lost for a request with a body (defect 7)

```
pre-fix : FAIL  POST with a 200 KB body -> 405 (body never parsed)   status=0
                >>> <POST + 200 KB body>
                <<<                                    <- nothing at all
post-fix: PASS  POST with a 200 KB body -> 405 (body never parsed)   status=405
```

### 1.7 Header limit (defect 8)

```
pre-fix : FAIL  9 KB header -> 431      status=200     (served the /healthz body)
post-fix: PASS  9 KB header -> 431      status=431
          <<< HTTP/1.1 431 Request Header Fields Too Large / Content-Length: 77
PASS  100 KB header in one write -> 431
PASS  header at the limit -> 200 (not 431)   sent=8184 bytes
```

### 1.8 Request-line handling (defects 16, 17)

```
pre-fix : FAIL  double SP in request line -> 400     status=404
          FAIL  absolute-form URI accepted -> 200    status=404
post-fix: PASS  double SP in request line -> 400
          PASS  absolute-form URI accepted -> 200
          PASS  HTTP/0.9 request line -> 400
          PASS  garbage request line -> 400
          PASS  empty request line -> 400
          PASS  bogus HTTP version handled deterministically
```

### 1.9 Dual stack (defect 15)

```
pre-fix : --bind [::]:57131   127.0.0.1 -> FAIL timed out
                              ::1       -> b'HTTP/1.1 200 OK'
post-fix: [::] bind accepts ::1        ::1:49364 -> b'HTTP/1.1 200 OK'
          [::] bind accepts 127.0.0.1  127.0.0.1:49364 -> b'HTTP/1.1 200 OK'
```

### 1.10 What already worked (regression guard)

`GET /healthz` 200 + `Connection: close` + `Content-Length: 69` + `nosniff`;
`HEAD /healthz` 200 with **no body** and `Content-Length: 69` (identical to GET);
`/readyz`, `/`, `/metrics` 200; `/nope` 404 `application/problem+json`;
`POST/PUT/DELETE/PATCH/OPTIONS/TRACE/CONNECT` 405 + `Allow: GET, HEAD`;
request split across 5 TCP segments 200; pipelined x2 answered once;
client RST mid-header tolerated; half-closed client still served;
100 concurrent idle connections tolerated; 200 KB body ignored.

Final state: **48/48 protocol cases, 11/11 server unit tests, 6/6 metrics unit
tests, 15/16 process-contract cases** (the single failure is defect 24, unfixed
by design).

### 1.11 CLI / process contract (behaviour unchanged, re-verified)

```
--print-version           exit 0  'vpnd 0.1.0 (wire v1, protocol 1)'
--validate-config         exit 0  'configuration OK (environment=development)'
--print-config            exit 0  admin_token = "<redacted>", key_file = "<redacted>"
unknown flag              exit 2  "error: unknown argument '--totally-unknown-flag'"
missing flag value        exit 2  "error: --bind requires host:port"
malformed --bind          exit 2  "endpoint must be host:port (got 'not-an-endpoint')"
missing config file       exit 2  "cannot open config file: /nonexistent/vpnd.toml"
invalid config value      exit 2  "http.request_timeout_secs must be 1..300"
port already in use       exit 3  "cannot bind 127.0.0.1:49358: address already in use"
```

## 2. Thread-safety review (main thread + refresher)

* `metrics` is declared before `server` in `main()`, so `HttpServer` (which holds
  `obs::Metrics&` and `HealthState&`) is destroyed first; the refresher thread is
  joined before `main` returns. No use-after-destruction of `metrics_`.
* `Metrics` is fully mutex-guarded (`render()` included), so the refresher's
  `set_gauge` and the accept loop's `inc_counter` cannot race.
* `HealthState` is all `std::atomic` with relaxed ordering; the only consistency
  requirement (readyz reflecting `shutting_down` / `accepting_connections`) is a
  liveness signal, so relaxed ordering is correct here.
* `stop()` is called from the refresher thread while `serve()` runs. It now only
  touches atomics plus a best-effort `shutdown()` on `active_client_`. Residual
  benign race: `stop()` may read a client fd that the serving thread is closing;
  `shutdown()` then fails with `EBADF`/`WSAENOTSOCK` (ignored). The read loop also
  polls `stopping_` every 100 ms, so correctness does not depend on `shutdown()`
  succeeding.
* Signal handler does exactly one atomic store — async-signal-safe. Handlers are
  now installed before `listen()`.

## 3. What remains risky, and whether that is acceptable

1. **Head-of-line blocking (accepted for M0, documented).** The accept loop is
   single-threaded, so one slow client delays *all* health responses for up to
   `http.request_timeout_secs` (default 10 s) — measured: a stalled client made a
   concurrent `/healthz` take 6.01 s. Previously it was unbounded; now it is
   bounded and the shutdown path no longer waits for it. **Not acceptable for a
   public-internet listener**; acceptable only behind loopback/reverse proxy.
   `docs/ARCHITECTURE.md` §7 now states this explicitly. A real fix is a bounded
   worker pool or Drogon (M3).
2. **No TLS and no auth (already documented).** `/metrics` exposes uptime and
   request counters to anyone who can reach the port. Keep it on loopback.
3. **`metrics.bind` is a lie until M3.** Now warned about at startup; the config
   key still exists and doing nothing is the surprising part. Either wire it up or
   reject it in `validate()`.
4. **The daemon does not build without the missing include (defect 1).** This is
   the highest-value follow-up: two one-line edits (`#include
   "vpn/common/result_helpers.hpp"` in `src/common/endpoint.cpp` and
   `src/config/config.cpp`). Until then every CI "green" claim about `vpnd` is
   unverified.
5. **`--bind ":8080"` documented but rejected (defect 24).** Either implement the
   wildcard (skip `validate_host` for an empty host) or fix `endpoint.hpp`'s
   comment. Until then the only wildcard forms are `0.0.0.0:p` (IPv4-only) and
   `[::]:p` (dual-stack, now correct).
6. **`listen_fd_` as `int` (defect 25).** `SOCKET` is `UINT_PTR` on Win64; the cast
   at `http_server.cpp:161` can truncate. Recommend `std::intptr_t` for the member
   and its comparisons. Not exercised by any test on this platform.
7. **No `Date` header (defect 26).** Harmless for Prometheus/kubelet probes; a
   strict HTTP/1.1 conformance gap. Cheap to add later.
8. **Log sink is `fwrite`+`fflush` per line under a mutex.** Fine at M0 volume
   (health checks), and it is deliberately off any data-plane path, but a busy
   log level would serialise the accept loop. `log.cpp` itself is correct:
   escaping is sound, one `fwrite` per line, no allocation on the level check.
   Message bodies are escaped, so no log injection via request paths (paths are
   never logged anyway).
9. **Integration harness is Windows/native-only in this run.** SIGTERM delivery
   cannot be synthesised from Python on Windows; the shutdown requirement is
   therefore proven at the level the signal handler acts on (`stop()` →
   `serve()`). `daemon_lifecycle.py` performs the full end-to-end SIGTERM timing
   on POSIX and is a no-op on Windows.

## 4. Files changed

* `server/src/controlplane/http_server.cpp` — recv loop rewritten around
  `select()` + absolute deadline, header-limit re-check, request-line validation,
  absolute-form support, bounded metric labels, response builder, `send_all` /
  drain / shutdown helpers, `SO_EXCLUSIVEADDRUSE`, `IPV6_V6ONLY=0`, bind error
  text, accept backoff, `stop()` interrupts the in-flight connection.
* `server/include/vpn/controlplane/http_server.hpp` — `active_client_`, honest
  doc comment about the single-threaded limit.
* `server/src/controlplane/main.cpp` — handlers installed before `listen()`,
  `metrics.bind` warning.
* `server/src/obs/metrics.cpp` / `metrics.hpp` — histogram suffix placement,
  per-sample kind, NaN/Inf handling, canonical label order.
* `server/tests/unit/test_http_server.cpp`, `server/tests/unit/test_metrics.cpp`
  (new), `server/tests/CMakeLists.txt` (new `vpn_http_tests` target).
* `server/tests/integration/{raw_http_probe.py,daemon_lifecycle.py,slowloris_probe.py}`
  (new) and this report.
* `docs/ARCHITECTURE.md` §7 — factual statement of the thread/slow-client limit.



