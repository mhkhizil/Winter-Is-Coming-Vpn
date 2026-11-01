# WireGuard-core verification report

Subject: `server/src/crypto/blake2s.cpp`, `server/src/crypto/ct.cpp`,
`server/src/wire/message.cpp`, `server/src/wire/replay_window.cpp` and the unit
tests under `server/tests/unit/`.
Method: differential testing against independent references (Python
`hashlib.blake2s`, two independent Python BLAKE2s models, a line-by-line port of
the code under test, and the published RFC 7693 / RFC 6479 / `wireguard-go` /
Linux-kernel WireGuard sources fetched from their canonical URLs).
**No `src/` file was modified**: every defect below is reported for the lead to
patch.

## 1. Verdict

| area | verdict |
|---|---|
| BLAKE2s (unkeyed, keyed, streaming, 1..32-byte output) | **PASS** — 560/560 cases match `hashlib`, in a line-by-line port *and* in the real C++ |
| Hard-coded digests in `test_blake2s.cpp` | **PASS** — 15/15 correct (2 RFC 7693 Appendix B + 13 golden); no wrong vector |
| mac1 / mac2 derivation and byte coverage | **PASS** — byte offsets and MAC spans match the kernel's `compute_mac1/mac2` exactly |
| Cookie derivation | **PASS** — `keyed-BLAKE2s-128(secret, ip ‖ port_be)` matches the kernel's `make_cookie`, IPv4 **and** IPv6 (finding W-1 is fixed in `src/`) |
| Anti-replay window | **1 deviation** — semantics match `wireguard-go` on 318/319 scenarios; the usable window is one counter narrower than RFC 6479 (finding R-1, low) |
| `ct::select` | **FAIL** — inverted with respect to its documented contract (finding C-1); currently unused |
| Buildability + unit suite | **PASS** — `vpn_core` compiles clean with `-Wall -Wextra`; 71 unit tests, 0 failures |

Bottom line: the cryptographic primitive (BLAKE2s) and the handshake message
format are correct, byte for byte, against the WireGuard specification. Two real
defects remain: an inverted constant-time `select()` (latent — nothing calls it
yet) and a one-counter-narrow replay window. Both are small, both are patched by
a one-line change, neither is remotely exploitable as written.

## 2. How to reproduce

```
cd server/tests/golden

python run_all_verifications.py --cxx <zig.exe>   # every verifier, one summary
python verify_blake2s.py --cxx <zig.exe>          # 560 cases + the unit vectors
python verify_macs.py --cxx <zig.exe>             # mac1/mac2/cookie + offsets
python verify_replay_window.py --cxx <zig.exe>    # 319 scenarios vs wireguard-go
python check_new_replay_assertions.py             # sanity-checks the C++ assertions
python refresh_verification_doc.py                # re-splices BLAKE2S_VERIFICATION.md

# the unit suite (all of vpn_core + every test file, no CMake needed):
<zig.exe> c++ -std=c++20 -O1 -Iinclude -Itests/unit \
  src/common/endpoint.cpp src/common/log.cpp src/crypto/blake2s.cpp \
  src/crypto/ct.cpp src/wire/message.cpp src/wire/replay_window.cpp \
  src/config/config.cpp src/obs/metrics.cpp \
  tests/unit/test_main.cpp tests/unit/test_blake2s.cpp \
  tests/unit/test_wire_message.cpp tests/unit/test_replay_window.cpp \
  tests/unit/test_ct.cpp tests/unit/test_config.cpp tests/unit/test_metrics.cpp \
  -o work/unit_tests.exe
# add -DVPN_ENABLE_KNOWN_BUG_TESTS=1 to reproduce C-1 and R-1.
```

`verify_replay_window.py` and therefore `run_all_verifications.py` exit non-zero
**only** because finding R-1 is still open. That is intentional: the gates stay
red while a deviation exists.

Environment: Python 3.14.7 (`hashlib.blake2s`); `zig c++` 0.16.0 (clang front
end, libc++), Windows x86-64, `-std=c++20`. PyNaCl is installed under
`work/pynacl` but its hash API is BLAKE2b-only and there is no `openssl` binary,
so neither can cross-check BLAKE2s — see `BLAKE2S_VERIFICATION.md`.


## 3. Check table

Legend: **PASS** = observed equals the independent reference. **FAIL** = the
code under test disagrees with the reference, or with its own documented
contract. **INFO** = behaviour is safe/benign but deviates from the letter of the
spec or is a caller hazard.

### 3.1 BLAKE2s (`src/crypto/blake2s.cpp`, `include/vpn/crypto/blake2s.hpp`)

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 1 | 560-case differential set: `hashlib` vs a line-by-line port of `blake2s.cpp` | identical | identical (560/560) | PASS |
| 2 | same set vs a from-scratch RFC 7693 model | identical | identical (560/560) | PASS |
| 3 | same set vs the **real C++** (`zig c++ -O2`) | identical | identical (560/560) | PASS |
| 4 | unkeyed digests, inputs empty/abc/1/63/64/65/127/128/129/1000 | `hashlib.blake2s` | identical (20/20, out len 16 **and** 32) | PASS |
| 5 | keyed digests, key lengths 1/16/32 × out 16/32 × the same inputs | `hashlib.blake2s(key=…)` | identical (60/60) | PASS |
| 6 | keyed **empty** message (key block must be the *final* block, `t=64`, last flag set) | `hashlib` | identical | PASS |
| 7 | streaming == one-shot at splits 1/7/63/64/65/127/128/129/999 | identical | identical (429/429) | PASS |
| 8 | 200 randomised cases (len 0..300, key 0/1/16/32, out 1..32, random chunks) | `hashlib` | identical (200/200) | PASS |
| 9 | output length != 32 is not a truncation of the 32-byte digest (parameter block differs) | different | different | PASS |
| 10 | `blake2s()` with a 33-byte output span / 33-byte key | refused | refused | PASS |
| 11 | `blake2s()` with a 0-byte output span | refused | refused | PASS (new test) |
| 12 | `Blake2s::final()` with an undersized buffer: returns 0 **and** does not consume state (a retry yields the RFC "abc" digest) | 0, then the correct digest | 0, then the correct digest | PASS (new test) |
| 13 | `Blake2s(out, key)` built directly with a key longer than the 64-byte `buf_` | no overflow | `memcpy` overflows `buf_` (unchecked) | **FAIL (C-3, low)** |

### 3.2 Hard-coded vectors in `tests/unit/test_blake2s.cpp`

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 14 | `empty_input_rfc_vector` (`BLAKE2s-256("")`) | `69217a30…eef9` | `hashlib` agrees | PASS |
| 15 | `abc_rfc_vector` (`BLAKE2s-256("abc")`) | `508c5e8c…5982` | `hashlib` agrees | PASS |
| 16 | 13 rows of the `kGolden` table, each re-derived from its own (data_len, key_len, out_len) and the file's byte patterns | `hashlib` | 13/13 identical | PASS |
| 17 | coverage: every digest literal in the file is one this audit re-derived | 0 unverified | 0 unverified (15 literals) | PASS |

No wrong vector was found. The two RFC values are the ones printed in RFC 7693
Appendix B, and all 15 are reproduced independently by `hashlib.blake2s`.

### 3.3 Message layout, mac1 / mac2 / cookie (`src/wire/message.cpp`)

Reference: the WireGuard protocol document (message formats), `wireguard-go`
`device/cookie.go` (`CheckMAC1`, `CheckMAC2`, `CreateReply`, `AddMacs`) and the
Linux kernel `drivers/net/wireguard/cookie.c` (`compute_mac1`, `compute_mac2`,
`make_cookie`, `precompute_key`), all fetched and read during this pass.

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 18 | initiation field offsets: sender 4, ephemeral 8, encrypted_static 40, encrypted_timestamp 88, mac1 116, mac2 132 (total 148) | 8/40/88/116/132 | 8/40/88/116/132 | PASS |
| 19 | response offsets: sender 4, receiver 8, ephemeral 12, encrypted_nothing 44, mac1 60, mac2 76 (total 92) | 12/44/60/76 | 12/44/60/76 | PASS |
| 20 | cookie reply offsets: receiver 4, nonce 8 (24 B), encrypted_cookie 32 (16+16 B) (total 64) | 8/32 | 8/32 | PASS |
| 21 | transport offsets: receiver 4, counter 8, ciphertext 16 | 4/8/16 | 4/8/16 | PASS |
| 22 | `mac1` covers exactly `[0, len-32)`: kernel `len - sizeof(message_macs) + offsetof(mac1)` → 116 / 60 | 116 (init), 60 (resp) | 116 / 60 | PASS |
| 23 | `mac2` covers exactly `[0, len-16)`, i.e. **including mac1**: kernel `… + offsetof(mac2)` → 132 / 76 | 132 / 76 | 132 / 76 | PASS |
| 24 | wrong-coverage probes (`mac1` over 132 or 115, `mac2` over 116 or 148/60) | all different | all different | PASS |
| 25 | `mac1_key = BLAKE2s-256("mac1----" ‖ server_static_pub)` (kernel `precompute_key` with `mac1_key_label`) | `d5685476…ef12a3` for `spub[i]=(i*3+1)` | identical | PASS |
| 26 | `mac1 = BLAKE2s-128(key=mac1_key, msg[0:116))` known-answer | `b688b76e…f011f4` | identical | PASS |
| 27 | `mac2 = BLAKE2s-128(key=cookie, msg[0:132))` known-answer | `502a0161…d9b569` (with mac1 in place) | identical | PASS |
| 28 | response mac1/mac2 known-answers over 60 / 76 bytes | `4b6c1bed…10209a` / `323b95ef…ff3878` | identical | PASS |
| 29 | `cookie = BLAKE2s-128(secret, ip4 ‖ port_be)` — kernel `make_cookie`: 4 addr bytes then `udp_hdr->source` as `__be16` | `hashlib` | identical (ports 0/1/51820/65535/51821) | PASS |
| 30 | `cookie = BLAKE2s-128(secret, ip6 ‖ port_be)` — kernel: 16 addr bytes then the port | `hashlib` | identical (`331f0c31…cc3d21`) | PASS |
| 31 | IPv4 cookie **binds the source port** (finding W-1: the port used to be written at `buf[16]` while only `ip_len+2` bytes were hashed) | 4 distinct cookies for 4 ports | 4 distinct cookies; `cc89a9a4…` for 51820, `cac84086…` for 1 | PASS (fixed in `src/`) |
| 32 | empty address span hashes exactly `ip ‖ port_be` (2 bytes), not 2 zero bytes | `a44c109c…8df6a2` | `a44c109c…8df6a2` | PASS |
| 33 | label constants: `kMac1Label == "mac1----"`, `kCookieLabel == "cookie--"` (8 significant bytes each) | exact bytes | exact bytes | PASS (new test) |
| 34 | message sizes 148 / 92 / 64 / 16 / 32 (keepalive) | 148/92/64/16/32 | 148/92/64/16/32 | PASS |
| 35 | decode→encode round-trip is byte-identical for initiation, response, cookie reply, keepalive, 16-byte and 64-byte transport | identical | identical | PASS |
| 36 | strict decode: 3-byte datagram, 147-byte initiation, 149-byte initiation, unknown type 9, non-multiple-of-16 payload, counter ≥ `kRejectAfterMessages`, all-zero ephemeral | rejected | rejected | PASS |
| 37 | `encode(TransportData)` returns header+payload+tag but writes only header+payload (the 16 tag bytes are the AEAD's job) | documented | 16 tag bytes left untouched | INFO (W-2) |


### 3.4 Anti-replay window (`src/wire/replay_window.cpp`)

Reference: RFC 6479 §3 (`if ((sequence_number + replaywin_size) <
replaywin_lastseq) reject;`) and `wireguard-go` `replay/replay.go`
(`windowSize = (128-1)*64 = 8128`; `else if f.last-counter > windowSize {
return false }`). Both therefore **accept** a counter exactly 8128 behind the
highest accepted counter. 319 scenarios (19 hand-written + 300 randomised) were
replayed through both the real C++ and the model.

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 38 | in-order 0..999 accepted, `highest() == 999` | accept | accept | PASS |
| 39 | duplicates rejected, `highest()` does not move | reject | reject | PASS |
| 40 | out-of-order inside the window (1000, 990, 500, 1) | accept | accept | PASS |
| 41 | lag 8127 behind the head | accept | accept | PASS |
| 42 | lag 8129 behind the head | reject | reject | PASS |
| 43 | **lag exactly 8128 behind the head** | **accept** (RFC 6479 / wireguard-go / kernel) | **reject** | **FAIL (R-1)** |
| 44 | jump of 3 × 8192 forward: new counters accepted, everything old rejected | accept/reject | accept/reject | PASS |
| 45 | jump of exactly one ring (8192) clears every stale bit; the counter whose ring slot collides with an old one is fresh | accept | accept | PASS |
| 46 | partial wrap (100 → 164) keeps the bits in the words it did not pass | correct | correct | PASS |
| 47 | forward jump **within one 64-counter word** must not clear that word (else replays inside the current word are admitted) | bits kept | bits kept | PASS (new test) |
| 48 | `kRejectAfterMessages` and `UINT64_MAX` rejected | reject | reject | PASS |
| 49 | first-seen counter of any value (0, 1, 999, 123456789, 2^62, 2^63) accepted once, then rejected | accept, reject | accept, reject | PASS |
| 50 | `reset()` restores a virgin window (counter 0 accepted again) | accept | accept | PASS |
| 51 | 64-bit arithmetic near 2^63: `highest - counter` never wraps | no wrap | no wrap | PASS |
| 52 | model vs real C++ over all 319 scenarios | identical | identical | PASS |
| 53 | reference vs C++ divergences over all scenarios | 0 | 1 (row 43) | **FAIL (R-1)** |
| 54 | `kRejectAfterMessages` constant: `UINT64_MAX - (1<<13) - 1` | `2^64 - 2^13 - 1` (wireguard-go, and `docs/PROTOCOL.md:107`) | `2^64 - 2^13 - 2` (one lower) | INFO (R-2) |

### 3.5 Constant-time primitives (`src/crypto/ct.cpp`)

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 55 | `equal()` identical spans (incl. two empty spans) | true | true | PASS |
| 56 | `equal()` every single-bit flip, 32 bytes × 8 bits | false | false (256/256) | PASS |
| 57 | `equal()` length mismatch, and equal prefixes of different length | false | false | PASS |
| 58 | `equal()` zero-filled spans (the `(diff-1)>>31` fold) | true | true | PASS |
| 59 | `is_nonzero_u8()` for 0, 1, 2, 0x80, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF and every value 0..255 | 0x00 / 0xFF | correct | PASS |
| 60 | `cleanse()` wipes exactly the requested span; empty span is a no-op | span only | span only | PASS |
| 61 | `select(dst,a,b,true)` — contract says `dst = cond ? a : b` | `dst == a` | `dst == b` | **FAIL (C-1)** |
| 62 | `select(dst,a,b,false)` | `dst == b` | `dst == a` | **FAIL (C-1)** |
| 63 | `select()` never reads or writes outside `min(dst,a,b)` | no over-read/write | correct | PASS |

### 3.6 Build and test gates

| # | check | expected | observed | verdict |
|---|---|---|---|---|
| 64 | `vpn_core` (all 8 sources) compiles with `-std=c++20 -Wall -Wextra` | clean | clean, no warnings | PASS |
| 65 | unit suite (blake2s + wire + replay + ct + config + metrics) | all green | **71 tests, 0 assertion failures** | PASS |
| 66 | `-DVPN_ENABLE_KNOWN_BUG_TESTS=1` reproduces the open defects and nothing else | C-1 (2 tests), R-1 (1 test) fail; W-1 passes now that it is fixed | exactly that (5 assertions) | PASS (as designed) |
| 67 | `run_all_verifications.py --cxx <zig>` overall | red while a deviation is open | red, solely because of R-1 | PASS (as designed) |


## 4. Findings

### C-1 — `ct::select()` is inverted with respect to its documented contract (open, severity **low today / high when adopted**)

* Where: `include/vpn/crypto/ct.hpp:21-22` says `dst = cond ? a : b`;
  `src/crypto/ct.cpp:37` implements `dst = cond ? b : a`.
* Proof: `dst[i] = a[i] ^ (mask & (a[i] ^ b[i]))` with `mask = 0xFF` gives
  `a[i] ^ a[i] ^ b[i] == b[i]`. Reproduced by `test_ct.cpp:126-149`
  (`-DVPN_ENABLE_KNOWN_BUG_TESTS=1` → 2 tests, 4 assertions fail).
* Why it matters: nothing calls `ct::select()` today (a grep over `src/` and
  `include/` finds only `ct::cleanse` in `blake2s.cpp`), so no current behaviour
  is wrong. The moment it is used for its stated purpose — choosing between two
  secrets, or between a real and a dummy value — every caller silently gets the
  *opposite* operand. That is a wrong-key / wrong-plaintext bug with a timing
  story attached, which is the worst combination to inherit.
* Recommended patch (`src/crypto/ct.cpp:37`):
  ```cpp
  dst[i] = static_cast<Byte>(b[i] ^ static_cast<Byte>(mask & (a[i] ^ b[i])));
  ```
  (identical to the note already written in `test_ct.cpp:124`), then drop the
  `#if defined(VPN_ENABLE_KNOWN_BUG_TESTS)` guard around those two tests so they
  gate normally.
* Impact if shipped as-is: latent. No exploitable path exists in M0.

### R-1 — replay window is one counter narrower than RFC 6479 / WireGuard (open, severity **low**)

* Where: `src/wire/replay_window.cpp:34`
  `if (counter < highest_ && (highest_ - counter) >= kCounterWindowSize) return false;`
* Proof: RFC 6479 §3 rejects only when `lastseq > sequence_number +
  replaywin_size`, and `wireguard-go` `replay.Filter.ValidateCounter` rejects
  only when `last - counter > windowSize` (`windowSize = 8128`). Both therefore
  accept a counter exactly 8128 behind the head; this code rejects it. Verified
  independently (`verify_replay_window.py`, scenario `boundary_exactly_8128`:
  reference = accept, C++ = reject) and reproducible with
  `test_replay_window.cpp:205-211`.
* Why it matters: it is the *safe* direction — a replay can never be accepted
  because of it — so it is not a security bug. It is a conformance bug: one
  marginal counter value is dropped where every WireGuard peer would deliver it,
  and the M1 byte-diff/interop gate can trip on the boundary.
* Recommended patch (`src/wire/replay_window.cpp:34`): `>=` → `>`:
  ```cpp
  if (counter < highest_ && (highest_ - counter) > kCounterWindowSize) return false;
  ```
  After that, two existing assertions encode the old boundary and must be
  flipped with it (they describe *current behaviour*, not a contract):
  `test_replay_window.cpp:49-51` (`oldest_inside = 100000 - 8127`, then
  `!accept(100000 - 8128)` — the 8128 case must become the accepted one) and
  `test_replay_window.cpp:181`. The known-bug test at 205-211 then passes and
  should lose its guard.
* Impact if shipped as-is: a legitimate packet arriving exactly 8128 counters
  behind the head is dropped. Practically invisible (needs ~8 k reordering), and
  never a security regression.


### C-3 — `Blake2s`'s constructor does not bound the key length and overflows `buf_` (open, severity **low**, memory safety)

* Where: `src/crypto/blake2s.cpp:62` `std::memcpy(buf_, key.data(), key.size());`
  into `Byte buf_[kBlake2sBlockSize]` (`include/vpn/crypto/blake2s.hpp:48`, 64 B).
* Why it matters: the header documents "up to 32 bytes" as a precondition and
  says preconditions are enforced by the factory helpers — and the one-shot
  helpers do check (`blake2s.cpp:146`). But the class is public and
  stack-constructible, so a future streaming caller that passes a key slice of
  the wrong length (e.g. a 64-byte buffer instead of a 32-byte key) gets a stack
  buffer overflow on a crypto path. A silent overflow is a much worse failure
  mode than a refused digest.
* Recommended patch (defence in depth, no behaviour change for valid inputs):
  ```cpp
  const auto key_len = static_cast<std::uint32_t>(
      key.size() > kBlake2sMaxKey ? kBlake2sMaxKey : key.size());
  ...
  std::memcpy(buf_, key.data(), key_len);   // never more than 32 bytes
  ```
  plus an `assert(key.size() <= kBlake2sMaxKey)` in debug builds.
* Impact if shipped as-is: none today (no caller violates the precondition); a
  latent memory-safety foot-gun.

### R-2 — `kRejectAfterMessages` is one below `wireguard-go`'s (INFO)

* Where: `include/vpn/wire/constants.hpp:60-61`
  `UINT64_MAX - (1ULL << 13U) - 1ULL` = `2^64 - 2^13 - 2`.
* `wireguard-go` `device/constants.go` uses `(1 << 64) - (1 << 13) - 1`
  = `2^64 - 2^13 - 1` = `UINT64_MAX - (1 << 13)`, which is also what
  `docs/PROTOCOL.md:107` documents. The kernel differs again
  (`U64_MAX - COUNTER_WINDOW_SIZE - 1` = `2^64 - 8130`), so there is no single
  authority — but the code matches *neither*, and it differs from its own doc.
* Recommended patch: `UINT64_MAX - (1ULL << 13U)` (drop the trailing `- 1`).
* Impact: none reachable (a session rekeys at `2^60`). Cosmetic conformance.

### W-2 — `encode(TransportData)` leaves the 16 AEAD tag bytes unwritten (INFO, caller hazard)

* Where: `src/wire/message.cpp:134-143`; `total = header + payload + tag` is
  returned but only `header + payload` is written (the body comment says so).
* Risk: the first data-plane caller that trusts the return value and forgets to
  seal into `out + header + payload` puts 16 bytes of uninitialised caller
  buffer on the wire (information disclosure, not a crypto break).
* Recommended patch: zero those bytes in `encode()`
  (`std::memset(out.data() + kTransportHeaderSize + payload.size(), 0, kTransportTagSize)`,
  ~free at these sizes), or make the tag span an explicit out-parameter so a
  caller cannot forget it. Documenting the hazard in `message.hpp` is the
  minimum.


### W-1 — cookie ignored the source port for IPv4 peers (FIXED in `src/`, verified here; docs and one test are now stale)

* The fix is in place: `src/wire/message.cpp:173` writes the port at
  `buf + ip_len`, so the hashed span `ip_len + 2` really is `ip ‖ port_be` —
  exactly the kernel's `make_cookie` (4 or 16 address bytes, then the UDP source
  port as `__be16`). Verified against `hashlib` for IPv4 (4 ports), IPv6 and an
  empty address span, both in Python and end-to-end through the C++ driver.
* Still stale, please clean up:
  * `docs/PROTOCOL.md:49-82` ("Known defect in the M0 cookie derivation
    (blocking)") still describes the old code and the old symptom. It should
    become a "fixed and regression-tested" note.
  * `tests/unit/test_wire_message.cpp:508-535` is a `VPN_ENABLE_KNOWN_BUG_TESTS`
    block whose assertions now **pass**. This pass added always-on equivalents
    (`wire.cookie_for_ipv4_binds_the_source_port`,
    `wire.wire_labels_are_the_specification_bytes`), so the guarded block can be
    deleted or promoted out of the guard.
* Impact of the original defect (for the record): every IPv4 cookie was
  `BLAKE2s-128(secret, ip4 ‖ 0x0000)` — the same cookie for every source port of
  one address, i.e. a NAT-scoped proof of address rather than proof of address
  *and* port, weakening the rate limiter's binding.

### D-1 — the documentation over-states R-1 (INFO)

`docs/PROTOCOL.md:116` calls the replay deviation "blocking for interop". It
cannot block interop: our receiver is strictly stricter and no WireGuard peer can
observe the difference. Recommend "non-conforming, low severity" instead, so the
severity of a genuinely blocking item is not diluted.

### Previously reported findings that no longer reproduce

* **B-1** (`src/common/endpoint.cpp` did not compile: `make_error` undeclared,
  plus `ErrorCode:kInvalidArgument` / `kInvalidAument` typos): it compiles clean
  now — `zig c++ -std=c++20 -Wall -Wextra -c` succeeds and the full unit binary
  links it.
* **B-2** (`tests/unit/test_wire_message.cpp` did not compile): it compiles and
  passes now.

## 5. Files added / changed by this pass

Only `server/tests/` was touched. No `src/`, `include/` or `docs/` file was
modified. (`BLAKE2S_VERIFICATION.md` and `VERIFICATION_REPORT.md` already existed
from an earlier, interrupted pass; both were rewritten from scratch in this one
and every number in them was re-derived by the runs described above.)

Added / rewritten:

* `server/tests/golden/BLAKE2S_VERIFICATION.md` — rewritten as the BLAKE2s
  verification record: models, 560-case matrix, mandated digest tables (unkeyed
  and keyed, out 16/32, key 1/16/32), the 15/15 hard-coded-vector audit, and the
  generated per-case appendix.
* `server/tests/golden/VERIFICATION_REPORT.md` — this report.

Extended (existing files, nothing removed, no assertion weakened):

* `server/tests/golden/verify_blake2s.py` — new `audit_unit_test_vectors()`:
  re-derives **every** digest literal in `server/tests/unit/test_blake2s.cpp`
  from `hashlib` (2 RFC vectors + all 13 `kGolden` rows, each using its own
  quoted parameters) and adds a coverage check that fails if any digest literal
  in that file is not one `hashlib` produced. Summary line now reports 15/15.
* `server/tests/golden/verify_macs.py` — added the `cookie/empty-ip/port51820`
  case (degenerate address span must hash `ip ‖ port_be`, i.e. the 2 port bytes);
  replaced the stale "empty-IP deviation present" probe, which asserted the
  post-fix state from memory and printed a misleading `True`, with a comparison
  of the real C++ output against the reference.
* `server/tests/golden/check_new_replay_assertions.py` — replays the assertions
  of the new C++ replay test against the Python port (9 additional expectations).
* `server/tests/unit/test_blake2s.cpp` — two new tests:
  `final_refuses_a_short_output_buffer_and_can_be_retried` and
  `zero_length_output_is_refused` (API-contract edges that no vector reached).
* `server/tests/unit/test_wire_message.cpp` — two new always-on tests:
  `cookie_for_ipv4_binds_the_source_port` (hashlib known-answers `cc89a9a4…`,
  `cac84086…`; locks the W-1 fix in the default gate instead of behind
  `-DVPN_ENABLE_KNOWN_BUG_TESTS`) and `wire_labels_are_the_specification_bytes`
  (pins `"mac1----"` / `"cookie--"`, an interop constant with no other coverage);
  plus explicit `<string>` / `<string_view>` includes.
* `server/tests/unit/test_replay_window.cpp` — one new test:
  `forward_jump_inside_one_word_keeps_the_bits_already_set` (a forward jump must
  never clear the ring word it is standing on; clearing it would admit replays
  inside the current 64-counter word).

Unit suite: 66 tests before this pass, **71 after, 0 assertion failures**
(`zig c++ -std=c++20 -O1 -Wall -Wextra`, all of `vpn_core`).

## 6. What this pass did *not* establish

* No sanitizer run (ASan/UBSan unavailable here), so C-3 is a code-reading
  finding rather than a demonstrated crash.
* `ct::equal`, `ct::select` and the MAC comparisons are branch-free by
  inspection only; no timing measurements were taken, and there is no
  `-O2`-level disassembly review proving the compiler kept them branch-free.
* The handshake itself (Noise_IKpsk2, AEAD, XChaCha20-Poly1305 for the cookie
  reply) is not implemented in M0 and was therefore not verified; only the
  message framing and the MAC/cookie derivations that exist today.

