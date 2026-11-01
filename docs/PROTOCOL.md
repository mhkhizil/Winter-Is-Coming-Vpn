# Wire protocol

Status: **normative** (wire v1.0, frozen at M1). Related: ADR-0002, ADR-0006.

We implement the WireGuard® protocol so that stock clients and stock `.conf`
files work on day one. We are not affiliated with the WireGuard project (see
`NOTICE`). There is no RFC: the normative source is Donenfeld's paper
*"WireGuard: Next Generation Kernel Network Tunnel"* plus the reference
implementations (`wireguard-go`, `boringtun`).

## 1. Message catalogue

All integers little-endian on the wire. `type` is a `u32`.

| Type | Message | Size | Layout |
|---|---|---|---|
| 1 | Handshake Initiation | **148** | `type(4) sender_index(4) ephemeral(32) encrypted_static(48) encrypted_timestamp(28) mac1(16) mac2(16)` |
| 2 | Handshake Response | **92** | `type(4) sender_index(4) receiver_index(4) ephemeral(32) encrypted_nothing(16) mac1(16) mac2(16)` |
| 3 | Cookie Reply | **64** | `type(4) receiver_index(4) nonce(24) encrypted_cookie(32)` |
| 4 | Transport Data | **32 + n** | `type(4) receiver_index(4) counter(8) payload(n) tag(16)`, `n` a multiple of 16 |

A **keepalive** is a Transport Data message with `n = 0` (32 bytes total). The
parser rejects any datagram whose type is unknown, whose length is not exact
for types 1–3, or whose transport payload is not a 16-byte multiple
(`vpn::wire::decode`). Implemented and unit-tested in M0.

## 2. Cryptographic primitives (fixed, no negotiation)

| Purpose | Algorithm |
|---|---|
| Diffie-Hellman | X25519 (RFC 7748) |
| Hash | BLAKE2s-256 (RFC 7693) |
| MAC | keyed BLAKE2s-128 |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 8-byte LE counter ‖ `00000000` nonce |
| Cookie encryption | XChaCha20-Poly1305 |
| KDF | HKDF with HMAC-BLAKE2s-256 (`KDF1`/`KDF2`/`KDF3`) |

There is **no cipher negotiation**, by design: there is no downgrade surface.
Agility, when it arrives (post-quantum PSK), is expressed *outside* the message
format — see §6.

`mac1 = keyed-BLAKE2s-128( BLAKE2s-256("mac1----" ‖ server_static_pub ), msg_before_mac1)`
`mac2 = keyed-BLAKE2s-128( cookie, msg_before_mac2 )`

Both are implemented in M0 (`vpn::wire::compute_mac1/compute_mac2`) with the
label derivation in `mac1_key()`, so the interop test at M1 only has to prove
the handshake transcript, not the plumbing.

### 2.1 Known defect in the M0 cookie derivation (blocking)

`compute_cookie(secret, source_ip, source_port)` is specified as
`keyed-BLAKE2s-128(secret, source_ip_bytes ‖ source_port_be)` — the cookie must
bind both address *and* port, or a cookie obtained from one source port can be
replayed from another behind the same NAT address.

The implementation does not do that for IPv4:

```cpp
Byte buf[18] = {};
/* ip at 0..ip_len-1 */
store_be16(buf + 16, source_port);                       // port at 16..17
return crypto::blake2s_128(ByteSpan{buf, ip_len + 2}, …); // ...but only 0..5 hashed
```

For `ip_len == 4` the hashed span is `buf[0..5]` = IPv4 address ‖ `0x0000`, so
the port is **never an input**; two cookies for ports 51820 and 51821 are
byte-identical. For IPv6 (`ip_len == 16`) the span is `buf[0..17]` and the port
*is* included, so the function is also internally inconsistent between address
families.

Consequences:

* `vpn_unit_tests` is red — `test_wire_message.cpp`, case
  `cookie_is_bound_to_address_and_port`, asserts exactly the property that is
  missing.
* The M1 interop gate cannot pass while the cookie differs from the reference
  implementation.
* Do **not** build a DoS-mitigation design on the cookie path until this is
  fixed and tested for both families.

Owner: crypto owner. Fix: lay the address and port out contiguously (e.g. hash
`address ‖ port` with a length that depends on the family) and keep the test.

## 3. Handshake (Noise_IKpsk2)

```
Initiator                                                      Responder (us)
  │ ── msg1: e_i, es, s_i ─────────────────────────────────────▶│  verify mac1
  │                                                            │  (under load) mac2/cookie
  │                                                            │  3x DH: es, ss, se
  │ ◀──────────────────────────── msg2: e_r, ee, se, psk ───────│
  │  verify mac1, 3x DH                                          │
  │ ── msg3: empty transport (confirmation) ───────────────────▶│  first transport proves keys
```

* `encrypted_static` hides the initiator's public key until the responder can
  decrypt it, so passive observers cannot enumerate peers.
* `encrypted_timestamp` carries TAI64N. **We treat it as a per-peer monotonic
  sequence number**, never as wall-clock truth: comparing it to our clock would
  allow a peer with a skewed clock to be locked out, and would leak our clock.
* The `psk` step is where a post-quantum secret will be injected (§6).

## 4. Transport, counters and replay

* Each direction has its own 64-bit counter; the keypair is unusable beyond
  `2^60` messages (`kRekeyAfterMessages`) and hard-rejected at
  `2^64 - 2^13 - 1` (`kRejectAfterMessages`).
* Replay protection: 8192-bit ring bitmap, **8128-bit window per RFC 6479 — but
  the implementation's usable window is 8127** (`vpn::wire::ReplayWindow`,
  unit-tested in M0). See §4.1. The window is updated **only after AEAD
  authentication succeeds**, so forged packets cannot poison it.
* Roaming: the peer's source endpoint is updated only when a packet authenticates
  *and* carries a fresh counter. A replayed packet can never hijack a session's
  endpoint.

### 4.1 Window boundary (M0: fixed and pinned by a test)

RFC 6479 (and `wireguard-go`) reject a counter only when
`highest - counter > windowSize`, so a counter exactly 8128 behind the highest
accepted counter is **still accepted**. `server/src/wire/replay_window.cpp` tests
`>` and the boundary is asserted unconditionally by
`replay.boundary_at_exactly_the_window_size`, so a regression fails the default
gate rather than hiding behind a define. The usable window is therefore 8128
counters, matching every WireGuard peer.

### 4.2 Lesson: no disabled failing assertions

This repository briefly carried "KNOWN-BUG" tests that were compiled out behind a
`-DVPN_ENABLE_KNOWN_BUG_TESTS` define that no build actually set. That pattern is
banned: a failing assertion that is disabled by default is not a test, and "CI is
green" then means less than it appears to. The defects those blocks described
(cookie port binding, replay boundary, inverted `ct::select`) have been fixed and
their assertions are now always on.
leave the test enabled-but-`xfail`-marked by an explicit, reviewed mechanism.

## 5. Timers

| Timer | Value | Notes |
|---|---|---|
| `REKEY_AFTER_TIME` | 120 s | initiator rekeys at 105 s (120 − 10 − 5) |
| `REJECT_AFTER_TIME` | 180 s | no packets after this |
| `REKEY_TIMEOUT` | 5 s | + 0–334 ms jitter, max 18 attempts / 90 s |
| `KEEPALIVE_TIMEOUT` | 10 s | server sends keepalive after 10 s of silence |
| client `PersistentKeepalive` | 25 s default | mobile default; 0 disables |
| cookie secret rotation | 120 s | two secrets live simultaneously (seqlock) |
| keypair wipe | 540 s | three reject periods, then zeroize |

## 6. Post-quantum agility (designed now, shipped later)

The `psk` slot is the only extendable secret. We derive it as

```
psk = HKDF-BLAKE2s( ss_mlkem768 ‖ ss_x25519, salt=transcript, info="vpnd-psk-v1" ‖ tenant ‖ peer_pub )
```

when both sides advertise ML-KEM-768 support via the control plane. The wire
format is untouched, so official clients keep working whenever PQ is off.
`.conf` extensions are expressed as magic comments (`#!vpnd:v=1;pq=...`);
`[Interface]`/`[Peer]` unknown keys would be a parse error in every client, so we
never put them there.

## 7. Acceptance gates before "compatible" may be claimed

Blocking, in this order:
1. RFC 7693 / 7748 / 8439 test vectors — **only the BLAKE2s-256 part is green in
   M0** (RFC 7693 Appendix B, "abc" and empty). X25519 and ChaCha20-Poly1305 are
   not implemented, and the MAC/cookie derivation has the defect in §2.1.
2. Deterministic byte-diff of all four message types against `wireguard-go` for a
   fixed seed.
3. 200/200 live interop runs: `wg`/`wg-quick`, `wireguard-go`, `boringtun`,
   wireguard-android emulator, WireGuardKit simulator.
4. Replay, roaming, forced under-load cookie flow, 1 s revocation, 10k-peer
   restart.
5. Fuzz `msg_initiation`, `msg_response`, `msg_cookie`, `msg_transport`,
   `conf_parse` under ASan/UBSan/MSan for 24 h clean.

Until gate 3 passes, every document in this repo must say
"WireGuard®-compatible — **target**, not yet verified".
