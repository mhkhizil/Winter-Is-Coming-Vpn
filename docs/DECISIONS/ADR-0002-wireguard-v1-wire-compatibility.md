# ADR-0002 — WireGuard-compatible protocol (not a custom design)

* Status: accepted
* Date: 2026-11-01
* Deciders: server team, crypto owner

## Context
We need a VPN protocol for a consumer + B2B product with Android and iOS clients.
Options: a custom Noise-based protocol, OpenVPN-style TLS, IKEv2/IPsec, QUIC +
MASQUE `CONNECT-UDP`, or WireGuard compatibility.

## Decision
Implement **WireGuard-compatible** framing and handshake in our own userspace
server. We claim compatibility only after the M1 interop gate (200/200 vs
`wireguard-go`, plus the official clients). `NOTICE` carries the trademark
attribution; no binary is named `wg*`.

## Why
* Stock `.conf` files and QR codes import into every existing client on day one.
* The crypto surface is tiny and fixed (X25519, ChaCha20-Poly1305, BLAKE2s) with
  no cipher negotiation, hence no downgrade path.
* Roaming is free: sessions are keyed by index, not by address/port.
* Audited implementations exist for clients (`wireguard-android`, `WireGuardKit`,
  Rust `boringtun` BSD-3) so we do not have to write client crypto.
* A custom protocol would need its own audit, its own client libraries and its own
  years of interop debugging; we would be inventing a liability.

## Consequences
* We must not extend the wire format. Post-quantum support goes into the existing
  PSK slot (ADR-0006) and into control-plane flags, never into message layouts.
* The kernel's GPL-2.0 `wireguard.ko` is unusable as a shipping backend for a
  proprietary product; we use it only as a reference/benchmark.
* "WireGuard®" is a registered trademark: always "WireGuard®-compatible".

## Alternatives rejected
* **Custom Noise protocol** — no clients, no audit, no interop, no upside.
* **IKEv2/IPsec** — GPLv2 stacks dominate Linux, iOS has no PSK-based IKEv2
  client path that fits our enrollment flow.
* **QUIC + MASQUE** — promising for censorship resistance but adds a second
  crypto stack and a second client integration; kept as a v2 option (outer
  transport), not the v1 protocol.
