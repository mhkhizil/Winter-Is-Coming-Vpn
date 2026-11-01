# ADR-0006 — Post-quantum readiness via the PSK slot (Rosenpass-style)

* Status: accepted (design only; implementation scheduled post-v1)
* Date: 2026-11-01
* Deciders: crypto owner

## Context
WireGuard's static-static X25519 exchange is not post-quantum secure. We cannot
change the message layouts without breaking every official client (ADR-0002), but
we must not paint ourselves into a corner either.

## Decision
WireGuard's optional **preshared key (PSK)** slot is our agility point.
* A hybrid secret is computed out of band (Rosenpass-style, or directly when the
  client supports ML-KEM-768):
  `psk = HKDF-BLAKE2s(ss_mlkem768 ‖ ss_x25519, salt=transcript, info="vpnd-psk-v1" ‖ tenant ‖ peer_pub)`.
* The wire format is untouched. Official clients that do not support PQ keep
  working with `psk = null`; the control plane records the negotiated capability.
* Schema support exists from day 1: `peers.psk_source
  ENUM('static','hybrid_mlkem768_x25519','rosenpass')` and `peers.psk_epoch`.
* PSK rollover uses dual-accept (`{current, next}`) so a rotation never drops a
  tunnel; the promotion window is 180 s.
* `.conf` extensions are expressed **only** as magic comments
  (`#!vpnd:v=1;pq=...`), because unknown `[Interface]`/`[Peer]` keys are a hard
  parse error in every existing client.

## Consequences
* We do not overstate security: the static server identity is still X25519 until a
  PQ signature scheme is adopted at the control-plane layer (future ADR).
* PSK rotation costs one extra AEAD open during the overlap window.
* Supporting PQ requires client work; the Android/iOS contract already carries the
  fields, so no API break is needed later.

## Alternatives rejected
* **Custom PQ handshake message** — breaks compatibility, i.e. defeats ADR-0002.
* **Claim PQ by adding ML-KEM to the static key** — impossible without changing
  the Noise pattern.
