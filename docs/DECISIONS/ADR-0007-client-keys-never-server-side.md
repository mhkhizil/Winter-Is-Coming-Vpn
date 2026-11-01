# ADR-0007 — Client private keys never reach the server

* Status: accepted
* Date: 2026-11-01
* Deciders: security owner, product

## Context
The easiest enrollment UX is "server generates a keypair and hands you a `.conf`".
It is also the easiest way to lose every customer's identity in one database
breach, and it makes the server an attractive target and a liability in court.

## Decision
1. **Default and store-build-required**: the client generates its X25519 keypair
   on-device and uploads only the public key
   (`PUT /api/v1/devices/{id}/key`).
2. The `server` key-generation mode exists **only** for imports/legacy clients:
   the private key is generated in RAM, returned exactly once in the `.conf`, and
   the buffer is zeroized immediately. It is audited, rate-limited (5/hour/device)
   and the response has a 60 s TTL.
3. The database has **no column** that can hold a client private key. A CI grep
   gate fails the build if any code path writes one (`private_key`, `psk` writes
   outside the audited module are rejected in review).

## Consequences
* Worse "email me a config" UX; enrollment goes through the app or a QR code.
* A breach of our database does not yield any client identity.
* Support cannot "reset" a device by re-issuing the same config; the user
  re-enrolls. This is the correct trade.
* Key rotation is client-initiated (`POST /peers/{id}/rotate-keys`), which also
  means the client must implement rotation — part of the client contract.

## Alternatives rejected
* **Server-held keys with envelope encryption** — still yields all keys to an
  attacker with KMS access, and we would have to defend that in discovery.
* **Hybrid (server key for old clients)** — this *is* the `server` mode above,
  constrained and audited rather than default.
