# ADR-0008 — Two binaries, gRPC/mTLS between them, level-triggered reconciliation

* Status: accepted
* Date: 2026-11-01
* Deciders: server team

## Context
Options for CP↔DP: a shared database (the DP polls Postgres), a unix-socket
protobuf protocol, an HTTP API, or gRPC with mTLS. Nodes may be remote and behind
NAT; the control plane may be a fleet of pods.

## Decision
* **gRPC over mTLS**, always **agent-initiated** (the node dials out, so it works
  behind NAT and needs no inbound firewall hole besides UDP/51820).
* Short-lived SVIDs (24 h) with URI SAN `spiffe://vpn.internal/node/{server_id}`,
  rotated by the agent using a bootstrap token stored in the TPM.
* **Level-triggered reconciliation**: `Watch` streams a full immutable
  `DesiredState{generation, sha256, peers[], policy}`; the agent applies, fsyncs
  `state.json`, then `Ack{generation}`.
* A unix-domain socket transport is used only when CP and DP are co-located (dev).
* Netlink is internal to the DP and never crosses a process boundary.

## Why not the alternatives
* **Shared database** — the DP would need DB credentials; a compromised data plane
  (internet-facing, parses untrusted packets) would expose the whole tenant model.
  Also couples schema migrations to data-plane releases.
* **HTTP/JSON polling** — no server push, no schema, no streaming, and polling
  either wastes CPU or adds config lag.
* **Unix socket only** — cannot reach remote nodes.

## Consequences
* gRPC/protobuf is a dependency for both binaries (M3), plus BoringSSL for mTLS.
* Reconciliation is idempotent and self-healing: an agent restart re-applies the
  last snapshot and converges without special-casing.
* Rollback = a *new higher* generation with old content; the agent rejects
  `generation <= applied`, so a replayed old snapshot cannot resurrect revoked peers.
* Split-brain is fenced by a 30 s lease with 10 s renewal; a second agent for the
  same node receives `Shutdown` on its stream.
* If the CP is unreachable, the DP **fails static** for 7 days: existing peers keep
  working, no new peers are admitted.
