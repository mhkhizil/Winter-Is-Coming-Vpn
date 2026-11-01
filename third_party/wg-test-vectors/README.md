# third_party/wg-test-vectors

Fixtures for the M1 interoperability gate. **Nothing in this directory is linked
into the server**; it exists so that a protocol change cannot silently break
compatibility with the reference implementations.

## What will live here

| Path | Contents | Source | License |
|---|---|---|---|
| `wireguard-go/` | deterministic handshake transcripts for a fixed seed | `wireguard-go` (MIT) | MIT |
| `boringtun/` | same, for cross-checking | `boringtun` (BSD-3) | BSD-3 |
| `rfc/` | RFC 7693 / 7748 / 8439 vectors in a machine-readable form | IETF | public |
| `conf/` | `wg-quick` configs used by the interop harness | ours | Apache-2.0 |

## Rules

1. Vectors are **generated, not hand-edited**; each directory contains the
   generator script and the exact commit SHA used.
2. Any file derived from a GPL-licensed project (e.g. `wireguard-tools`) is
   **forbidden** here — it would drag GPL into this repository. The harness may
   *invoke* `wg`/`wg-quick` as separate processes in a container, which does not
   create a derivative work.
3. A vector may only be replaced with a new one in a dedicated commit, so that a
   protocol regression is never masked by regenerating fixtures in the same PR.
