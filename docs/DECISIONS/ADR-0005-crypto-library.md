# ADR-0005 — One crypto provider: BoringSSL (no libsodium, no OpenSSL)

* Status: accepted
* Date: 2026-11-01
* Deciders: crypto owner, server team
* Supersedes: an earlier proposal to use libsodium for the data plane and
  OpenSSL 3 for the control plane.

## Context
We need: X25519, ChaCha20-Poly1305 (IETF), BLAKE2s + keyed BLAKE2s-128, TLS 1.3
for the API, mTLS for node agents, and eventually ML-KEM-768 for the hybrid PSK.
Two crypto stacks mean two sets of CVE feeds, two FIPS stories and two bug classes.

## Decision
**BoringSSL**, pinned to a commit and statically linked, for the whole server.
`vpn_core` implements **BLAKE2s itself** (`server/src/crypto/blake2s.cpp`) because
neither BoringSSL's EVP nor libsodium exposes *keyed BLAKE2s-128*.

## Why BoringSSL wins here
* It is the only one of the three that gives us X25519 + AEAD + TLS + ML-KEM
  behind a single, audited, fuzz-covered API, and it is gRPC's default provider
  (no second TLS stack in the process).
* `EVP_aead_chacha20_poly1305_seal_scatter / open_scatter` supports our in-place,
  scatter/gather packet path without an extra copy.
* Static linking removes the "no stable ABI" objection entirely: nothing outside
  the binary links against it.

## Consequences
* No distro package: BoringSSL is built from source (vcpkg with a pinned commit,
  `tools/deps.lock` records the SHA). Cold build cost is paid once by the cache.
* deb/rpm packages statically embed it; the SBOM lists the commit and the
  `LICENSE` file ships in `/usr/share/doc/vpn-datapath/`.
* We must track BoringSSL security advisories ourselves (calendar reminder +
  `deps-bump.yml` job opening a PR monthly).
* Keyed BLAKE2s-128 is our code, so it carries our test and fuzz burden: RFC 7693
  vectors are already green in M0, differential fuzzing against the reference
  implementation is an M1 gate.

## Alternatives rejected
* **libsodium + OpenSSL 3** — two stacks, both with their own TLS story; libsodium
  has no BLAKE2s at all (only BLAKE2b), so a third implementation was needed anyway.
* **OpenSSL 3 only** — heavier API for the scatter/gather AEAD path, and its
  provider architecture complicates static linking; still a viable fallback if
  BoringSSL's build ever becomes impractical.
* **Rust `boringtun` core via FFI** — kept as *schedule insurance*: if the M1 gate
  slips more than 6 weeks we ship `boringtun` (BSD-3) behind the same
  `vpn::wire` interface rather than missing the release.
