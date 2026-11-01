# Interoperability test (the gate that self-consistency cannot prove)

Status: **normative for any "WireGuard-compatible" claim**. Owner: server team.

## Why this document exists

Every unit test in this repository runs our own initiator against our own
responder. That proves the state machine is *self-consistent* — it cannot prove we
implemented the same protocol as everybody else. A shared misreading (a label, a
transcript ordering, a KDF step) would pass every test and fail every real client.

`scripts/interop-test.sh` closes that gap by driving the **official** WireGuard
client (`wg-quick` + `wireguard-tools`) against `vpn-dp`.

## Running it

Requirements: Linux, root, `wireguard-tools`, `iproute2`, `xxd`, `curl`.

```sh
cmake -S . -B out/build -DVPN_BUILD_DATAPLANE=ON
cmake --build out/build --parallel

sudo ./scripts/interop-test.sh
# or point it at another binary / port:
sudo VPN_DP=/usr/bin/vpn-dp PORT=51820 ./scripts/interop-test.sh
```

The script:

1. generates a server key pair with `vpn-dp --genkey` and a client key pair with
   `wg genkey | wg pubkey` (the official tool);
2. converts the client's base64 key to the hex form the config uses;
3. writes a `datad.toml`, starts `vpn-dp` on `127.0.0.1:51821` with a private TUN;
4. writes a `wg-quick` client config using the **base64** server key and brings it up;
5. waits up to 15 s for `latest-handshakes` to become non-zero;
6. pings `10.66.0.1` through the tunnel;
7. asserts the client counted transport bytes.

Exit code 0 = handshake + ICMP + transport all worked with the official client.
Anything else prints the server log and `wg show` output.

## What a pass proves, and what it does not

| Proves | Does not prove |
|---|---|
| Our Noise_IK transcript matches the reference (both directions) | Throughput (that is `docs/CAPACITY.md`, measured separately) |
| mac1/mac2 derivation is byte-correct | Roaming across NATs (needs two networks) |
| Transport framing, counters and replay window are compatible | Interop with the *kernel* module on the client side |
| Rekeying works (the client rekeys at 105 s; the script's keepalive forces traffic) | Behaviour under handshake floods |

## Current status: independently verified, official client pending

Two harnesses exist because two different things need proving:

| Harness | What it drives | Status |
|---|---|---|
| `scripts/interop-local.ps1` (Windows/CI, no TUN needed) | `scripts/interop_client.py` — a WireGuard implementation written from the spec **in Python, on a different crypto library** (`cryptography` for X25519/ChaCha20-Poly1305, `hashlib` for BLAKE2s) | **PASS** — see below |
| `scripts/interop-test.sh` (Linux, root) | the **official** `wg-quick` client | not yet run (needs a Linux host with `wireguard-tools`) |

Measured result of the independent harness:

```
client: handshake ok: local index 1847455516, remote index 2881985962
client: transport sent: 4 packets
server: peer interop-client established (local index 2881985962)
server: peer interop-client: first transport packet accepted (32 bytes inner)
PASS: independent implementation handshake + transport against vpn-dp
```

What that proves: our Noise_IK transcript, mac1 derivation, key schedule
(`KDF1/2/3`, the `tau` step) and transport AEAD agree with an implementation that
shares no code with ours. **That is the class of bug self-consistency cannot catch
— and it caught two real ones:**

1. `datad.toml` parsing never handled TOML arrays, so `allowed_ips = ["…/32"]`
   was rejected: the shipped sample config could not start the server at all.
2. The transport path requires the inner payload to be a 16-byte multiple
   (WireGuard pads); a 20-byte test packet was correctly dropped by the server.

What it does **not** prove: that our bytes are accepted by the *official* client
build (the Python implementation is independent of us, but it is still one
implementation). Run `sudo ./scripts/interop-test.sh` on any Linux box to close
that, and record the output in `docs/perf/interop-<date>.md`. Until then, docs say
"independently verified" rather than "compatible with the official client".

## If it fails

Work outward from the handshake, because each step has a distinct symptom:

| Symptom | Most likely cause |
|---|---|
| `wg-quick up` succeeds but `latest-handshakes` stays 0 | mac1 mismatch (label/`mac1----` bytes), or the responder static key in the transcript hash |
| Handshake completes, `ping` fails | allowed-ips / TUN address mismatch, or the inner routing table |
| Handshake flaky, works once then dies | rekey (KDF3 `tau` step) or the replay window boundary |
| `wg` reports "Invalid handshake initiation" | message length or field offsets |

Each of those maps to a section of `docs/PROTOCOL.md`, and every one of them is
covered by a unit test once the fix lands — a protocol fix without a test is not
accepted.
