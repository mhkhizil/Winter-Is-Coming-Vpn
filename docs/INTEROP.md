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

## Current status

**Not yet executed on real hardware.** The sandbox this project was developed in has
no Linux host, no `wireguard-tools` and no TUN device, so the claim remains
"WireGuard®-compatible — target, not yet verified" (see `docs/PROTOCOL.md` §7).

Run the script on any Linux box (a €4 VPS is enough) and record the output in
`docs/perf/interop-<date>.md`. Until that file exists, no document in this
repository may drop the "target, not verified" qualifier.

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
