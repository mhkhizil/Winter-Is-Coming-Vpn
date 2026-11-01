# Security policy

> **M0 status: this software is pre-alpha and must not be exposed to the
> internet.** It has no TLS, no authentication, and a known protocol defect
> (`docs/PROTOCOL.md` §2.1). "Supported versions" below refers to the policy that
> will apply from v1.0, not to a currently supported product.

## Reporting a vulnerability

**Do not open a public issue.** Email `security@example.invalid` with:

* affected component (`vpnd`, `vpn-dp`, `vpn_core`, deploy manifests),
* version or git SHA,
* a reproducer, and the impact you believe it has.

> ⚠️ `example.invalid` is a placeholder in the reserved `.invalid` TLD — it can
> never receive mail, and RFC 2606 guarantees it will never resolve. **There is
> currently no working disclosure channel.** This must be replaced with a real,
> monitored address (plus a PGP key fingerprint) before this repository is made
> public or any release is tagged. Tracked as a release blocker.

Because the channel does not exist yet, the acknowledgement and triage targets
below are *intentions*, not commitments anyone is currently able to meet:

You will get an acknowledgement within **48 hours** and a triage decision within
**5 business days**. We will credit you in the release notes unless you ask
otherwise. We do not currently run a paid bounty programme.

## Supported versions

| Version | Supported |
|---|---|
| `main` (pre-1.0) | yes — fixes land on `main` |
| `1.x` | from v1.0: latest minor + previous minor |
| older | no |

## What we already defend against

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The short version, with the
honest scope of each item in M0:

* Client private keys never reach the server (ADR-0007) — **enforced by the schema
  now**: `server/migrations/0001_init.sql` has no column that could hold one, and
  a CI grep backs it up. No server-side code exists to violate it yet.
* No per-connection logs by default; aggregate counters only — **true of the code
  that exists**. `vpnd` logs only startup/shutdown lines.
* Constant-time comparisons for all secret-dependent checks (`vpn::ct::equal`) —
  the primitive exists and is tested; **there are no secret-dependent checks in
  M0**, so this is a rule for M1+ rather than a current property.
* Strict wire parsing (exact sizes, no trailing bytes) — **true and tested**
  (`vpn::wire::decode` rejects wrong sizes, unknown types and non-16-byte-multiple
  transport payloads).
* Hardened systemd unit and a distroless/scratch container for the data plane —
  **files exist, binaries do not**. `vpn-datad` is M2 and its unit is currently
  mis-specified (`Type=notify` with no `sd_notify`). The hardened unit you can
  actually run today is `deploy/systemd/vpnd.service`.

## Known, accepted limitations (not vulnerabilities)

1. **Traffic analysis.** We do not pad or obfuscate; an observer sees IPs, sizes
   and timing.
2. **Compromised client device.** A rooted/jailbroken device can read its own
   tunnel.
3. **Static X25519 is not post-quantum.** Hybrid PSK is designed (ADR-0006) but
   not shipped.
4. **Operator compulsion.** No-logs is architectural, not a legal shield.
5. **`server` key mode** (`POST /peers` with `key_mode=server`) hands a private key
   over the wire once, by design, for legacy imports. It is rate-limited, audited
   and disabled for store builds.

## Hardening checklist for operators

Scope: `vpnd` (the control plane) is the only component that exists. The
data-plane lines below are tagged `[M2]` and cannot be run yet.

```sh
# Control plane (available now)
systemd-analyze security vpnd             # hardened unit: deploy/systemd/vpnd.service
ss -ltnp | grep -E '8080|9100'            # expect ONLY 8080; 9100 is never bound
vpnd --print-config --config /etc/vpn/vpnd.toml | grep -E 'admin_token|key_file'  # secrets masked

# Data plane (M2 — these commands fail today: no vpn-datad binary, no deb)
systemd-analyze security vpn-datad        # [M2] expect < 2.0
ss -lunp | grep 51820                      # [M2] only the data plane listens on UDP
journalctl -u vpn-datad | grep -i 'key'   # [M2] must output nothing
```

Rotate node keys at least every 90 days (`vpnctl node rotate-key` — **[M3]**, the
CLI does not exist yet), keep PostgreSQL off the public internet, and never enable
`VPN_DEV_MODE` outside development. That last rule *is* enforced:
`vpn::config::validate` refuses to start when `environment = "production"` and
`dev_mode = true` (`server/src/config/config.cpp:182-184`).

**Known hole to be aware of:** `validate()` accepting a production config means
very little right now — it does not check `admin_token`, does not open the TLS
files, and nothing implements TLS. A "valid" production config is served as
plaintext HTTP with no authentication.
