> **Repository split (2026-11-02).** The Android client is no longer in this
> repository: it lives at
> **[mhkhizil/VPN-Fe-Android](https://github.com/mhkhizil/VPN-Fe-Android)** and is
> built from its own CI. Where this document says "Android (`android/`)", read "the
> separate Android repository"; the contract below is unchanged and is still the
> server's promise to it. `ios/` in this repository is still a placeholder.
> The client repo has `app/src/test/.../PeerConfigParserTest.kt`, which fails when
> the `POST /api/v1/peers` payload below changes — that test is the contract's
> enforcement mechanism, not this prose.


# Client integration contract (Android / iOS)

Status: **draft-1**. Android (`android/`) and iOS (`ios/`) are **folder
placeholders only** — this document is what those implementations will be built
against, so the server team cannot change the contract unilaterally.

## 1. Key generation (non-negotiable)

| Mode | Who generates the private key | Used for |
|---|---|---|
| `device` **(required for store builds)** | the client: Android `KeyPair` in Keystore, iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, X25519 scalar wrapped by the platform key | production |
| `server` | the server, once, in RAM, returned in a single `.conf` and immediately wiped | imports/legacy clients only — audited, 5/hour/device, 60 s TTL |

The server never stores a client private key (ADR-0008). Only the **public** key
is uploaded.

## 2. Config payload (returned by `POST /api/v1/peers`)

```json
{
  "peer_id": "pe_01H...",
  "server": { "id": "srv_fra_01", "endpoint": "fra-01.vpn.example:51820",
              "public_key": "base64", "key_id": "k_2026_11" },
  "interface": {
    "addresses": ["10.64.12.37/32", "fd00:64:12::37/128"],
    "dns": ["10.64.0.1", "fd00:64::1"],
    "mtu": 1420,
    "private_key": null,
    "listen_port": 0
  },
  "peer": {
    "public_key": "base64",
    "preshared_key": null,
    "persistent_keepalive_secs": 25,
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "excluded_ips": ["192.168.0.0/16", "fd00:64::/48"]
  },
  "routing": {
    "mode": "full_tunnel",
    "included_routes": ["0.0.0.0/0", "::/0"],
    "excluded_routes": ["192.168.0.0/16"],
    "included_apps": [],
    "excluded_apps": [],
    "allow_lan": false,
    "ipv6_mode": "dual"
  },
  "policy": {
    "session_ttl_secs": 86400,
    "max_session_bytes": null,
    "bandwidth_kbps": { "up": 0, "down": 0 },
    "blocked_dest_ports": [25, 465, 587, 445],
    "dns_filter_profile": "default",
    "kill_switch": true,
    "captive_portal_probe_url": "http://connectivitycheck.gstatic.com/generate_204"
  },
  "on_demand": {
    "enabled": false,
    "rules": [{ "action": "connect", "interface_types": ["cellular"], "ssid_match": null }],
    "trusted_ssids": []
  },
  "server_keys": [{ "key_id": "k_2026_11", "public_key": "base64", "state": "primary",
                    "retire_at": null }],
  "signature": { "alg": "ed25519", "key_id": "cp_sig_1", "value": "base64" }
}
```

Rules:
* Clients **must** verify `signature` against a pinned Ed25519 key delivered in
  `/.well-known/vpn-bootstrap.json` and **must** reject a payload whose
  `server.public_key` is not in `server_keys`.
* `included_apps`/`excluded_apps` are Android-only; iOS has no per-app exclusion
  in `NEPacketTunnelProvider` — the server must not offer it to iOS clients.
* Unknown fields are ignored (forward compatibility); unknown enum values are an
  error (`config_unsupported`).

## 3. Endpoints the clients call

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/vpn-bootstrap.json` | `api_base_urls`, `spki_sha256_pins`, `min_client_version`, attestation config |
| POST | `/api/v1/auth/token` | login/refresh (device-bound refresh token) |
| POST | `/api/v1/devices` | register install + attestation result |
| PUT | `/api/v1/devices/{id}/key` | upload the **public** key |
| GET | `/api/v1/regions`, `/api/v1/servers` | catalog + `load_hint` |
| POST | `/api/v1/peers` | create/reuse a peer, returns the config payload above |
| POST | `/api/v1/peers/{id}/rotate-keys` | rekey |
| GET | `/api/v1/peers/{id}/usage` | bytes used vs quota |
| DELETE | `/api/v1/peers/{id}` | remote wipe |
| POST | `/api/v1/telemetry/batches` | batched, aggregate-only counters |

## 4. Platform mapping

| Concern | Android (Kotlin) | iOS (Swift) |
|---|---|---|
| Tunnel API | `VpnService` + `Builder.addAddress/addRoute/addDnsServer/setMtu` | `NEPacketTunnelProvider` + `NEPacketTunnelNetworkSettings` |
| Roaming | `setUnderlyingNetworks(null)` on network change | `setTunnelNetworkSettings` re-apply |
| Split tunnel | `addAllowedApplication`/`addDisallowedApplication` | route-based only |
| Kill switch | `setBlocking(true)` + on-demand always-on | `NEOnDemandRule` + `includeAllNetworks` |
| Key storage | `AndroidKeyStore` (wrap the X25519 scalar) | Keychain, `ThisDeviceOnly` |
| Attestation | Play Integrity (`PLAY_RECOGNIZED`, `MEETS_DEVICE_INTEGRITY`) | App Attest + DeviceCheck |
| WireGuard core | official `wireguard-android` library **or** Rust `boringtun` via UniFFI | `WireGuardKit` **or** `boringtun` via UniFFI |

## 5. Reconnect behaviour (both platforms)

* keepalive 25 s; consider the tunnel dead after 75 s of silence or 180 s without
  a completed handshake.
* Backoff ladder 1-2-4-8-16-30 s ±20 % jitter; on the 2nd failure try
  `server_endpoints` alternates.
* `resume_token` (15 min) allows resuming a session on another node without a
  new enrollment.
* On `state: draining` the client performs make-before-break within 30 s, so a
  node drain never produces a user-visible outage.

## 6. Error model (RFC 9457 `application/problem+json`)

`unauthenticated`, `token_expired`, `device_revoked`, `quota_exceeded`,
`node_at_capacity`, `session_exists`, `resume_expired`, `config_unsupported`,
`rate_limited`, `tenant_suspended` — plus `status`, `detail`, `instance`.
