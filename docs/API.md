# Control-plane API

Status: **partially implemented.** The endpoints marked ✅ in §0.1 are live in
`vpnd` and were verified against the real binary; the rest are specified for the
next increment. Machine-readable spec: [`api/openapi.yaml`](api/openapi.yaml).

Base path `/api/v1`. Transport: **HTTPS terminated by a proxy** (this binary has no
TLS library; see `docs/DEPLOYMENT.md`). Auth: `Authorization: Bearer <opaque token>`.

## 0. Authentication carriers (implemented)

The router accepts the token in three places, in this order:

1. `Authorization: Bearer <token>` — standard, used by the mobile clients
2. JSON body field `{"access_token":"..."}` — clients that cannot set headers
3. query parameter `?token=<token>` — deep links

Tokens are opaque 256-bit values stored as `HMAC-BLAKE2s-256(pepper, token)`, so a
store leak cannot be replayed. TTL 3600 s (`RouterOptions::token_ttl_seconds`).

## 0.1 Implemented endpoints ✅

| Method | Path | Behaviour |
|---|---|---|
| POST | `/api/v1/auth/login` | `{email,password}` → `{access_token,token_type,expires_in,user_id}`; password hashes compared in constant time |
| POST | `/api/v1/auth/logout` | revokes the presented token |
| GET | `/api/v1/me` | `{user_id,tenant_id,role}` |
| POST | `/api/v1/devices` | 201 `{id,name,platform}` |
| GET | `/api/v1/devices` | caller's devices |
| PUT | `/api/v1/devices/{id}/key` | 204; accepts **only** a 64-hex public key (ADR-0007) |
| POST | `/api/v1/peers` | 201; allocates `10.66.0.N/32` + `fd00:66::N/128` |
| GET | `/api/v1/peers` | list, including `revoked` tombstones |
| GET | `/api/v1/peers/{id}` | single peer |
| GET | `/api/v1/peers/{id}/config` | `text/plain` wg-quick file (base64 server key, no private key) |
| DELETE | `/api/v1/peers/{id}` | 204; peer becomes `revoked` (tombstoned) |
| GET | `/api/v1/servers` | node catalog |
| POST | `/api/v1/nodes` | register a data-plane node (operator) |

Rate limit: per-IP token bucket, 20 rps / burst 40 → `429 rate_limited`.
Errors: RFC 9457 `application/problem+json` with a stable `code`.

## 1. Conventions

| Concern | Rule |
|---|---|
| Errors | RFC 9457 `application/problem+json`: `type`, `title`, `status`, `detail`, `instance`, plus `code` |
| Pagination | cursor: `?limit=50&cursor=...` → `{"data":[...],"next_cursor":"..."}` |
| Idempotency | `Idempotency-Key` required on all `POST` that create/mint; stored 24 h |
| Versioning | additive only within `v1`; breaking changes need `v2` + 6-month overlap |
| Timestamps | RFC 3339 UTC, millisecond precision |
| IDs | prefixed ULIDs (`ten_`, `usr_`, `dev_`, `pe_`, `srv_`) — never integers |
| Rate limits | `429` + `RateLimit-*` headers; per-token buckets |
| Correlation | `X-Request-Id` echoed, `traceparent` propagated |

## 2. Authentication

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | email + password (Argon2id, zxcvbn ≥3, HIBP range check) |
| POST | `/auth/email/verify`, `/auth/email/resend` | 24 h token |
| POST | `/auth/login` | returns access (600 s) + refresh (opaque, rotating) |
| POST | `/auth/refresh` | refresh-token rotation with family-reuse detection |
| POST | `/auth/logout`, `/auth/logout-all` | revokes the family / all sessions |
| POST | `/auth/password/forgot`, `/auth/password/reset` | always 202 (no user enumeration) |
| POST | `/auth/mfa/enroll`, `/auth/mfa/verify`, `/auth/mfa/disable` | TOTP |
| POST | `/auth/device/authorize`, `/auth/device/approve`, `/auth/device/token` | RFC 8628 device grant (TVs/CLI) |
| GET | `/.well-known/jwks.json`, `/.well-known/openid-configuration` | our own OIDC provider |
| GET | `/.well-known/vpn-bootstrap.json` | API URLs, SPKI pins, min client version |

Access token claims: `iss, sub, aud=vpn-api, exp, iat, nbf, jti, tid (tenant), role,
scope, sid, did (device), amr, acr, tv (token version), typ=at`.
Refresh: opaque 256-bit, stored as HMAC-SHA256, **rotating**, 30 d sliding with a
90 d family cap; reuse ⇒ the whole family is revoked.

## 3. Resources

| Group | Endpoints |
|---|---|
| Me | `GET,PATCH /me`, `GET /me/entitlements`, `GET /me/sessions`, `DELETE /me/sessions/{sid}` |
| Devices | `POST,GET /devices`, `GET,PATCH,DELETE /devices/{id}`, `GET /devices/attestation-challenge`, `POST /devices/{id}/attestation` |
| Enrollment | `POST,GET /enrollment-tokens`, `POST /enroll` (token-authenticated, no bearer) |
| Peers | `POST,GET /peers`, `GET,DELETE /peers/{id}`, `POST /peers/{id}/rotate-keys`, `POST /peers/{id}/suspend`, `POST /peers/{id}/resume`, `GET /peers/{id}/config`, `GET /peers/{id}/usage` |
| Catalog | `GET /regions`, `GET /servers`, `GET /servers/{id}` (ETag 15 s, `load_hint`) |
| Billing | `GET /plans`, `GET /subscription`, `POST /checkout`, `POST /webhooks/stripe` |
| Telemetry | `POST /telemetry/batches` (idempotent by client uuid) |
| Admin | `GET /admin/tenants`, `GET /admin/audit`, `POST /admin/tenants/{id}/suspend`, `POST /admin/impersonate` (≤30 min, audited) |

## 4. Peer creation example

```http
POST /api/v1/peers HTTP/1.1
Authorization: Bearer <jwt>
Idempotency-Key: 8f14e45f-...
Content-Type: application/json

{ "device_id": "dev_01H...", "region_preference": "fra", "public_key": "base64" }
```

`201 Created` returns the payload documented in
[CLIENT_INTEGRATION.md](CLIENT_INTEGRATION.md) §2, plus `ETag`.

Errors: `401 unauthenticated`, `403 device_revoked`, `409 session_exists`,
`422 config_unsupported`, `429 rate_limited`, `503 node_at_capacity`.

## 5. Security invariants (tested)

1. A token minted for tenant A can never read tenant B (route inventory test +
   RLS backstop).
2. Tenant id comes from the token, never from the body/path.
3. `GET /peers/{id}/config` returns `private_key: null` unless the device row is
   the caller's **and** the peer was created in `server` key mode.
4. No endpoint returns another user's email, device name, or IP.
5. Admin impersonation always writes an `audit_log` row with `impersonator_id`.

## Administration: accounts and paid access (implemented)

Access is sold in months and paid for out of band; an administrator records the
result. See [ADR-0010](DECISIONS/ADR-0010-admin-granted-access.md). All of these
require a token whose account has `role = "admin"`; anything else gets
`403 permission_denied`.

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/v1/admin/users` | `{"email","password","months"\|"days","role"?,"plan"?}` | Creates the account **and** its access window. `months` are 30-day months; default is 1 month. `role` is `user` (default), `admin` or `owner`; administrators never expire. Returns the account with `days_left`. |
| GET | `/api/v1/admin/users` | — | `{"data":[…]}` of every account: `id`, `email`, `role`, `plan`, `status`, `expires_at`, `days_left`. |
| GET | `/api/v1/admin/users/{id}` | — | One account. |
| POST | `/api/v1/admin/users/{id}/access` | `{"months"\|"days","plan"?}` | **Extends**: adds to `max(now, current expiry)`, so paying early never loses days. Also re-enables a revoked account. |
| POST | `/api/v1/admin/users/{id}/revoke` | — | `204`. Immediate lockout; the record and window are kept. An administrator cannot revoke themselves. |

`status` is derived, not stored as such:
`active` → `expired` when `expires_at` has passed, or `disabled` after a revoke.

### What expiry actually does

| Surface | Behaviour |
|---|---|
| `POST /api/v1/peers` | `403 access_expired` — no new peer can be allocated |
| `GET /api/v1/peers/{id}/config` | `403 access_expired` — the configuration cannot be re-downloaded |
| `GET /api/v1/me` | still available: the user must be able to see that the plan ended |
| Login | still available, for the same reason |
| Data plane (`vpn-dp`) | handshake refused, transport packets dropped — an **already installed** client stops passing traffic |

`vpnctl` mirrors these:

```
vpnctl admin users add --email ali@example.invalid --password <pw> --months 6
vpnctl admin users                      # id, email, plan, status, days left
vpnctl admin grant <user-id> --months 1 # extend by one month
vpnctl admin revoke <user-id>           # immediate lockout
vpnctl me                               # plan, status, days left (as the customer)
```

### Operator runbook

1. Money arrives out of band. Note the email and the plan.
2. `vpnctl admin users add --email … --months 6 --password <initial>` for a new
   customer, or `vpnctl admin grant <user-id> --months 6` for a renewal.
3. `vpnctl admin users` weekly: anyone with a small `days_left` gets a reminder.
4. Non-payment: `vpnctl admin revoke <user-id>` — the tunnel drops immediately.



## Credentials and renewal reminders (implemented, ADR-0011)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/rotate` | — | `200`. Returns a **new** `access_token` and immediately revokes the one presented in the `Authorization` header. Containment for a leaked token: same identity, same access window, old value dead. Not a refresh flow — there is no long-lived refresh secret. |
| POST | `/api/v1/admin/audit`→`GET` | query: `limit=N` (default 100) | `{"data":[{"actor","action","target","at"}]}` of recent administrator actions (`user.create`, `user.grant`, `user.revoke`), newest last. Administrator only. |
| POST | `/api/v1/me/password` | `{"current_password","new_password"}` | `204`. The initial password is issued by an administrator, so users must be able to change it. Wrong current password → `401`. |
| POST | `/api/v1/admin/users/{id}/password` | `{"password"}` | `204`. Administrator reset for a customer who forgot theirs. |
| POST | `/api/v1/admin/reminders/run` | query: `days=7,1`, `dry_run=1` | One mail per account per bucket. `{"sent":n,"failed":n,"dry_run":bool}`; `502` if any send failed (those stay unmarked and are retried). Idempotent: a daily cron cannot double-mail. `503` when SMTP is unconfigured. |
| GET | `/api/v1/dp/config` | query: `node=<id>` | The peer table as the TOML subset `vpn-dp` parses, for `vpn-dp --config-url`. Administrator only. |

```bash
vpnctl passwd --current <old> --new <new>
vpnctl admin set-password <user-id> --password <new>
vpnctl admin remind --days 7,1          # cron: 0 9 * * * vpnctl admin remind
vpnctl admin dp-config                 # what a node would pull
```

### Node bootstrap with no hand-copied keys

```toml
# /etc/vpn/datad.toml - interface only; peers arrive over HTTP
[interface]
private_key = "<from: vpn-dp --genkey>"
listen = "0.0.0.0:51820"
tun = "wg0"
```

```bash
vpn-dp --config /etc/vpn/datad.toml \
       --config-url http://127.0.0.1:8080/api/v1/dp/config \
       --token "$VPN_DP_TOKEN" --refresh 60
```

`http://` only: terminate TLS in a local relay (stunnel) or reach the control plane
over a private network (ADR-0009/ADR-0011). A failed pull logs a warning and keeps
the last good table, so a control-plane outage never drops live tunnels.
