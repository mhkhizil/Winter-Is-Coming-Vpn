# Control-plane API

Status: **normative for M3+**. Nothing in this document is implemented; `vpnd`
serves only `/healthz`, `/readyz`, `/metrics` and `/` today. Machine-readable
spec: [`api/openapi.yaml`](api/openapi.yaml) (hand-written, spec-first). Clients
will be generated from it; the intended server check is `oasdiff --breaking` in
CI, which **does not exist yet** (no `oasdiff` step in `.github/workflows/`).

Base path `/api/v1`. Transport: HTTPS only (TLS 1.3 minimum). Auth:
`Authorization: Bearer <access JWT>`.

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
