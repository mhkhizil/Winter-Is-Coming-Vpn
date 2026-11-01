# Data model

Status: **normative for M3+** (the schema in `server/migrations/0001_init.sql`
is the source of truth; this document explains the *why*).

## 1. Tenancy

Every row that belongs to a customer carries `tenant_id`. Enforcement is
threefold:

1. **Application**: repositories always take `tenant_id` as their first arg.
2. **Database**: `vpn_app` role cannot bypass RLS; each request sets
   `SET LOCAL app.tenant_id = '...'` inside its transaction.
3. **Schema**: composite foreign keys (`devices(id, tenant_id)`) make a
   cross-tenant reference *unrepresentable*.

`vpn_platform` (BYPASSRLS) exists for migrations and support tooling, and every
use is audited.

## 2. Core tables

| Table | Purpose | Key columns | Notes |
|---|---|---|---|
| `tenants` | billing boundary | `id uuid pk`, `slug unique`, `status` | `slug` used in URLs |
| `users` | human identity | `id`, `tenant_id`, `email`, `password_hash`, `token_epoch` | `unique (tenant_id, lower(email))` |
| `memberships` | user↔tenant role | `(user_id, tenant_id) pk`, `role` | role ∈ owner/admin/billing/viewer/member |
| `devices` | a client install | `id`, `tenant_id`, `user_id`, `platform`, `public_key`, `attestation` | `unique (tenant_id, public_key)` |
| `peers` | a tunnel config | `id`, `tenant_id`, `device_id`, `server_id`, `public_key`, `ipv4`, `ipv6`, `status` | `unique (server_id, ipv4)`, `unique (server_id, ipv6)` |
| `servers` | a data-plane node | `id`, `region_code`, `public_key`, `endpoint_host`, `status`, `generation` | `public_key` only — never a private key |
| `server_endpoints` | alternate hostnames | `server_id`, `host`, `port`, `weight` | for `suggested_endpoints` |
| `regions` | catalog | `code pk`, `display_name`, `country` | |
| `plans` | product catalog | `code`, `version`, `price_cents`, `device_limit`, `bandwidth_bytes`, `stripe_price_id` | `tenant_id NULL` = global |
| `subscriptions` | entitlement periods | `tenant_id`, `plan_code`, `period tstzrange` | `EXCLUDE USING gist` non-overlapping |
| `invoices`, `webhook_events` | billing | `provider_event_id unique` | idempotent webhook handling |
| `usage_counters` | metering | `(tenant_id, peer_id, metric, window_start)` | monthly partitions, 25 months |
| `telemetry_batches` | client uploads | `id`, `device_id`, `payload_sha256` | `unique (device_id, id)` for idempotency |
| `audit_log` | accountability | `occurred_at`, `actor_*`, `action`, `diff jsonb` | monthly partitions, append-only |
| `sessions` | refresh tokens | `sid`, `family_id`, `refresh_token_hash`, `amr`, `token_floor` | hashed only |
| `api_keys` | B2B | `key_prefix`, `key_hash`, `scopes[]` | `vpn_live_` prefix |
| `enrollment_tokens` | `.conf`/QR issuance | `token_hash`, `device_id`, `expires_at`, `used_at` | single use, 10 min TTL |
| `outbox` | reliable side effects | `topic`, `dedupe_key`, `payload` | worker drains |

## 3. IP address management (IPAM)

* Each node owns one IPv4 **pool**: `10.64.<region>.<node>/24` (254 usable).
* Each tenant owns one IPv6 **block**: `/64` from `fd00:64::/48`.
* A peer gets `/32` (v4) and `/128` (v6) allocated transactionally:

```sql
UPDATE ip_allocations_v4 SET state = 'assigned', peer_id = $2
 WHERE id = (SELECT id FROM ip_allocations_v4
              WHERE server_id = $1 AND state = 'free'
              ORDER BY addr LIMIT 1 FOR UPDATE SKIP LOCKED)
 RETURNING addr;
```

* Collisions are impossible by construction:

```sql
ALTER TABLE ip_allocations_v4 ADD CONSTRAINT no_overlap
  EXCLUDE USING gist (server_id WITH =, addr WITH &&);
```

* Reclaim: `assigned → quarantine` for 300 s (a roaming client must not get its
  old address given to someone else instantly) `→ free`.
* One route per **pool** on the node, never per peer (a `/24` route covers 254
  peers; per-peer routes do not scale past ~5k).

## 4. Encryption at rest and retention

| Data | At rest | Retention |
|---|---|---|
| Password hashes | Argon2id + HMAC pepper (pepper in KMS, not DB) | account lifetime |
| Refresh tokens | HMAC-SHA256 hash | 90 days max |
| Peer public keys | plaintext (they are public) | until revoked + 30 d |
| Usage counters | plaintext | 25 months (billing/audit) |
| Audit log | plaintext | 13 months |
| Session IP attribution | **not stored** by default | 0 s |

## 5. Migrations

`goose` (SQL-only) + `atlas migrate lint`. Rules: expand/contract only (never
drop a column in the same release that stops writing it), `CREATE INDEX
CONCURRENTLY`, `SET lock_timeout = '3s'`, CI runs `up → down → up` on a real
PostgreSQL 16 container. Backups: WAL-G with `archive_timeout=60s`, 35-day PITR
→ RPO ≤1 min, RTO ≤30 min in-region. A nightly restore drill is a hard CI gate.
