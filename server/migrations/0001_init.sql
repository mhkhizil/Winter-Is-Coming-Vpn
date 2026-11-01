-- 0001_init.sql - core schema (M3 target; created early so the data model is
-- reviewable before code depends on it).
--
-- Rules:
--   * every customer-owned row carries tenant_id
--   * composite foreign keys make cross-tenant references unrepresentable
--   * exclusion constraints make IP/port collisions impossible
--   * there is NO column that can hold a client private key (ADR-0007)
--
-- Applied by goose. Expand/contract only: never drop a column in the same
-- release that stops writing it.

BEGIN;

CREATE EXTENSION IF NOT EXISTS btree_gist;   -- needed for EXCLUDE on uuid + inet
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------- tenancy --
CREATE TABLE tenants (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         citext NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,38}$'),
  display_name text   NOT NULL,
  status       text   NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  email         citext NOT NULL,
  password_hash text,                       -- NULL until e-mail is verified
  email_verified_at timestamptz,
  token_epoch   integer NOT NULL DEFAULT 1,  -- bump to revoke every token
  mfa_secret    text,
  status        text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'locked', 'deleted')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email),
  UNIQUE (id, tenant_id)                    -- target for composite FKs
);

CREATE TABLE memberships (
  user_id    uuid NOT NULL,
  tenant_id  uuid NOT NULL,
  role       text NOT NULL CHECK (role IN ('owner', 'admin', 'billing', 'viewer', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, tenant_id),
  FOREIGN KEY (user_id, tenant_id) REFERENCES users (id, tenant_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------- devices --
CREATE TABLE devices (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  user_id      uuid NOT NULL,
  platform     text NOT NULL CHECK (platform IN ('android', 'ios', 'linux', 'macos', 'windows')),
  display_name text NOT NULL DEFAULT '',
  public_key   bytea CHECK (octet_length(public_key) = 32),
  attestation  jsonb,
  status       text NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'active', 'revoked')),
  revoked_at   timestamptz,
  last_seen_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (user_id, tenant_id) REFERENCES users (id, tenant_id) ON DELETE CASCADE,
  UNIQUE (tenant_id, public_key),
  UNIQUE (id, tenant_id)
);

-- ----------------------------------------------------------------- servers --
CREATE TABLE regions (
  code         citext PRIMARY KEY,
  display_name text NOT NULL,
  country      char(2) NOT NULL
);

CREATE TABLE servers (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  region_code    citext NOT NULL REFERENCES regions (code),
  name           text NOT NULL UNIQUE,
  public_key     bytea NOT NULL CHECK (octet_length(public_key) = 32),  -- public only
  endpoint_host  text NOT NULL,
  endpoint_port  integer NOT NULL DEFAULT 51820 CHECK (endpoint_port BETWEEN 1 AND 65535),
  ipv4_pool      cidr NOT NULL,
  ipv6_block     cidr NOT NULL,
  status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'active', 'degraded', 'draining', 'disabled')),
  generation     bigint NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE server_endpoints (
  id        bigserial PRIMARY KEY,
  server_id uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
  host      text NOT NULL,
  port      integer NOT NULL DEFAULT 51820 CHECK (port BETWEEN 1 AND 65535),
  weight    integer NOT NULL DEFAULT 100 CHECK (weight > 0),
  UNIQUE (server_id, host, port)
);

COMMIT;
