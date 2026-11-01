#!/usr/bin/env sh
# Seed a development database with one tenant, one user, one device, one region
# and one server. Requires `psql` and a reachable database.
#
#   VPN_DATABASE_URL=postgres://vpn:vpn@127.0.0.1:5432/vpn sh scripts/seed.sh
set -eu

: "${VPN_DATABASE_URL:=postgres://vpn:vpn@127.0.0.1:5432/vpn?sslmode=disable}"

echo "==> seeding ${VPN_DATABASE_URL%%\?*}"
psql "$VPN_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO regions (code, display_name, country)
VALUES ('fra', 'Frankfurt', 'DE'), ('ams', 'Amsterdam', 'NL')
ON CONFLICT (code) DO NOTHING;

INSERT INTO tenants (id, slug, display_name)
VALUES ('11111111-1111-1111-1111-111111111111', 'dev', 'Development tenant')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO users (tenant_id, email, password_hash, email_verified_at)
VALUES ('11111111-1111-1111-1111-111111111111', 'dev@example.invalid',
        -- Argon2id hash of "dev-only-password"; replace via the API in real use.
        '$argon2id$v=19$m=65536,t=3,p=1$ZGV2c2FsdGRldnNhbHQ$devplaceholderhash',
        now())
ON CONFLICT (tenant_id, email) DO NOTHING;

INSERT INTO servers (region_code, name, public_key, endpoint_host, ipv4_pool, ipv6_block)
VALUES ('fra', 'fra-dev-01', decode(repeat('11', 32), 'hex'), '127.0.0.1', '10.64.1.0/24',
        'fd00:64:1::/64')
ON CONFLICT (name) DO NOTHING;

SELECT 'tenant' AS kind, count(*) FROM tenants
UNION ALL SELECT 'region', count(*) FROM regions
UNION ALL SELECT 'server', count(*) FROM servers;
SQL

echo "==> done"
