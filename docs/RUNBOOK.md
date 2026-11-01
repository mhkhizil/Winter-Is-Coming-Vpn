# Runbook

Status: **normative**. Every step is copy-pasteable and states the expected
output. Steps that depend on a milestone that is not implemented yet are tagged
inline; an untagged step implies the command exists today.

> **Read this first (M0).** Only §1 is executable today. §2–§9 depend on
> `vpnctl` (M3), `vpn-datad` (M2), `wal-g` backup tooling (M5) and the metrics in
> the §0 table that no binary exports. They are written down now so the interface
> is fixed, not because an on-call engineer can follow them. Tagging rules:
> [`docs/README.md`](README.md) rule 4.

## 0. Golden signals

Only the first row exists in M0. Every other metric below is exported by nothing
in this repository yet — do not build alerts on them.

| Signal | Source | Alert threshold | Available today |
|---|---|---|---|
| API availability | `vpn_http_requests_total` | 5xx > 1 % for 5 min | **yes** (labels: `route`, `method`, `status`) |
| Config propagation | `vpn_dp_config_lag_seconds` | p95 > 10 s for 5 min | no — M3 |
| Handshake success | `vpn_handshakes_total{result="ok"}` | ratio < 90 % for 5 min | no — M1 |
| Packet drops (legit) | `vpn_dp_drops_total{reason="policy"}` | > 0.1 % for 10 min | no — M2 |
| Per-peer quota cut-offs | `vpn_quota_exceeded_total` | spike > 100/min | no — M2 |
| Node CPU | `node_cpu_seconds_total` | > 70 % sustained 15 min | no |
| DB saturation | `pg_stat_activity` | > 80 % of `max_connections` | no — M3 |

The only metrics `vpnd` registers are `vpn_build_info`, `vpn_uptime_seconds` and
`vpn_http_requests_total`, all served on the `http.bind` port (default `:8080`),
**not** on `:9100`.

## 1. Start / stop / verify (M0)

```sh
./build/default/server/vpnd --config deploy/compose/vpnd.dev.toml &
curl -s localhost:8080/readyz            # {"status":"ready",...}
curl -s localhost:8080/metrics | head
curl -s localhost:8080/healthz
./build/default/server/vpnd --validate-config --config deploy/compose/vpnd.dev.toml
./build/default/server/vpnd --print-config   --config deploy/compose/vpnd.dev.toml
kill -TERM %1                            # vpnd logs "stopped cleanly", exit 0
```

Exit codes: `0` ok, `1` generic failure, `2` usage/config error, `3` runtime error.
`/readyz` returns `503 starting` before the accept loop begins and `503 draining`
once a stop has been requested — a restarting `vpnd` will briefly report
unready, which is the intended gate for load balancers.

There is **no** hot reload: `systemctl reload vpnd` does nothing because
`vpnd.service` deliberately omits `ExecReload`. Restart to apply config.

## 2. A node is not taking new sessions — [M3]

1. `vpnctl node list` → look at `status` (`degraded`/`draining`/`disabled`).
2. `vpnctl node describe <id>` → `last_ack_generation`, `config_lag`.
3. On the node: `journalctl -u vpn-datad -n 200 --no-pager`.
4. If `generation` is stuck: the apply failed. Re-apply the last known good:
   `vpnctl node resync <id>` (server re-sends the snapshot with a **new** higher
   generation; a failed apply never advances the generation by itself).
5. If the node is wedged: `vpnctl node drain <id> --grace 300s`, then restart.

## 3. Drain a node without dropping tunnels — [M3]

```sh
vpnctl node drain srv_fra_01 --grace 900s
# clients receive suggested_endpoints and reconnect in make-before-break fashion
vpnctl node status srv_fra_01 --watch      # wait for live_peers: 0
systemctl stop vpn-datad
```

Expected: `live_peers` decreases monotonically; `suggested_endpoint` counts rise;
no client reports an outage longer than 30 s.

## 4. Rotate a server key — [M3]

```sh
vpnctl node rotate-key srv_fra_01 --new-key-id k_2026_12
```

Effects: new key becomes primary for new handshakes; `k_2026_11` stays accepted
for 24 h; clients receive both in `server_keys`; after 24 h the old key is
retired. Verify with `vpnctl node describe srv_fra_01 --show-keys`.

## 5. Revoke a device (fraud / theft) — [M3]

```sh
vpnctl peer revoke pe_01H... --reason "device reported stolen"
```

SLO: **≤1 s** until the peer's handshakes are refused (index removal + allowed-IP
removal + cuckoo filter insert). Verify: the client gets `device_revoked`, and
`vpn_dp_drops_total{reason="revoked"}` increments once.

## 6. Suspected server-key compromise (S1) — [M3]

1. `vpnctl node remove <id> --force` → node disappears from the catalog.
2. Rotate the node's TPM-sealed key: `vpnctl node rotate-key <id>` (requires the
   node to be re-registered afterwards).
3. Announce in the incident channel; start the post-mortem within 24 h.
4. Check `audit_log` for the access path that led to the compromise.

## 7. PostgreSQL restore drill (monthly) — [M5]

```sh
wal-g backup-fetch /var/lib/postgresql/restore LATEST
# start a scratch instance on :5433, run migrations, compare row counts
psql -p 5433 -c "select count(*) from peers;"
```

Target RPO ≤1 min, RTO ≤30 min in-region. A restore that has not been drilled in
the last 35 days blocks the release.

## 8. Handshake flood (S3) — [M2/M3]

1. Enable cookie mode: `vpnctl node set-cookies srv_fra_01 on` (default is
   `auto`: cookies engage above 20 k handshakes/s).
2. Confirm `vpn_handshakes_total{result="cookie_sent"}` rises and CPU falls.
3. If the source is volumetric: enable upstream scrubbing/anycast for the
   handshake path only; established sessions keep flowing unicast.
4. Do **not** blackhole whole prefixes without a second opinion — CGNAT means
   thousands of legitimate users share an address.

## 9. Abuse ticket — [M3]

1. Correlate only by aggregate counters (no per-connection logs exist).
2. Block destination ports per-tenant via `policy.blocked_dest_ports`.
3. For repeat offenders: suspend the tenant (`POST /admin/tenants/{id}/suspend`)
   — this is visible to the customer and audited.

## 10. On-call escalation

| Severity | Page | Response |
|---|---|---|
| S1 key compromise / tenant breach | architect + security | 15 min |
| S2 data-plane outage in a region | data-plane owner | 30 min |
| S3 API degraded / billing down | backend owner | 1 h |
| S4 single node degraded | no page, next business day | — |
