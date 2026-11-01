# Deployment

Status: **normative**. M0 deploys nothing but `vpnd`; the data-plane topology is
the M2/M4 target and is documented here so infrastructure work can start early.

## 1. Topology

```
                        ┌─────────────── K8s: vpn-control (2..20 pods, HPA) ───────────────┐
  clients ──HTTPS:443──▶│ vpnd  (stateless)  ──▶ PostgreSQL 16 (HA, PITR)   Redis 7       │
                        │        │  gRPC/mTLS :9443                                         │
                        └────────┼──────────────────────────────────────────────────────────┘
                                 │ agent-initiated (NAT-safe)
      ┌──────────────────────────┼───────────────────────────┐
      ▼                          ▼                           ▼
  fra-01 (VM, public IPv4)   ams-01 (VM)                iad-01 (VM)
  vpn-dp as systemd unit     vpn-dp                     vpn-dp
  UDP 51820, /dev/net/tun    ...                        ...
```

**Why the data plane is not a pod:** it needs a stable public UDP endpoint, a
`/dev/net/tun`, CPU pinning and `SO_REUSEPORT` handoff during upgrades. A
DaemonSet with `hostNetwork` + a tainted node pool is the documented alternate
(ADR-0004), but the default is a VM with a systemd unit.

## 2. Local stack

```sh
make dev      # docker compose -f deploy/compose/compose.yaml up --build -d
```

| Service | Image | Ports | Notes |
|---|---|---|---|
| `postgres` | `postgres:16.4-alpine` | 5432 | `vpn` db, schema auto-applied from `server/migrations/`. **`vpnd` never connects to it in M0.** |
| `redis` | `redis:7.4-alpine` | 6379 | **`vpnd` never connects to it in M0.** `VPN_REDIS_URL` is ignored. |
| `control` | built from `deploy/docker/Dockerfile.vpnd` | 8080 | dev config mounted. The compose file also publishes 9100 and the image `EXPOSE`s it, but **nothing listens there** — `/metrics` is on 8080. |
| `datad` | built from `deploy/docker/Dockerfile.datad` | 51820/udp | **M2 — the image deliberately fails to build** until `server/src/dataplane/main.cpp` exists. Behind the `dataplane` profile. |
| `wgclient` | `linuxserver/wireguard` (test harness only) | — | M1+; cannot prove anything until a handshake exists. |

`make dev` therefore starts Postgres and Redis that the control plane does not
use. That is intentional scaffolding, not a working dependency graph — do not
read readiness from it.

## 3. Edge node (systemd) — [M2], not available today

```sh
sudo apt install -y ./vpn-datad_0.1.0_amd64.deb     # no deb is produced yet
sudo systemctl enable --now vpn-datad
sudo systemd-analyze security vpn-datad     # expect < 2.0 exposure
journalctl -u vpn-datad -f
```

The `vpnd` control plane now has its own unit: `deploy/systemd/vpnd.service`
(`Type=simple`, no capabilities, no network listeners beyond `http.bind`).
It is the only unit that can run today.

> `deploy/systemd/vpn-datad.service` sets `Type=notify`, but neither binary calls
> `sd_notify(3)` — the unit would hang until `TimeoutStartSec` and be killed.
> It also sets `ExecReload=/bin/kill -HUP`, and no binary has a SIGHUP handler,
> so reload is a silent no-op. Both must be fixed with the M2 binary.

Unit hardening (full file in `deploy/systemd/vpn-datad.service`): `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices=no` (needs
TUN), `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`,
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`, `SystemCallFilter=@system-service`,
`MemoryDenyWriteExecute=yes`, `LockPersonality=yes`.

## 4. Node lifecycle — [M3], `vpnctl` does not exist

| Action | Command | Behaviour |
|---|---|---|
| Add node | Terraform `edge_node` module + `vpnctl node register` | appears in catalog once it acks a config |
| Drain | `vpnctl node drain --grace 900s` | stops new sessions, sends `suggested_endpoints`, hard-drains at 0 peers |
| Undrain | `vpnctl node undrain` | back in the catalog |
| Rotate node key | `vpnctl node rotate-key` | new key id live; old key accepted 24 h |
| Remove | `vpnctl node remove --force` | peers deleted, clients re-enroll on next connect |

Upgrades never drop tunnels: new process binds with `SO_REUSEPORT`, old process
stops accepting, drains its sessions, then exits.

## 5. Configuration precedence

`defaults → config file → environment (VPN_*) → CLI flags`. `vpn::config::validate`
rejects an unknown `environment` string, `dev_mode` in production, mismatched
`tls.cert_file`/`tls.key_file`, and out-of-range HTTP limits.

> **Corrections (M0 reality):**
> * `validate()` does **not** check the admin token. An empty `admin_token` starts
>   fine, and no route consumes it anyway. Earlier revisions of this document
>   claimed it was rejected.
> * `validate()` only checks that `tls.cert_file`/`tls.key_file` are non-empty in
>   production — it does not open them, and **no TLS is implemented**, so a
>   production config is accepted and then served as plaintext. Do not trust this
>   check for anything.
> * `vpnd` does **not** log the effective config at startup. Only
>   `vpnd --print-config` renders it (with `tls.key_file` and `admin_token`
>   redacted, everything else in clear).
> * Only these environment variables are read: `VPN_ENV`, `VPN_HTTP_BIND`,
>   `VPN_METRICS_BIND`, `VPN_LOG_LEVEL`, `VPN_ADMIN_TOKEN`, `VPN_DEV_MODE`,
>   `VPN_TLS_CERT_FILE`, `VPN_TLS_KEY_FILE`, `VPN_TLS_CLIENT_CA_FILE`. Everything
>   else in `.env.example` (`VPN_DATABASE_URL`, `VPN_REDIS_URL`, `VPN_JWT_*`,
>   `STRIPE_*`, …) is **silently ignored** — unknown environment keys are not an
>   error, unlike unknown config-file keys.

## 6. Environments

| Env | Control plane | Data plane | Data |
|---|---|---|---|
| dev | compose, 1 pod | compose or absent | seeded, disposable |
| staging | K8s, 2 pods | 1 node per region | anonymised snapshot, 7-day PITR |
| prod | K8s, ≥3 pods, 2 regions | ≥2 nodes per region | PG HA + 35-day PITR, SOCKS-audited access |

## 7. Rollback — [M5], not implemented

Images are tagged by git SHA and signed. Rollback = deploy the previous tag; the
database is protected by expand/contract migrations, so the previous version keeps
working for at least one release. A rollback drill runs monthly in staging.

> None of this exists yet: no image is signed, no deb/rpm is produced, no
> migration runner (`goose`) is wired up, and no rollback drill has run. Treat
> this section as the intended procedure.
