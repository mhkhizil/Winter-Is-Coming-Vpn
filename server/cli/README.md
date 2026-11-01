# server/cli — `vpnctl` (M3)

Operator CLI. Placeholder until M3; the interface is already fixed by the
runbook so that operations scripts can be written against it.

```
vpnctl node list [--region fra] [--json]
vpnctl node describe <server_id> [--show-keys]
vpnctl node register --name fra-01 --region fra --endpoint fra-01.vpn.example:51820
vpnctl node drain <server_id> --grace 900s
vpnctl node undrain <server_id>
vpnctl node resync <server_id>
vpnctl node rotate-key <server_id> --new-key-id k_2026_12
vpnctl node remove <server_id> [--force]
vpnctl node set-cookies <server_id> on|off|auto
vpnctl peer list --tenant <slug>
vpnctl peer revoke <peer_id> --reason "device reported stolen"
vpnctl config print --redacted
```

Rules:
* `vpnctl` **never** reads or writes a client private key (ADR-0007).
* Every mutating command is audited server-side with `actor_type=operator`.
* Exit codes match `vpnd`: `0` ok, `1` failure, `2` usage error, `3` server error.
* `--json` output is stable and versioned (`{"schema":"v1", ...}`) so that
  Terraform/Ansible can consume it.

Implementation notes (M3): CLI11 for parsing, gRPC/REST client from the generated
OpenAPI/proto stubs, mTLS client cert for operator auth, and no direct database
access under any circumstances.
