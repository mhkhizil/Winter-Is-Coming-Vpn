# ADR-0004 — Data plane runs as a systemd unit on edge VMs, not as a Kubernetes pod

* Status: accepted (alternate documented)
* Date: 2026-11-01
* Deciders: server team, SRE

## Context
The data plane needs: a stable public UDP endpoint, `/dev/net/tun`,
`CAP_NET_ADMIN`, CPU pinning, `SO_REUSEPORT` handoff during upgrades, and
predictable packet scheduling. The control plane is a stateless HTTP service that
fits Kubernetes perfectly.

## Decision
* Control plane → **Kubernetes** (HPA 3–20 pods).
* Data plane → **VM with a systemd unit** (`vpn-datad`), installed from a deb/rpm,
  hardened with `systemd-analyze security` < 2.0.
* Documented alternate for teams that insist on Kubernetes: a `DaemonSet` with
  `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`, a tainted node pool,
  `OnDelete` updates, and `NET_ADMIN` + a `/dev/net/tun` hostPath. It is *not*
  the default because of the upgrade and scheduling caveats below.

## Consequences
* Two deployment mechanisms to maintain (Helm + deb/rpm). Accepted: they have
  different release cadences anyway.
* Node lifecycle is explicit (`vpnctl node register/drain/remove`) instead of
  implicit via the scheduler — this is a feature: draining is a product concern
  (clients must be told where to go), not a scheduler detail.
* Autoscaling is not automatic; capacity is planned with the table in
  `docs/CAPACITY.md` and alerted on CPU/pps.

## Why not a normal pod
* Pod eviction/CIDR churn changes the public endpoint clients pinned.
* `NET_ADMIN` + `hostPath /dev/net/tun` requires a PSA exemption, which weakens
  the cluster's security posture for every other workload.
* The container runtime's cgroup/CPU manager interferes with packet pacing.
* Rolling updates cannot hand off `SO_REUSEPORT` sockets across pod identities.

## Alternatives rejected
* **DPDK/bare metal only** — 3× the operational cost for a 10 Gbps target we can
  hit in userspace.
* **Kernel `wireguard.ko` as the primary backend** — GPL-2.0 linkage, no
  per-peer quota hooks, coarse rate limiting, and no roaming notifications. Kept
  as a fallback backend if userspace throughput disappoints at M4.
