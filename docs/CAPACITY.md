# Capacity and cost model

Status: **model, not measurement** — the numbers below are engineering estimates
with explicit factors. They are replaced by `bench/` results at M2/M5, and every
replacement is recorded here with hardware, kernel and payload mix.

## 1. Per-node throughput model

Per 1420-byte packet, userspace WireGuard on a modern x86 core:

| Stage | cycles/packet | Notes |
|---|---|---|
| UDP receive + GRO | 700 | batched, `recvmmsg`/io_uring |
| Session lookup | 25 | direct-mapped index table |
| ChaCha20-Poly1305 decrypt | 1 100 | ~2.1 cycles/byte at 1420 B |
| Policy + token bucket | 60 | no allocation |
| TUN write + GSO | 450 | one syscall per ~45 packets |
| Encrypt (return path) | 1 100 | |
| Reverse lookup + transmit | 400 | |
| **Ideal total** | **≈ 3 800** | |
| **With a 1.45× reality factor** | **≈ 5 500** | cache misses, syscalls, qdisc |

At ~3.0 GHz: ≈ 545 kpps/core → **6.2 Gbps/core** at 1420 B, **4.4 Gbps/core** at
IMIX (700 B average). Crypto alone tops out near 12 Gbps/core.

| Target workload | Cores needed | Node SKU |
|---|---|---|
| 1 Gbps IMIX | 1 | 2 vCPU (shares control plane) |
| 5 Gbps IMIX | 2 data + 1 control | 4 vCPU / 8 GB |
| 10 Gbps IMIX | 3 data + 1 control | 8 vCPU / 16 GB |
| 20 Gbps IMIX | 5 data + 2 control | 16 vCPU / 32 GB, 2 × 25 GbE |

**Memory:** ≈ 6 KB per peer (session + replay window + policy) + fixed buffers
(48 MB at 8 workers with 2 MiB + 4 MiB slabs). 20 000 peers ≈ 120 MB + 48 MB.

**Handshakes:** ~4 000 responder handshakes/s/core (3 X25519 multiplications per
handshake, ~90–180 µs each). Capacity limits are memory and pps, not Curve25519.

## 2. Scaling table

| Concurrent peers | Peers/node | Nodes | Aggregate egress |
|---|---|---|---|
| 10 000 | 10 000 | 1–2 | 2–4 Gbps |
| 100 000 | 20 000 | 6 (+1 spare/region) | 20–40 Gbps |
| 1 000 000 | 20 000 | 55 | 200–400 Gbps |

Rules of thumb:
* Never exceed ~70 % of a node's measured `IMIX` ceiling — that is where the p99
  latency target (≤1.5 ms added) starts to slip.
* Keep ≥1 spare node per region so a drain never forces cross-region reconnects.
* A `/24` per node caps IPv4 at 254 peers per node — size the pool per node, not
  per region (the schema allows one pool row per node).

## 3. Bandwidth cost (2026 list prices, EUR)

| Item | Unit cost | Notes |
|---|---|---|
| Transit / peering blend | €0.35–0.90 per TB | varies 3× by region |
| Egress at 10 Gbps sustained | €300–800/month | 95th percentile billing |
| VM (8 vCPU/16 GB, 2 × 10 GbE) | €120–260/month | FRA/AMS cheapest, IAD ~1.4× |
| Control plane (3 pods + PG HA + Redis) | €250–450/month | shared across all nodes |

Unit economics for a €5/month consumer plan with a 250 GB cap: worst-case
bandwidth cost €0.09–0.23, node cost per 5 000 users ≈ €0.05, so gross margin is
comfortable **as long as** the 5 % heaviest users are rate-limited by the per-peer
token bucket (which is why quota enforcement lives in the fast path, not in
billing).

## 4. Load-test plan (M2)

| Test | Tool | Pass criteria |
|---|---|---|
| Throughput | `iperf3` through the tunnel, 8 streams | ≥10 Gbps IMIX at ≤70 % CPU |
| pps | `pktgen`/`trex` with 512 B packets | ≥2.5 Mpps |
| Latency | `wrk2`/custom UDP echo, 70 % load | added p99 ≤1.5 ms, p99.9 ≤5 ms |
| Handshakes | custom Go client, 5 000 concurrent | ≥5 000/s, p99 ≤250 ms |
| Churn | 10 000 connect/disconnect per hour, 6 h | 0 leaked sessions/routes/BPF entries |
| Soak | 72 h at 70 % load | RSS slope <1 MB/h, no fd growth |
| Chaos | `kill -9` a worker, NIC flap, 110 % peer table | self-heals <30 s, no cross-tenant effects |

CI gate: any per-PR micro-benchmark regression >3 % versus the 30-day median
blocks the merge.

> **Not implemented.** There is no `server/tests/bench/`, no benchmark baseline
> store, and no benchmark step in `.github/workflows/`. No number in this document
> has been measured on this codebase — the whole file is a model.
