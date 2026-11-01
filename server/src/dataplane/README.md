# server/src/dataplane — M2 (empty on purpose)

This directory is where the data plane lands:

| File | Responsibility |
|---|---|
| `main.cpp` | process lifecycle, TUN setup, worker spawn, signal handling |
| `udp_socket.cpp` | `SO_REUSEPORT` sockets, `recvmmsg`/`io_uring` batches, GSO/GRO |
| `tun_device.cpp` | `TUNSETIFF`, `TUNSETOFFLOAD`, per-tenant queues, MTU |
| `peer_table.cpp` | pubkey → slot (robin-hood), index → session (direct-mapped) |
| `worker_peer_state.cpp` | replay window, counters, endpoint, timers |
| `policy.cpp` | allowed-IPs trie, default-deny ACL, tenant fwmark |
| `shaper.cpp` | per-peer token bucket, EDT pacing, DSCP |
| `netlink_programmer.cpp` | routes, VRF, nftables (libnl + libnftables, never `fork`) |
| `timer_wheel.cpp` | handshake retry, rekey, keepalive expiry |

Design constraints (from `docs/ARCHITECTURE.md` / `docs/CAPACITY.md`):

* 0 heap allocations and 0 locks per packet; one coarse clock read per batch.
* 2 memcpys per packet (skb→user, user→skb); GSO/GRO amortises syscalls.
* Session slots partitioned per worker, so the replay window needs no atomics.
* Everything is behind `vpn::wire` — no packet-format knowledge lives here.

The interface it must satisfy is already fixed by M0: `vpn::wire::decode()`,
`vpn::wire::ReplayWindow`, and the MAC/cookie helpers. That is why those exist
before the data plane does.
