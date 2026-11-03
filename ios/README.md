# ios/ — Swift client (placeholder)

**Status: folder placeholder only. No code, no Xcode project, no Package.swift.**

This directory will hold the iOS client: an app plus a `NEPacketTunnelProvider`
extension, exposing the contract in
[`../docs/CLIENT_INTEGRATION.md`](../docs/CLIENT_INTEGRATION.md).

Planned responsibilities (for whoever picks this up):

* **Key management** — generate the X25519 keypair on-device and store it in the
  Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; upload only the
  public key. Never send a private key to the API (ADR-0007).
* **Device attestation** — App Attest + DeviceCheck at enrollment.
* **Tunnel** — `NEPacketTunnelProvider` +
  `NETunnelProviderProtocol.providerConfiguration` (the signed config payload) +
  `NEPacketTunnelNetworkSettings` (addresses, routes, DNS, MTU 1420).
* **On-demand** — `NEOnDemandRule*` plus `includeAllNetworks` for kill switch.
  Note: iOS has **no per-app exclusion**; the server must not offer
  `included_apps`/`excluded_apps` to iOS clients.
* **Lifecycle** — same timers and backoff ladder as Android; handle
  `sleep`/`wake` by re-applying `NEPacketTunnelNetworkSettings` and letting the
  tunnel core re-handshake.
* **Telemetry** — batched aggregate counters only.

Constraints to remember: the extension has a ~50 MB memory limit on some devices,
so the tunnel core must not allocate per packet; and `NetworkExtension` requires a
paid Apple Developer account with the `packet-tunnel-provider` entitlement.
