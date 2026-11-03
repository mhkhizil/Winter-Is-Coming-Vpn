> **STATUS UPDATE (supersedes the placeholder text below).** Phase 1 is done: this
> directory now contains a real Gradle project (`settings.gradle.kts`,
> `build.gradle.kts`, `gradle.properties`, `app/`), the API client, the tunnel
> seam and JVM contract tests. See the app sources and
> [`../docs/DECISIONS/ADR-0012-android-client-tunnel.md`](../docs/DECISIONS/ADR-0012-android-client-tunnel.md).
>
> **It has never been compiled.** This development machine has no JDK, no Android
> SDK and no NDK; the build is proven only by
> [`../.github/workflows/ci-android.yml`](../.github/workflows/ci-android.yml).
> Treat the first green CI run as the moment this code exists.
>
> Two corrections to the text below: (1) "do not start until the M3 API is frozen"
> no longer applies — the API is implemented and a live response is captured in
> `app/src/test/.../PeerConfigParserTest.kt`; (2) AndroidKeyStore has **no X25519**,
> so "X25519 scalar in Keystore" means generate with the library's
> `com.wireguard.crypto.KeyPair` and seal it with a KeyStore-backed AES-GCM key —
> not `KeyPairGenerator`.


# android/ — Kotlin client (placeholder)

**Status: folder placeholder only. No code, no Gradle project, no build.**

This directory will hold the Android client: a Kotlin app plus an optional
`wireguard-android`/`boringtun` tunnel core, exposing the contract in
[`../docs/CLIENT_INTEGRATION.md`](../docs/CLIENT_INTEGRATION.md).

Planned responsibilities (for whoever picks this up):

* **Key management** — generate the X25519 keypair on-device, keep the scalar
  wrapped in `AndroidKeyStore`, and upload only the public key
  (`PUT /api/v1/devices/{id}/key`). Never send a private key to the API
  (ADR-0007).
* **Device attestation** — Play Integrity (`PLAY_RECOGNIZED`,
  `MEETS_DEVICE_INTEGRITY`) at enrollment, bound to the device row.
* **Tunnel** — `VpnService` + `Builder.addAddress/addRoute/addDnsServer/setMtu`,
  `setBlocking(true)` for kill switch, `addDisallowedApplication` for split
  tunnelling, `setUnderlyingNetworks(null)` to survive Wi-Fi↔cellular roaming.
* **Lifecycle** — keepalive 25 s, dead at 75 s, backoff ladder 1-2-4-8-16-30 s,
  make-before-break on a draining node, `resume_token` within 15 min.
* **Telemetry** — batched aggregate counters only (`POST /api/v1/telemetry/batches`).

Do not start this until the M3 API is frozen and `openapi.yaml` has generated
client stubs; before that we would be building against a moving target.
