# ADR-0012: the Android client embeds the official WireGuard tunnel library

**Status:** accepted (2026-11-02)
**Context:** the first front end is an Android app (milestone M5 of the roadmap).

## Context

We have a portable, tested C++ WireGuard implementation in this repository
(`server/src/wire`, `server/src/crypto`): the protocol layer has **no OS
dependencies** and could be built for Android with the NDK. That makes "write our
own client tunnel" an option. The other option is the official
`com.wireguard.android:tunnel` AAR (Apache-2.0, Maven Central), which is what the
official Android app itself uses.

The asymmetry that decides it:

- Our **server** has never spoken to an official WireGuard implementation. Every
  session it has ever served came from a client we also wrote. Two implementations
  we authored agreeing with each other is precisely the failure mode that
  self-consistency cannot detect.
- A client-side WireGuard must get timers, rekey, cookie replies, keepalives,
  roaming and rate limits right. Getting one of those subtly wrong produces a
  tunnel that works on the developer's network and fails on mobile.

## Decision

**The app embeds `com.wireguard.android:tunnel`** (`1.0.20260102`, Apache-2.0)
behind our own `TunnelEngine` interface.

- Every user session therefore doubles as an official-implementation interop proof
  for the server — the project's largest open risk becomes something production
  traffic tests continuously.
- `VpnService` subclasses the library's `GoBackend.VpnService`, which is the
  documented embedding path and the handle the library's `setState` expects.
- The NDK port of `wire/` is **not** abandoned: it slots in behind the same
  `TunnelEngine` interface (with `FakeTunnelEngine` already providing the test
  seam). By then we will have production interop data to validate it against.
- The app additionally offers "Export to WireGuard" (share the `.conf` the server
  already generates) so users who prefer the official app are not excluded, and so
  launch does not depend solely on the embedded tunnel.

## Consequences

**Positive**

- No Go/gomobile toolchain, no NDK shipping in v1; one Gradle dependency.
- Client protocol correctness is not our problem in v1.
- The server's interop claim becomes continuously evidenced rather than asserted.

**Negative**

- APK grows by a few MB; we inherit the library's minSdk/ABI choices and its release
  cadence (Apache-2.0, so we must ship its NOTICE).
- Requires Java 17 + core library desugaring (documented by the library).
- The app must not become a place where our own protocol code grows quietly: if we
  want to own the client tunnel later, that is a deliberate ADR-level change.

## Alternatives rejected

- **NDK port of `wire/` for v1.** Highest code reuse, but it leaves the server's
  official-interop question unanswered while adding client-side protocol risk.
- **No embedded tunnel: hand the `.conf` to the official app (§Path A).** Works and
  is cheapest, but the in-app UX (login, plan status, renewal, one-tap connect)
  becomes impossible, and it is not what a VPN product is.
- **Kernel WireGuard via `wg-quick`.** Requires root; not available to a Play app.
