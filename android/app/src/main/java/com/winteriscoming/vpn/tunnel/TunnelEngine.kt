// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
package com.winteriscoming.vpn.tunnel

import com.winteriscoming.vpn.api.PeerConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The seam between the app and whatever actually moves packets.
 *
 * There are two implementations on purpose: [WgTunnelEngine] wraps the official
 * WireGuard library (ADR-0012) and [FakeTunnelEngine] lets the whole onboarding and
 * UI flow be tested on the JVM with no VPN service, no emulator and no root. If we
 * ever replace the official library with our own NDK build of `wire/`, it happens
 * behind this interface and nothing above it changes.
 */
interface TunnelEngine {
    val state: StateFlow<TunnelState>

    /**
     * Brings the tunnel up. [privateKeyBase64] is unwrapped from the keystore-backed
     * container by the caller and must not be logged or persisted anywhere else.
     */
    suspend fun connect(config: PeerConfig, privateKeyBase64: String)

    suspend fun disconnect()
}

sealed interface TunnelState {
    data object Down : TunnelState
    data object Connecting : TunnelState
    data class Up(val sinceEpochSeconds: Long, val rxBytes: Long = 0, val txBytes: Long = 0) :
        TunnelState

    /** [renewalRequired] is true for `403 access_expired`: the UI shows "renew", not "retry". */
    data class Failed(val message: String, val renewalRequired: Boolean = false) : TunnelState
}

/** No-op engine for tests and for the "logged in but not connected" UI state. */
class FakeTunnelEngine : TunnelEngine {
    private val _state = MutableStateFlow<TunnelState>(TunnelState.Down)
    override val state: StateFlow<TunnelState> = _state

    var lastConfig: PeerConfig? = null
        private set
    var lastPrivateKey: String? = null
        private set

    override suspend fun connect(config: PeerConfig, privateKeyBase64: String) {
        lastConfig = config
        lastPrivateKey = privateKeyBase64
        _state.value = TunnelState.Connecting
        _state.value = TunnelState.Up(sinceEpochSeconds = System.currentTimeMillis() / 1000)
    }

    override suspend fun disconnect() {
        _state.value = TunnelState.Down
    }
}
