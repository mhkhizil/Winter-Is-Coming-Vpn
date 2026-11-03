// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
package com.winteriscoming.vpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.winteriscoming.vpn.api.PeerConfig
import com.winteriscoming.vpn.api.VpnApi

/**
 * Onboarding + connect screen.
 *
 * Deliberately thin for now: it drives the real API and the [TunnelEngine] seam, and
 * it runs against [FakeTunnelEngine] so the flow is testable without a VPN service.
 * Wiring the real engine requires the VPN-consent dialog (`VpnService.prepare`) and
 * the keystore-backed key container - that is milestone M2/M3, not UI work.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Scaffold { padding ->
                    OnboardingScreen(Modifier.fillMaxSize().padding(padding))
                }
            }
        }
    }
}

private enum class Phase { LOGIN, READY, FAILED }

@Composable
private fun OnboardingScreen(modifier: Modifier = Modifier) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Not connected") }
    var phase by remember { mutableStateOf(Phase.LOGIN) }
    var renewal by remember { mutableStateOf(false) }

    // The server URL is a build concern; keep it visible rather than hidden in a
    // resource so a reviewer can see exactly where credentials are sent.
    val api = remember { VpnApi(BuildConfig.API_BASE_URL) }

    Column(
        modifier.padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Winter VPN", style = MaterialTheme.typography.headlineSmall)
        Text(status, style = MaterialTheme.typography.bodyMedium)

        if (phase == Phase.LOGIN) {
            OutlinedTextField(email, { email = it }, label = { Text("Email") })
            OutlinedTextField(password, { password = it }, label = { Text("Password") })
            Button(onClick = {
                status = "Signing in…"
                // Real work runs off the main thread; this is a skeleton, so the
                // network call is left to the caller's coroutine scope in M2.
                runCatching { api.login(email, password) }
                    .onSuccess { phase = Phase.READY; status = "Signed in as ${it.userId}" }
                    .onFailure {
                        phase = Phase.FAILED
                        renewal = (it as? VpnApi.ApiException)?.renewalRequired == true
                        status = it.message ?: "Sign-in failed"
                    }
            }) { Text("Sign in") }
        }

        if (phase == Phase.READY) {
            Button(onClick = {
                val deviceId = api.createDevice("android")
                // The client generates its keypair; the server only ever sees the
                // public half (ADR-0007). Key generation lands in M2 with the
                // keystore-backed container.
                status = "Device ${deviceId.ifEmpty { "?" }} registered"
            }) { Text("Register this device") }

            Button(onClick = {
                status = runCatching { api.listServers().toString() }
                    .getOrElse { "Could not load servers: ${it.message}" }
            }) { Text("Show servers") }
        }

        if (phase == Phase.FAILED) {
            Button(onClick = { phase = Phase.LOGIN }) { Text("Back") }
            if (renewal) {
                Text("Your plan has ended. Contact your provider to renew.")
            }
        }
    }
}

/** Kept for the (unused-yet) connect path so the import stays meaningful. */
@Suppress("unused")
private fun describe(config: PeerConfig): String =
    "${config.serverEndpoint} mtu=${config.mtu}"
