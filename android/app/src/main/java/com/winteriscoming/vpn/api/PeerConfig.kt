// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
package com.winteriscoming.vpn.api

import org.json.JSONObject

/**
 * Everything the tunnel needs, parsed from the `POST /api/v1/peers` response.
 *
 * The server returns this shape (verified against a live vpnd):
 * ```
 * {"id":"pe_…","peer_id":"pe_…","device_id":"dev_…","status":"active",
 *  "interface":{"addresses":["10.66.0.2/32","fd00:66::2/128"],"dns":["10.66.0.1"],
 *               "mtu":1420,"persistent_keepalive":25,"private_key":null},
 *  "server":{"id":"srv_default","endpoint":"vpn.example.com:51820",
 *            "public_key":"<base64>","allowed_ips":["0.0.0.0/0","::/0"]}}
 * ```
 *
 * `private_key` is deliberately null: the client generates and keeps its own key
 * (ADR-0007). There is no code path here that could accept a private key from the
 * server, which is the point.
 */
data class PeerConfig(
    val peerId: String,
    val deviceId: String,
    val status: String,
    val addresses: List<String>,
    val dnsServers: List<String>,
    val mtu: Int,
    val persistentKeepaliveSeconds: Int,
    val serverEndpoint: String,
    /** Base64, exactly as wg-quick and the official clients want it. */
    val serverPublicKey: String,
    val allowedIps: List<String>,
) {
    /** Host part of `host:port`, tolerating a bracketed IPv6 literal. */
    val serverHost: String
        get() = if (serverEndpoint.startsWith("[")) {
            serverEndpoint.substringAfter('[').substringBefore(']')
        } else {
            serverEndpoint.substringBeforeLast(':')
        }

    val serverPort: Int
        get() = when {
            serverEndpoint.startsWith("[") -> serverEndpoint.substringAfter("]:").toIntOrNull()
            else -> serverEndpoint.substringAfterLast(':').toIntOrNull()
        } ?: 51820
}

object PeerConfigParser {
    /**
     * Parses the peer payload. Throws [IllegalArgumentException] with a message that
     * names the missing field, because a half-parsed tunnel configuration is worse
     * than a loud failure at onboarding time.
     */
    @JvmStatic
    fun parse(body: String): PeerConfig {
        val root = JSONObject(body)
        val iface = root.optJSONObject("interface")
            ?: throw IllegalArgumentException("missing 'interface' block")
        val server = root.optJSONObject("server")
            ?: throw IllegalArgumentException("missing 'server' block")

        val addresses = stringList(iface, "addresses")
        if (addresses.isEmpty()) {
            throw IllegalArgumentException("missing 'interface.addresses'")
        }
        val endpoint = server.optString("endpoint", "")
        if (endpoint.isEmpty()) throw IllegalArgumentException("missing 'server.endpoint'")
        val serverKey = server.optString("public_key", "")
        if (serverKey.isEmpty()) throw IllegalArgumentException("missing 'server.public_key'")

        // A private key must never come from the server. Failing loudly here makes
        // that invariant executable rather than a sentence in a document.
        if (!iface.isNull("private_key")) {
            throw IllegalArgumentException("server sent a private_key; refusing it (ADR-0007)")
        }

        return PeerConfig(
            peerId = root.optString("peer_id", root.optString("id", "")),
            deviceId = root.optString("device_id", ""),
            status = root.optString("status", "active"),
            addresses = addresses,
            dnsServers = stringList(iface, "dns"),
            mtu = iface.optInt("mtu", 1420),
            persistentKeepaliveSeconds = iface.optInt("persistent_keepalive", 25),
            serverEndpoint = endpoint,
            serverPublicKey = serverKey,
            allowedIps = stringList(server, "allowed_ips"),
        )
    }

    private fun stringList(parent: JSONObject, name: String): List<String> {
        val array = parent.optJSONArray(name) ?: return emptyList()
        return (0 until array.length()).map { array.optString(it, "") }.filter { it.isNotEmpty() }
    }
}
