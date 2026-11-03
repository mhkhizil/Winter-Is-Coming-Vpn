// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
package com.winteriscoming.vpn.api

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the client/server contract on the JVM, so a server-side change to the peer
 * payload breaks this test rather than a release. The fixture is a real response
 * captured from `vpnctl peers create` against a live vpnd.
 */
class PeerConfigParserTest {

    private val liveResponse = """
        {"id":"pe_3996cbc6667065af480041023d8cb0b7","peer_id":"pe_3996cbc6667065af480041023d8cb0b7",
         "device_id":"dev_bc9b485a9d61dcbcc59f8fffca5919d5","status":"active",
         "interface":{"addresses":["10.66.0.2/32","fd00:66::2/128"],"dns":["10.66.0.1"],
                      "mtu":1420,"persistent_keepalive":25,"private_key":null},
         "server":{"id":"srv_default","endpoint":"vpn.example.com:51820",
                   "public_key":"A4uR6Gx3e1rXgaEcbAo1rNurUIlxfbSgP5UhRU7NpCw=",
                   "allowed_ips":["0.0.0.0/0","::/0"]}}
    """.trimIndent()

    @Test
    fun parsesTheLiveServerPayload() {
        val config = PeerConfigParser.parse(liveResponse)
        assertEquals("pe_3996cbc6667065af480041023d8cb0b7", config.peerId)
        assertEquals("dev_bc9b485a9d61dcbcc59f8fffca5919d5", config.deviceId)
        assertEquals("active", config.status)
        assertEquals(listOf("10.66.0.2/32", "fd00:66::2/128"), config.addresses)
        assertEquals(listOf("10.66.0.1"), config.dnsServers)
        assertEquals(1420, config.mtu)
        assertEquals(25, config.persistentKeepaliveSeconds)
        assertEquals("vpn.example.com:51820", config.serverEndpoint)
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals(51820, config.serverPort)
        assertEquals(listOf("0.0.0.0/0", "::/0"), config.allowedIps)
    }

    @Test
    fun keepsTheServerKeyVerbatimSoBase64IsNotMangled() {
        // '=' padding is the classic casualty of "helpful" normalisation.
        val config = PeerConfigParser.parse(liveResponse)
        assertTrue(config.serverPublicKey.endsWith("="))
        assertEquals(44, config.serverPublicKey.length)
    }

    @Test
    fun toleratesABracketedIpv6Endpoint() {
        val config = PeerConfigParser.parse(
            liveResponse.replace("vpn.example.com:51820", "[fd00:66::1]:51820"),
        )
        assertEquals("fd00:66::1", config.serverHost)
        assertEquals(51820, config.serverPort)
    }

    @Test
    fun refusesAPrivateKeyFromTheServer() {
        // ADR-0007: the server must never see, store or return a client private key.
        val tampered = liveResponse.replace("\"private_key\":null", "\"private_key\":\"abc=\"")
        val error = assertThrows(IllegalArgumentException::class.java) {
            PeerConfigParser.parse(tampered)
        }
        assertTrue(error.message!!.contains("private_key"))
    }

    @Test
    fun namesTheMissingField() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            PeerConfigParser.parse("""{"interface":{"addresses":["10.66.0.2/32"]}}""")
        }
        assertTrue(error.message!!.contains("server"))
    }
}
