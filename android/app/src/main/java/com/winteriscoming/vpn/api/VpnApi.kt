// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
package com.winteriscoming.vpn.api

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Thin client for the vpnd REST API. Endpoints are the ones documented in
 * docs/API.md and verified against a live server; the shapes here are the ones the
 * server actually returns today, not the aspirational ones.
 */
class VpnApi(baseUrl: String, private val http: OkHttpClient = defaultClient()) {

    private val base = baseUrl.trimEnd('/')

    @Volatile
    var accessToken: String? = null

    data class Session(val userId: String, val role: String, val accessToken: String)

    fun login(email: String, password: String): Session {
        val body = JSONObject().put("email", email).put("password", password)
        val json = post("/api/v1/auth/login", body, token = null)
        val session = Session(
            userId = json.optString("user_id"),
            role = json.optString("role", "user"),
            accessToken = json.getString("access_token"),
        )
        accessToken = session.accessToken
        return session
    }

    /** Rotates the token: the old value dies server-side, so a leak has a short life. */
    fun rotateToken(): Session {
        val json = post("/api/v1/auth/rotate", JSONObject(), token = requireToken())
        val session = Session(
            userId = json.optString("user_id"),
            role = json.optString("role", "user"),
            accessToken = json.getString("access_token"),
        )
        accessToken = session.accessToken
        return session
    }

    /** `/me` reports plan and days_left so the UI can show "expires in N days". */
    fun me(): JSONObject = get("/api/v1/me", requireToken())

    fun createDevice(name: String, platform: String = "android"): String {
        val body = JSONObject().put("name", name).put("platform", platform)
        return post("/api/v1/devices", body, requireToken()).getString("id")
    }

    /**
     * Uploads the device public key. Mandatory before peer creation: the server
     * rejects a peer for a device with no key, so onboarding has a fixed order.
     */
    fun uploadDeviceKey(deviceId: String, publicKeyHex: String) {
        put("/api/v1/devices/$deviceId/key", JSONObject().put("public_key", publicKeyHex), requireToken())
    }

    /** Creates (or returns) the peer and its full tunnel configuration. */
    fun createPeer(deviceId: String): PeerConfig =
        PeerConfigParser.parse(post("/api/v1/peers", JSONObject().put("device_id", deviceId), requireToken()).toString())

    fun listServers(): JSONObject = get("/api/v1/servers", requireToken())

    private fun requireToken(): String =
        accessToken ?: throw IllegalStateException("not logged in")

    private fun get(path: String, token: String?): JSONObject =
        execute(Request.Builder().url(base + path).get(), token)

    private fun post(path: String, body: JSONObject, token: String?): JSONObject =
        execute(
            Request.Builder().url(base + path).post(body.toString().toRequestBody(JSON)),
            token,
        )

    private fun put(path: String, body: JSONObject, token: String?): JSONObject =
        execute(
            Request.Builder().url(base + path).put(body.toString().toRequestBody(JSON)),
            token,
        )

    private fun execute(builder: Request.Builder, token: String?): JSONObject {
        if (token != null) builder.header("Authorization", "Bearer $token")
        builder.header("Accept", "application/json")
        http.newCall(builder.build()).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(response.code, problemDetail(text))
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        }
    }

    private fun problemDetail(text: String): String =
        runCatching { JSONObject(text).optString("detail", text) }.getOrDefault(text)

    class ApiException(val status: Int, override val message: String) : Exception(message) {
        /**
         * True when the plan has lapsed. The server answers `403 access_expired`, and
         * the UI must offer renewal rather than a retry button (ADR-0010).
         */
        val renewalRequired: Boolean get() = status == 403
    }

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}
