package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject

/** Consumes only the already verified, encrypted country configuration.
 * Never expose these fields in diagnostics or fall back to an unchained SOCKS dial. */
internal class BifrostSmartGateSocks private constructor(
    private val host: String, private val port: Int, private val user: String, private val password: String,
    private val udp: Boolean,
) {
    fun singBox(tag: String, front: String): JSONObject = JSONObject().put("type", "socks").put("tag", tag)
        .put("server", host).put("server_port", port).put("version", "5")
        .put("username", user).put("password", password).put("detour", front)
        .also { if (!udp) it.put("network", "tcp") }

    fun xray(tag: String, front: String): JSONObject = JSONObject().put("protocol", "socks").put("tag", tag)
        .put("settings", JSONObject().put("servers", JSONArray().put(JSONObject()
            .put("address", host).put("port", port).put("users", JSONArray().put(JSONObject().put("user", user).put("pass", password))))))
        .put("proxySettings", JSONObject().put("tag", front).put("transportLayer", true))

    companion object {
        fun fromCountry(country: JSONObject?): BifrostSmartGateSocks? {
            if (country == null || !country.has("socks")) return null // Legacy opaque country profile.
            check(country.optString("status") == "enabled") { "BF-COUNTRY-NOT-AVAILABLE" }
            val socks = country.optJSONObject("socks") ?: error("BF-SMARTGATE-SOCKS")
            check(socks.optString("scheme") in setOf("socks5", "socks5h")) { "BF-SMARTGATE-SOCKS" }
            val host = socks.optString("host").trim()
            check(host.isNotEmpty() && host.length <= 253 && host.none { it.isWhitespace() || it.isISOControl() || it in "/\\@" }) { "BF-SMARTGATE-SOCKS" }
            val port = socks.optInt("port")
            check(port in 1..65535) { "BF-SMARTGATE-SOCKS" }
            fun credential(key: String, max: Int): String = socks.optString(key).also {
                check(it.isNotEmpty() && it.length <= max && it.none(Char::isISOControl)) { "BF-SMARTGATE-SOCKS" }
            }
            return BifrostSmartGateSocks(host, port, credential("user", 128), credential("password", 256), country.optBoolean("udp"))
        }

        fun fronts(payload: JSONObject, country: JSONObject, requested: String?, automatic: Boolean, selectedSource: String): List<JSONObject> {
            val options = country.optJSONArray("front_source_options") ?: error("BF-SMARTGATE-FRONT-NOT-MAPPED")
            val codes = (0 until options.length()).map { options.getString(it) }.distinct()
            check(codes.isNotEmpty() && codes.size <= 2 && codes.all { it in setOf("A", "B") }) { "BF-SMARTGATE-FRONT-NOT-MAPPED" }
            val explicit = requested?.trim()?.takeIf { it.isNotEmpty() && !it.equals("auto", true) }
            val chosen = if (explicit != null) listOf(explicit)
                else if (automatic) codes
                else listOf(selectedSource.takeIf { it in codes } ?: country.optString("front_source_code"))
            check(chosen.all { it in codes }) { "BF-SMARTGATE-FRONT-NOT-MAPPED" }
            val sources = payload.getJSONArray("sources")
            return chosen.map { code ->
                (0 until sources.length()).map { sources.getJSONObject(it) }.singleOrNull { it.optString("code") == code && it.optBoolean("configured") }
                    ?: error("BF-SMARTGATE-FRONT-NOT_READY")
            }
        }
    }
}
