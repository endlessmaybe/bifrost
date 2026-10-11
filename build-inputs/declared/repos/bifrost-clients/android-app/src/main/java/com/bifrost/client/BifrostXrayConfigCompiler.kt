package com.bifrost.client

import java.net.URI
import org.json.JSONArray
import org.json.JSONObject

/** Builds the Xray transport side of the Android shared-TUN bridge. */
object BifrostXrayConfigCompiler {
    fun compile(
        content: String,
        sourceCode: String,
        countryCode: String,
        selectedCandidate: String? = null,
        frontSourceCode: String? = null,
        mode: String = "smart",
        includePackages: List<String> = emptyList(),
        excludePackages: List<String> = emptyList(),
        appPolicyMode: String = "allow",
        applicationPolicy: BifrostApplicationPolicySnapshot,
    ): String {
        require(mode in setOf("smart", "global", "per-app")) { "BF-MODE" }
        resolveApplicationPolicy(mode, appPolicyMode, includePackages, excludePackages, applicationPolicy)
        val payload = JSONObject(content)
        val source = payload.optJSONArray("sources")?.findObject { it.optString("code") == sourceCode }
            ?: error("BF-SOURCE-NOT_FOUND")
        check(source.optBoolean("configured", false)) { "BF-SOURCE-NOT_READY" }
        val country = if (countryCode != "auto") {
            payload.optJSONArray("countries")?.findObject { it.optString("code") == countryCode }
                ?: error("BF-COUNTRY-NOT_FOUND")
        } else null
        if (country != null) check(country.optString("status", "enabled") == "enabled") { "BF-COUNTRY-NOT-AVAILABLE" }
        val countrySocks = BifrostSmartGateSocks.fromCountry(country)
        val candidate = chooseCandidate(source, selectedCandidate)
        val directProfile = source.optJSONObject("profiles")?.optJSONObject("direct") ?: error("BF-PROFILE")
        val vmessProfile = if (country != null && countrySocks == null) {
            source.optJSONObject("profiles")?.optJSONObject("countries")?.optJSONObject(countryCode)
                ?: error("BF-COUNTRY-PROFILE")
        } else directProfile
        val vmess = buildVmess(source, candidate, vmessProfile, "proxy")
        val frontOptions = country?.optJSONArray("front_source_options")?.toStringList().orEmpty()
        val frontCode = resolveFrontCode(country, sourceCode, frontSourceCode, frontOptions)
        val frontSource = if (country != null && frontCode != sourceCode) {
            payload.optJSONArray("sources")?.findObject { it.optString("code") == frontCode } ?: error("BF-SMARTGATE-FRONT-NOT_FOUND")
        } else source
        val frontVmess = if (frontSource !== source) {
            check(frontSource.optBoolean("configured", false)) { "BF-SMARTGATE-FRONT-NOT_READY" }
            val frontProfile = frontSource.optJSONObject("profiles")?.optJSONObject("direct")
                ?: error("BF-SMARTGATE-FRONT-PROFILE")
            buildVmess(frontSource, chooseCandidate(frontSource, null), frontProfile, "front-vmess")
        } else null
        if (frontSource !== source) vmess.put("proxySettings", JSONObject().put("tag", "front-vmess"))
        val outbounds = JSONArray()
        if (countrySocks != null) {
            val front = BifrostSmartGateSocks.fronts(payload, country!!, frontSourceCode, false, sourceCode).single()
            val seed = if (front.optString("code") == sourceCode) selectedCandidate else null
            outbounds.put(buildVmess(front, chooseCandidate(front, seed), front.getJSONObject("profiles").getJSONObject("direct"), "front-vmess"))
            outbounds.put(countrySocks.xray("proxy", "front-vmess"))
        } else {
            if (frontVmess != null) outbounds.put(frontVmess)
            outbounds.put(vmess)
        }
        val finalTag = "proxy"
        outbounds.put(JSONObject().put("protocol", "freedom").put("tag", "direct"))
        outbounds.put(JSONObject().put("protocol", "blackhole").put("tag", "block"))
        // The embedded Android Xray transport has no geoip.dat loader. Spell
        // out local ranges so startup never depends on an unpackaged database.
        val localRanges = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")
        val routeRules = JSONArray()
            .put(JSONObject().put("type", "field").put("ip", JSONArray(localRanges)).put("outboundTag", "direct"))
        // The shared libbox bridge applies smart domain/IP and DNS routing
        // before proxy traffic reaches Xray, including SmartGate country mode.
        // This transport stage only needs a private/link-local safety bypass.
        // Per-application ownership is enforced by VpnService.Builder before
        // packets reach this shared TUN.  Xray intentionally has no fake
        // `app` rule extension here; its route remains valid for both cores.
        // Xray has no Bifrost-private final-tag extension.  An explicit
        // catch-all rule is required so SmartGate always resolves to
        // VMess -> SOCKS5 (or the selected VMess proxy) and never the first
        // outbound by accident.
        routeRules.put(JSONObject().put("network", "tcp,udp").put("outboundTag", finalTag))
        val routing = JSONObject().put("domainStrategy", "AsIs").put("rules", routeRules)
        val dnsPolicy = payload.optJSONObject("routing")?.optJSONObject("dns_policy")
            ?: payload.optJSONObject("dns_policy") ?: error("BF-CONFIG-DNS")
        check(dnsPolicy.keys().asSequence().toSet() == setOf("version", "remote", "direct", "smart_gate_remote", "plaintext_fallback", "ipv4", "ipv6", "failure")) { "BF-CONFIG-DNS-SCHEMA" }
        check(dnsPolicy.optString("version") == "dns-policy-v1" && dnsPolicy.optBoolean("smart_gate_remote") && dnsPolicy.optString("failure") == "block") { "BF-CONFIG-DNS-POLICY" }
        check(dnsPolicy.optString("ipv4") in setOf("proxy", "block") && dnsPolicy.optString("ipv6") in setOf("proxy", "block")) { "BF-CONFIG-DNS-POLICY" }
        check(!dnsPolicy.optBoolean("plaintext_fallback", true)) { "BF-CONFIG-DNS-PLAINTEXT" }
        val remoteDns = httpsUrl(dnsPolicy.optString("remote"))
        val directDns = httpsUrl(dnsPolicy.optString("direct"))
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            // The shared libbox TUN bridge owns DNS routing; Xray still uses
            // the same signed encrypted resolvers for resolving its upstream
            // VMess/SOCKS endpoints and never enables plaintext fallback.
            .put("dns", JSONObject().put("servers", JSONArray().put(remoteDns).put(directDns)).put("queryStrategy", "UseIPv4"))
            // The libbox bridge forwards UDP/QUIC through SOCKS5 UDP ASSOCIATE
            // as well as TCP CONNECT. Disabling this silently breaks that hop.
            .put("inbounds", JSONArray().put(JSONObject().put("listen", "127.0.0.1").put("port", 10808).put("protocol", "socks").put("tag", "xray-socks").put("settings", JSONObject().put("auth", "noauth").put("udp", true).put("ip", "127.0.0.1"))))
            .put("outbounds", outbounds)
            .put("routing", routing)
            .toString()
    }

    private fun resolveApplicationPolicy(
        mode: String,
        appPolicyMode: String,
        includePackages: List<String>,
        excludePackages: List<String>,
        supplied: BifrostApplicationPolicySnapshot,
    ): BifrostApplicationPolicySnapshot {
        val effectiveMode = if (mode == "per-app") appPolicyMode else "none"
        val verified = BifrostApplicationPolicy.verify(supplied)
        require(
            verified == supplied &&
                verified.routeMode == mode &&
                verified.policyMode == effectiveMode &&
                verified.includePackages == (if (mode == "per-app") includePackages else emptyList()) &&
                verified.excludePackages == (if (mode == "per-app") excludePackages else emptyList()),
        ) {
            "BF-APP-POLICY-SNAPSHOT"
        }
        return verified
    }

    private fun chooseCandidate(source: JSONObject, selected: String?): JSONObject {
        val list = source.optJSONArray("candidates") ?: error("BF-SOURCE-CANDIDATE")
        val wanted = selected?.takeIf(String::isNotBlank)
            ?: source.optString("preferred_candidate").takeIf(String::isNotBlank)
            ?: source.optString("selected_candidate").takeIf(String::isNotBlank)
        return (0 until list.length()).mapNotNull { list.optJSONObject(it) }
            .firstOrNull {
                wanted == null || wanted.equals(it.optString("id"), true) || wanted.equals(it.optString("code"), true) ||
                    wanted.equals(it.optString("label"), true) || wanted.equals(it.optString("dial_address"), true)
            }
            ?: error("BF-SOURCE-CANDIDATE-NOT_FOUND")
    }

    /** Keep the Xray compiler's SmartGate selection semantics identical to
     * the shared libbox compiler. */
    private fun resolveFrontCode(country: JSONObject?, sourceCode: String, requestedValue: String?, options: List<String>): String {
        val requested = normalizeFrontCode(requestedValue)
        val mapped = normalizeFrontCode(country?.optString("front_source_code"))
        val resolved = requested ?: mapped ?: sourceCode
        if (requested != null && (mapped != null || options.isNotEmpty())) {
            val explicitlyAuthorized = resolved in options || (options.isEmpty() && mapped == resolved)
            check(explicitlyAuthorized) { "BF-SMARTGATE-FRONT-NOT-MAPPED" }
        }
        if (resolved == sourceCode) return resolved
        val authorized = resolved in options || (options.isEmpty() && mapped == resolved)
        check(authorized) { "BF-SMARTGATE-FRONT-NOT-MAPPED" }
        return resolved
    }

    private fun normalizeFrontCode(value: String?): String? = value?.trim()
        ?.takeIf { it.isNotEmpty() && !it.equals("auto", ignoreCase = true) }

    private fun buildVmess(source: JSONObject, candidate: JSONObject, profile: JSONObject, tag: String): JSONObject {
        val transport = source.optJSONObject("transport") ?: error("BF-VMESS-NOT_READY")
        val serverName = source.optString("server_name").trim()
        val transportSni = transport.optString("sni").trim()
        val sni = transportSni.ifBlank { serverName }.ifBlank { candidate.optString("dial_address") }
        val host = transport.optString("host").trim().ifBlank { serverName }.ifBlank { sni }
        val rawPath = source.optString("ws_path").trim().ifBlank { "/" }
        val path = if (rawPath.startsWith('/')) rawPath else "/$rawPath"
        return JSONObject().put("protocol", "vmess").put("tag", tag).put("settings", JSONObject().put("vnext", JSONArray().put(
            JSONObject().put("address", candidate.optString("dial_address"))
                .put("port", candidate.optInt("port", 443))
                .put("users", JSONArray().put(JSONObject().put("id", profile.optString("uuid")).put("alterId", transport.optInt("alter_id", 0)).put("security", transport.optString("security", "auto"))))
        ))).put("streamSettings", JSONObject()
            .put("network", transport.optString("network", "ws"))
            .put("security", if (transport.optBoolean("tls", true)) "tls" else "none")
            .put("tlsSettings", JSONObject().put("serverName", sni).put("allowInsecure", false))
            .put("wsSettings", JSONObject().put("path", path).put("headers", JSONObject().put("Host", host))))
    }

    private fun httpsUrl(value: String): String {
        val trimmed = value.trim()
        check(!trimmed.contains("\n") && !trimmed.contains("\r")) { "BF-CONFIG-DNS-HTTPS" }
        val uri = try { URI(trimmed) } catch (_: Throwable) { error("BF-CONFIG-DNS-HTTPS") }
        check(uri.scheme.equals("https", true) && uri.userInfo == null && uri.query == null && uri.fragment == null && !uri.host.isNullOrBlank()) { "BF-CONFIG-DNS-HTTPS" }
        check(uri.port == -1 || uri.port == 443) { "BF-CONFIG-DNS-HTTPS" }
        val host = uri.host.lowercase().trimEnd('.')
        check(!host.equals("localhost") && !host.endsWith(".localhost") && !host.equals("test") && !host.endsWith(".test")) { "BF-CONFIG-DNS-HOST" }
        check(!host.matches(Regex("(?:\\d{1,3}\\.){3}\\d{1,3}")) && !host.startsWith("[") && !host.contains(":")) { "BF-CONFIG-DNS-HOST" }
        check(uri.rawPath?.startsWith("/") == true) { "BF-CONFIG-DNS-PATH" }
        return trimmed
    }

    private inline fun JSONArray.findObject(predicate: (JSONObject) -> Boolean): JSONObject? {
        for (index in 0 until length()) optJSONObject(index)?.let { if (predicate(it)) return it }
        return null
    }

    private fun JSONArray.toStringList(): List<String> = (0 until length()).mapNotNull { optString(it).takeIf(String::isNotBlank) }
}
