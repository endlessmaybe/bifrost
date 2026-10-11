package com.bifrost.client

import java.net.URI
import org.json.JSONArray
import org.json.JSONObject

/**
 * Compiles a signed control package into the shared libbox TUN bridge.
 *
 * Xray is an in-process transport selected by [BifrostCoreAdapter]; libbox
 * still owns the Android TUN, DNS and routing boundary.  When [xrayPort] is
 * non-zero the bridge sends all proxy traffic to the Xray loopback SOCKS
 * listener.  There is no silent fallback: a missing/invalid port is rejected.
 */
object BifrostConfigCompiler {
    fun compile(
        content: String,
        sourceCode: String,
        countryCode: String,
        mode: String,
        core: String,
        includePackages: List<String> = emptyList(),
        excludePackages: List<String> = emptyList(),
        selectedCandidate: String? = null,
        xrayPort: Int = 0,
        frontSourceCode: String? = null,
        appPolicyMode: String = "allow",
        applicationPolicy: BifrostApplicationPolicySnapshot,
        candidateMode: String = "manual",
        routingRulesDirectory: String = "routing",
        candidateLabels: MutableMap<String, String>? = null,
    ): String {
        require(core == "auto" || core == "sing-box" || core == "xray") { "BF-CORE-UNSUPPORTED-ANDROID" }
        require(mode in setOf("smart", "global", "per-app")) { "BF-MODE" }
        require(candidateMode in setOf("auto", "manual")) { "BF-CANDIDATE-MODE" }
        val policy = resolveApplicationPolicy(mode, appPolicyMode, includePackages, excludePackages, applicationPolicy)
        if (core == "xray") require(xrayPort in 1..65535) { "BF-XRAY-TRANSPORT-NOT-READY" }
        val payload = JSONObject(content)
        val source = payload.optJSONArray("sources")?.findObject { it.optString("code") == sourceCode }
            ?: error("BF-SOURCE-NOT_FOUND")
        check(source.optBoolean("configured", false)) { "BF-SOURCE-NOT_READY" }
        val candidate = chooseCandidate(source, selectedCandidate)
        val country = if (countryCode != "auto") {
            payload.optJSONArray("countries")?.findObject { it.optString("code") == countryCode }
                ?: error("BF-COUNTRY-NOT_FOUND")
        } else null
        if (country != null) {
            // Disabled/maintenance countries may remain in a signed package
            // for recovery, but a new connection must fail closed rather than
            // silently selecting another country or profile.
            check(country.optString("status", "enabled") == "enabled") { "BF-COUNTRY-NOT-AVAILABLE" }
        }
        // Current signed packages describe VMess front -> country SOCKS, as on
        // Windows. Older packages without socks retain the opaque profile path.
        val directProfile = source.optJSONObject("profiles")?.optJSONObject("direct") ?: error("BF-PROFILE")
        val countrySocks = BifrostSmartGateSocks.fromCountry(country)
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
            val frontCandidate = chooseCandidate(frontSource, null)
            val frontProfile = frontSource.optJSONObject("profiles")?.optJSONObject("direct")
                ?: error("BF-SMARTGATE-FRONT-PROFILE")
            buildVmess(frontSource, frontCandidate, frontProfile, "front-vmess")
        } else vmess

        // A mapped alternate source is a real first hop, not metadata.  The
        // selected country's opaque profile remains on `proxy`; its socket
        // is detoured through the front VMess outbound before reaching the
        // node-owned country egress.
        if (frontSource !== source) vmess.put("detour", "front-vmess")

        candidateLabels?.clear()
        candidateLabels?.put("proxy", candidate.getString("label"))
        val outbounds = JSONArray()
        if (countrySocks == null && frontSource !== source) {
            if (candidateMode == "auto" && core != "xray")
                addAutomaticGroup(outbounds, frontSource, frontSource.getJSONObject("profiles").getJSONObject("direct"), "front-vmess", null, labels = candidateLabels)
            else outbounds.put(frontVmess)
        }
        var finalTag: String
        if (core == "xray") {
            // Xray owns VMess and optional SmartGate hop; libbox is a strict
            // local SOCKS bridge and cannot accidentally bypass the transport.
            outbounds.put(JSONObject().put("type", "socks").put("tag", "xray-transport")
                .put("server", "127.0.0.1").put("server_port", xrayPort))
            finalTag = "xray-transport"
        } else if (countrySocks != null) {
            addSmartGateGroup(outbounds, payload, country!!, countrySocks, sourceCode, frontSourceCode, selectedCandidate, candidateMode == "auto", candidateLabels)
            finalTag = "proxy"
        } else {
            if (candidateMode == "auto")
                addAutomaticGroup(outbounds, source, vmessProfile, "proxy", if (frontSource !== source) "front-vmess" else null, selectedCandidate, candidateLabels)
            else outbounds.put(vmess)
            finalTag = "proxy"
            // SmartGate's country SOCKS hop is selected by the node from the
            // opaque country VMess profile.  Keeping the device graph to a
            // VMess outbound also means no country host/user/password can be
            // leaked through compiled configs or logs.
        }
        outbounds.put(JSONObject().put("type", "direct").put("tag", "direct"))
        outbounds.put(JSONObject().put("type", "block").put("tag", "block"))

        val dnsPolicy = payload.optJSONObject("routing")?.optJSONObject("dns_policy")
            ?: payload.optJSONObject("dns_policy")
            ?: error("BF-CONFIG-DNS")
        check(dnsPolicy.keys().asSequence().toSet() == setOf("version", "remote", "direct", "smart_gate_remote", "plaintext_fallback", "ipv4", "ipv6", "failure")) { "BF-CONFIG-DNS-SCHEMA" }
        check(dnsPolicy.optString("version") == "dns-policy-v1" && dnsPolicy.optBoolean("smart_gate_remote") && dnsPolicy.optString("failure") == "block") { "BF-CONFIG-DNS-POLICY" }
        check(dnsPolicy.optString("ipv4") in setOf("proxy", "block") && dnsPolicy.optString("ipv6") in setOf("proxy", "block")) { "BF-CONFIG-DNS-POLICY" }
        check(!dnsPolicy.optBoolean("plaintext_fallback", true)) { "BF-CONFIG-DNS-PLAINTEXT" }
        val remoteDns = httpsUrl(dnsPolicy.optString("remote"))
        val directDns = httpsUrl(dnsPolicy.optString("direct"))
        val remoteDnsRuleHost = dnsRuleHost(remoteDns)
        val directDnsRuleHost = dnsRuleHost(directDns)
        val dnsServers = JSONArray()
            .put(httpsDnsServer(remoteDns, "remote-dns", finalTag, null))
            // Bootstrap the direct resolver without first consulting the
            // proxied resolver. This keeps domestic/direct DNS independent
            // from proxy health while preserving an encrypted-only boundary.
            .put(directBootstrapDnsServer())
            .put(directHttpsDnsServer(directDns))
        // Android may still choose an AAAA answer ahead of A even when the
        // resolver says prefer_ipv4. A v4-only gateway then resets TLS and
        // HttpURLConnection does not retry the working IPv4 address. Resolve
        // bootstrap names using IPv4 when the signed policy permits it.
        // Dual-stack application queries are virtualized below so an app's
        // IPv6 socket can still use a working IPv4 egress after name recovery.
        val dnsStrategy = if (dnsPolicy.optString("ipv4") == "proxy") "ipv4_only" else "ipv6_only"
        val dns = JSONObject()
            .put("servers", dnsServers)
            .put("final", "remote-dns")
            .put("strategy", dnsStrategy)
            // Match Windows: health/bootstrap hostnames are always resolved
            // with the direct encrypted resolver, including global/per-app
            // modes, so candidate health never depends on the candidate that
            // is currently being selected.
            .put("rules", JSONArray().put(
                JSONObject()
                    .put("domain", JSONArray(BifrostRoutingRules.healthBootstrapDnsDomains))
                    .put("action", "route")
                    .put("server", "direct-dns"),
            ))

        val rules = JSONArray()
            // L3 TUN traffic must be sniffed before domain rules, and every
            // DNS request is hijacked into the encrypted sing-box DNS module.
            .put(JSONObject().put("action", "sniff"))
            .put(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
        BifrostRoutingRules.preserveYoutubeUdp(rules)
        rules
            // Private/link-local traffic is the only mandatory global bypass.
            .put(JSONObject().put("ip_is_private", true).put("outbound", "direct"))
        // Package selection is enforced again by VpnService.Builder. Ordinary
        // smart mode, including country egress, shares Windows domain/IP policy.
        if (mode == "per-app") {
            val include = JSONArray().also { policy.includePackages.forEach(it::put) }
            val exclude = JSONArray().also { policy.excludePackages.forEach(it::put) }
            if (policy.policyMode == "allow") {
                rules.put(JSONObject().put("package_name", include).put("outbound", finalTag))
                if (exclude.length() > 0) rules.put(JSONObject().put("package_name", exclude).put("outbound", "direct"))
            } else {
                rules.put(JSONObject().put("package_name", exclude).put("outbound", "direct"))
                if (include.length() > 0) rules.put(JSONObject().put("package_name", include).put("outbound", finalTag))
            }
        }
        val routing = JSONObject()
            .put("auto_detect_interface", true)
            .put("default_domain_resolver", JSONObject().put("server", "remote-dns"))
            .put("final", finalTag)
            .put("rules", rules)
        if (mode == "smart") {
            BifrostRoutingRules.apply(
                routing,
                dns,
                finalTag,
                routingRulesDirectory,
                remoteDnsRuleHost,
                directDnsRuleHost,
            )
        }
        val dualStack = dnsPolicy.optString("ipv4") == "proxy" && dnsPolicy.optString("ipv6") == "proxy"
        if (dualStack) BifrostDualStackDns.configure(dns, routing, outbounds)
        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("dns", dns)
            .put("inbounds", JSONArray().put(JSONObject()
                .put("type", "tun").put("tag", "tun-in").put("interface_name", "bifrost0")
                .put("address", JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                .put("mtu", 1500)
                // Keep TCP forwarding inside the core. The system TCP listener
                // used by mixed can disappear during Android VPN recreation
                // while the loopback health proxy still reports success.
                .put("auto_route", true).put("strict_route", true).put("stack", "gvisor")))
            .put("outbounds", outbounds)
            .put("route", routing)
            .apply { if (dualStack) put("experimental", JSONObject().put("cache_file",
                JSONObject().put("enabled", true).put("store_fakeip", true))) }
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
        val candidates = source.optJSONArray("candidates") ?: error("BF-SOURCE-CANDIDATE")
        val wanted = selected?.takeIf(String::isNotBlank)
            ?: source.optString("selected_candidate").takeIf(String::isNotBlank)
        return (0 until candidates.length()).mapNotNull { candidates.optJSONObject(it) }
            .firstOrNull {
                wanted == null || wanted.equals(it.optString("id"), true) || wanted.equals(it.optString("code"), true) ||
                    wanted.equals(it.optString("label"), true) || wanted.equals(it.optString("dial_address"), true)
            }
            ?: error("BF-SOURCE-CANDIDATE-NOT_FOUND")
    }

    /**
     * `auto` is a UI sentinel, never a source code.  An explicit source is
     * accepted only when the signed country mapping authorizes it; an absent
     * mapping deterministically falls back to the selected source for auto,
     * but rejects an explicit alternate instead of silently bypassing it.
     */
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
        val path = source.optString("ws_path").trim().ifBlank { "/" }
        return JSONObject()
            .put("type", "vmess")
            .put("tag", tag)
            .put("server", candidate.optString("dial_address"))
            .put("server_port", candidate.optInt("port", 443))
            .put("uuid", profile.optString("uuid"))
            .put("security", transport.optString("security", "auto"))
            .put("alter_id", transport.optInt("alter_id", 0))
            .put("tls", JSONObject()
                .put("enabled", transport.optBoolean("tls", true))
                .put("server_name", sni)
                .put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
                .put("insecure", false))
            .put("transport", JSONObject()
                .put("type", transport.optString("network", "ws"))
                .put("path", if (path.startsWith('/')) path else "/$path")
                .put("headers", JSONObject().put("Host", host)))
    }

    /** The transport preflight is only a seed. Real HTTPS tests and failover
     * belong to the running core, using the same source/profile as traffic. */
    private fun addAutomaticGroup(outbounds: JSONArray, source: JSONObject, profile: JSONObject, tag: String, detour: String?, preferredLabel: String? = null, labels: MutableMap<String, String>? = null) {
        labels?.remove(tag)
        val candidates = source.getJSONArray("candidates")
        check(candidates.length() in 1..300) { "BF-CANDIDATE-MISSING" }
        val tags = JSONArray()
        // Keep leaf identifiers bound to signed candidate order. A persisted
        // winner may lead URLTest's preference list, but its leaf tag never
        // changes identity.
        for (index in 0 until candidates.length()) {
            val candidate = candidates.getJSONObject(index)
            val declaredSource = candidate.optString("source_code")
            check(declaredSource.isBlank() || declaredSource.equals(source.optString("code"), true)) { "BF-CANDIDATE-SOURCE-MISMATCH" }
            val candidateTag = "$tag-candidate-$index"
            labels?.put(candidateTag, candidate.getString("label"))
            val outbound = buildVmess(source, candidate, profile, candidateTag)
            if (detour != null) outbound.put("detour", detour)
            outbounds.put(outbound)
            tags.put(candidateTag)
        }
        val urlTestTags = JSONArray()
        val preferredTag = preferredLabel?.let { preferred ->
            (0 until candidates.length()).firstOrNull {
                candidates.getJSONObject(it).optString("label") == preferred
            }?.let { "$tag-candidate-$it" }
        }
        if (preferredTag != null) urlTestTags.put(preferredTag)
        for (index in 0 until tags.length()) {
            val candidateTag = tags.getString(index)
            if (candidateTag != preferredTag) urlTestTags.put(candidateTag)
        }
        outbounds.put(JSONObject().put("type", "urltest").put("tag", "$tag-auto").put("outbounds", urlTestTags)
            .put("url", "https://www.gstatic.com/generate_204").put("interval", "1m")
            .put("tolerance", BifrostNodeQuality.AUTO_SELECT_TOLERANCE_MS).put("idle_timeout", "5m").put("interrupt_exist_connections", false))
        val selections = JSONArray().put("$tag-auto")
        for (index in 0 until urlTestTags.length()) selections.put(urlTestTags.getString(index))
        outbounds.put(JSONObject().put("type", "selector").put("tag", tag).put("outbounds", selections)
            .put("default", "$tag-auto").put("interrupt_exist_connections", false))
    }

    private fun addSmartGateGroup(outbounds: JSONArray, payload: JSONObject, country: JSONObject, socks: BifrostSmartGateSocks,
        sourceCode: String, requestedFront: String?, selectedCandidate: String?, automatic: Boolean, labels: MutableMap<String, String>? = null) {
        labels?.remove("proxy")
        val tags = JSONArray()
        val seen = mutableSetOf<String>()
        val preferredTag = if (automatic) preferredSmartGateTag(
            payload, country, requestedFront, sourceCode, selectedCandidate
        ) else null
        var index = 0
        for (front in BifrostSmartGateSocks.fronts(payload, country, requestedFront, automatic, sourceCode)) {
            val candidates = front.getJSONArray("candidates")
            check(candidates.length() in 1..300) { "BF-CANDIDATE-MISSING" }
            val seed = if (front.optString("code") == sourceCode) selectedCandidate else null
            val members = if (!automatic) listOf(chooseCandidate(front, seed)) else
                (0 until candidates.length()).map { candidates.getJSONObject(it) }
            val direct = front.getJSONObject("profiles").getJSONObject("direct")
            for (member in members) {
                check(seen.add(member.getString("label"))) { "BF-CANDIDATE-LABEL-DUPLICATE" }
                val frontTag = "smartgate-front-${index}"
                val tag = if (automatic) "proxy-candidate-${index}" else "proxy"
                index++
                labels?.put(tag, member.getString("label"))
                outbounds.put(buildVmess(front, member, direct, frontTag))
                outbounds.put(socks.singBox(tag, frontTag))
                tags.put(tag)
            }
        }
        if (automatic) {
            val urlTestTags = JSONArray()
            if (preferredTag != null) urlTestTags.put(preferredTag)
            for (i in 0 until tags.length()) {
                val candidateTag = tags.getString(i)
                if (candidateTag != preferredTag) urlTestTags.put(candidateTag)
            }
            outbounds.put(JSONObject().put("type", "urltest").put("tag", "proxy-auto").put("outbounds", urlTestTags)
                .put("url", "https://www.gstatic.com/generate_204").put("interval", "1m")
                .put("tolerance", BifrostNodeQuality.AUTO_SELECT_TOLERANCE_MS).put("idle_timeout", "5m").put("interrupt_exist_connections", false))
            val choices = JSONArray().put("proxy-auto")
            for (i in 0 until urlTestTags.length()) choices.put(urlTestTags.getString(i))
            outbounds.put(JSONObject().put("type", "selector").put("tag", "proxy").put("outbounds", choices)
                .put("default", "proxy-auto").put("interrupt_exist_connections", false))
        }
    }

    private fun preferredSmartGateTag(
        payload: JSONObject,
        country: JSONObject,
        requestedFront: String?,
        sourceCode: String,
        selectedCandidate: String?,
    ): String? {
        if (selectedCandidate.isNullOrBlank()) return null
        var index = 0
        for (front in BifrostSmartGateSocks.fronts(payload, country, requestedFront, true, sourceCode)) {
            val candidates = front.getJSONArray("candidates")
            for (candidateIndex in 0 until candidates.length()) {
                val candidate = candidates.getJSONObject(candidateIndex)
                if (front.optString("code") == sourceCode && candidate.optString("label") == selectedCandidate) {
                    return "proxy-candidate-" + index
                }
                index++
            }
        }
        return null
    }

    private fun httpsDnsServer(value: String, tag: String, detour: String, domainResolver: String?): JSONObject {
        val validated = httpsUrl(value)
        val uri = URI(validated)
        val host = uri.host.lowercase().trimEnd('.')
        val server = JSONObject()
            .put("type", "https")
            .put("tag", tag)
            .put("server", host)
            .put("server_port", if (uri.port == -1) 443 else uri.port)
            .put("path", uri.rawPath.ifBlank { "/dns-query" })
            .put("tls", JSONObject().put("enabled", true).put("server_name", host))
        // A typed HTTPS DNS server already dials directly when detour is
        // absent. libbox rejects detouring through an unconfigured direct
        // outbound during service startup.
        if (detour != "direct") server.put("detour", detour)
        // `detour` carries the protected remote DNS hostname through a
        // domain-capable VMess/SOCKS hop, so remote-dns must not depend on
        // itself. The direct encrypted resolver is bootstrapped by remote-dns
        // instead of system/plaintext DNS.
        if (domainResolver != null) {
            server.put("domain_resolver", JSONObject().put("server", domainResolver))
        }
        return server
    }

    /**
     * Pin the transport address so direct DNS never needs plaintext/system
     * bootstrap, but authenticate the canonical provider hostname. Keeping
     * the IP only as the transport address preserves loop freedom while the
     * normal hostname certificate identity remains in use. The query remains
     * HTTPS-only. Unknown operator-provided resolvers keep the hostname plus
     * encrypted bootstrap path below.
     */
    private fun directHttpsDnsServer(value: String): JSONObject {
        val validated = httpsUrl(value)
        val uri = URI(validated)
        val host = uri.host.lowercase().trimEnd('.')
        val pinnedIp = when (host) {
            "dns.alidns.com" -> "223.5.5.5"
            "doh.pub" -> "1.12.12.12"
            else -> null
        }
        if (pinnedIp == null) return httpsDnsServer(validated, "direct-dns", "direct", "direct-bootstrap-dns")
        return JSONObject()
            .put("type", "https")
            .put("tag", "direct-dns")
            .put("server", pinnedIp)
            .put("server_port", if (uri.port == -1) 443 else uri.port)
            .put("path", uri.rawPath.ifBlank { "/dns-query" })
            // Destination stays pinned, so this canonical SNI/authority does
            // not require another resolver lookup.
            .put("headers", JSONObject().put("Host", host))
            .put("tls", JSONObject().put("enabled", true).put("server_name", host))
    }

    private fun dnsRuleHost(value: String): String? {
        val host = URI(value).host.lowercase().trimEnd('.')
        val ipv4 = host.split('.').let { parts ->
            parts.size == 4 && parts.all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }
        }
        return host.takeUnless { ipv4 || ':' in it }
    }

    private fun directBootstrapDnsServer(): JSONObject = JSONObject()
        .put("type", "https")
        .put("tag", "direct-bootstrap-dns")
        // This endpoint is used only to resolve the configured direct DoH
        // hostname. Supplying the address directly removes the DNS bootstrap
        // loop; TLS still authenticates the canonical AliDNS hostname.
        .put("server", "223.5.5.5")
        .put("server_port", 443)
        .put("path", "/dns-query")
        // Dial the fixed address but authenticate the canonical provider.
        .put("headers", JSONObject().put("Host", "dns.alidns.com"))
        .put("tls", JSONObject().put("enabled", true).put("server_name", "dns.alidns.com"))

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
