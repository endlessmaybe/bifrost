package com.bifrost.client

import java.io.File
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test

/** Exercise compiled policy against the shipped data, including service assets,
 * authentication, download endpoints and categories with overlapping membership. */
class BifrostRoutingMatrixTest {
    private val assets = File("src/main/assets/routing").absoluteFile
    private val cases = JSONObject(File("../tests/fixtures/routing-services-v1.json").readText()).getJSONArray("cases").objects()
    private data class Domains(val exact: Set<String>, val suffix: Set<String>, val keyword: List<String>, val regex: List<Regex>) {
        fun matches(host: String): Boolean {
            val labels = host.split('.')
            return host in exact || labels.indices.any { labels.drop(it).joinToString(".") in suffix } ||
                keyword.any(host::contains) || regex.any { it.containsMatchIn(host) }
        }
    }
    private val data = BifrostRoutingRules.categories.associateWith { tag ->
        val rules = JSONObject(File(assets, "$tag.json").readText()).getJSONArray("rules").objects()
        Domains(rules.flatMap { it.strings("domain") }.toSet(), rules.flatMap { it.strings("domain_suffix") }.map { it.trimStart('.') }.toSet(),
            rules.flatMap { it.strings("domain_keyword") }, rules.flatMap { it.strings("domain_regex") }.map(::Regex))
    }
    private fun JSONArray.objects() = (0 until length()).map(::getJSONObject)
    private fun JSONObject.strings(key: String): List<String> = optJSONArray(key)?.let { a -> (0 until a.length()).map(a::getString) }.orEmpty()
    private fun matches(rule: JSONObject, host: String): Boolean = host in rule.strings("domain") ||
        rule.strings("domain_suffix").any { host == it.trimStart('.') || host.endsWith("." + it.trimStart('.')) } ||
        rule.strings("domain_keyword").any { host.contains(it) } ||
        rule.strings("domain_regex").any { Regex(it).containsMatchIn(host) } ||
        rule.strings("rule_set").any { tag -> data.getValue(tag).matches(host) }
    private fun config(mode: String, core: String, country: String = "auto"): JSONObject = JSONObject(BifrostConfigCompiler.compile(
        SmartGateCompilerTest().fixture(), "A", country, mode, core,
        applicationPolicy = BifrostApplicationPolicy.normalize(mode, "none", emptyList(), emptyList()),
        xrayPort = if (core == "xray") 10808 else 0, routingRulesDirectory = assets.path))

    @Test fun serviceAndCdnMatrixUsesConsistentRouteAndDnsInSmartAndCountryModes() {
        for (core in listOf("sing-box", "xray")) for (country in listOf("auto", "CN")) {
            val compiled = config("smart", core, country)
            val route = compiled.getJSONObject("route")
            val dns = compiled.getJSONObject("dns")
            for (case in cases) {
                val host = case.getString("host")
                val expected = case.getString("smart")
                val rule = route.getJSONArray("rules").objects().firstOrNull { matches(it, host) }
                val actual = rule?.optString("outbound")?.takeIf(String::isNotEmpty) ?: rule?.optString("action")?.takeIf(String::isNotEmpty) ?: route.getString("final")
                assertEquals("$core/$country route $host", if (expected == "proxy") route.getString("final") else expected, actual)
                // Compare actual upstream DNS policy; tun-in A/AAAA mappings
                // are virtual addresses, not an upstream resolver.
                val dnsRule = dns.getJSONArray("rules").objects().firstOrNull { !it.has("inbound") && matches(it, host) }
                val actualDns = dnsRule?.optString("server")?.takeIf(String::isNotEmpty) ?: dnsRule?.optString("action")?.takeIf(String::isNotEmpty) ?: dns.getString("final")
                assertEquals("$core/$country DNS $host", when(expected) { "proxy" -> "remote-dns"; "direct" -> "direct-dns"; else -> "reject" }, actualDns)
            }
        }
    }

    @Test fun globalCannotInheritDomesticOrAdvertisingRulesForAnyService() {
        for (core in listOf("sing-box", "xray")) {
            val compiled = config("global", core)
            for (case in cases) assertNull(case.getString("host"), compiled.getJSONObject("route").getJSONArray("rules").objects().firstOrNull { matches(it, case.getString("host")) })
            assertEquals("remote-dns", compiled.getJSONObject("dns").getString("final"))
            assertTrue(compiled.getJSONObject("dns").getJSONArray("rules").objects().all {
                it.getString("server") in setOf("dual-stack-dns", "direct-dns") &&
                    !it.has("domain_suffix") && !it.has("rule_set") &&
                    (it.getString("server") != "direct-dns" ||
                        it.strings("domain") == BifrostRoutingRules.healthBootstrapDnsDomains)
            })
        }
    }

    @Test fun explicitApplicationPoliciesDoNotInheritServiceBypassOrPlayOverrides() {
        for (core in listOf("sing-box", "xray")) for (mode in listOf("allow", "exclude")) {
            val include = if (mode == "allow") listOf("org.wikipedia") else emptyList()
            val exclude = if (mode == "exclude") listOf("org.wikipedia") else emptyList()
            val compiled = JSONObject(BifrostConfigCompiler.compile(SmartGateCompilerTest().fixture(), "A", "auto", "per-app", core,
                includePackages=include, excludePackages=exclude, appPolicyMode=mode,
                applicationPolicy=BifrostApplicationPolicy.normalize("per-app", mode, include, exclude),
                xrayPort=if(core=="xray")10808 else 0, routingRulesDirectory=assets.path))
            val route = compiled.getJSONObject("route")
            assertFalse(route.has("rule_set"))
            assertTrue(compiled.getJSONObject("dns").getJSONArray("rules").objects().all {
                it.getString("server") in setOf("dual-stack-dns", "direct-dns") &&
                    !it.has("domain_suffix") && !it.has("rule_set") &&
                    (it.getString("server") != "direct-dns" ||
                        it.strings("domain") == BifrostRoutingRules.healthBootstrapDnsDomains)
            })
            val packages = route.getJSONArray("rules").objects().filter { it.has("package_name") }
            assertEquals(listOf("org.wikipedia"), packages.single().strings("package_name"))
            assertEquals(if (mode == "allow") route.getString("final") else "direct", packages.single().getString("outbound"))
        }
    }

    @Test fun youtubeIpOnlyTrafficHasAnAppRouteBeforeCnIpFallbackInSmartMode() {
        for (core in listOf("sing-box", "xray")) {
            val route = config("smart", core).getJSONObject("route")
            val rules = route.getJSONArray("rules").objects()
            for (pkg in BifrostServiceRouting.youtubePackages) {
                val index = rules.indexOfFirst { pkg in it.strings("package_name") }
                assertTrue(pkg, index >= 0)
                assertEquals(route.getString("final"), rules[index].getString("outbound"))
                assertTrue(index < rules.indexOfFirst { "geoip-cn" in it.strings("rule_set") })
            }
        }
    }

    @Test fun youtubeUdpOptionsAreNonTerminalAndBoundedToVideoHttps() {
        for (mode in listOf("smart", "global")) {
            val rules = config(mode, "sing-box").getJSONObject("route").getJSONArray("rules").objects()
            val option = rules.single { it.optString("action") == "route-options" }
            assertEquals("3m", option.getString("udp_timeout"))
            assertFalse("Never choose an outbound in the transport option", option.has("outbound"))
            assertEquals("and", option.getString("mode"))
            val terms = option.getJSONArray("rules").objects()
            assertEquals("udp", terms[0].getString("network"))
            assertEquals(443, terms[0].getInt("port"))
            val services = terms[1].getJSONArray("rules").objects()
            assertTrue("googlevideo.com" in services[0].strings("domain_suffix"))
            assertFalse("doubleclick.net" in services[0].strings("domain_suffix"))
        }
    }

    @Test fun qqPackageDoesNotForceForeignSharedLinksDirect() {
        for (core in listOf("sing-box", "xray")) {
            val rules = config("smart", core).getJSONObject("route").getJSONArray("rules").objects()
            val qqPackages = setOf("com.tencent.mobileqq", "com.tencent.tim")
            assertTrue("QQ/TIM must follow destination-domain policy instead of bypassing it", rules.none { rule ->
                rule.optString("outbound") == "direct" && rule.strings("package_name").any { it in qqPackages }
            })
        }
    }

    @Test fun bilibiliShareAndMediaHostsAreExplicitDirectDnsAndRoute() {
        for (core in listOf("sing-box", "xray")) {
            val compiled = config("smart", core)
            val route = compiled.getJSONObject("route")
            val dns = compiled.getJSONObject("dns")
            for (host in listOf("b23.tv", "www.bilibili.com", "i0.hdslb.com", "upos-sz-mirrorcos.bilivideo.com", "api.biliapi.net")) {
                val routeRule = route.getJSONArray("rules").objects().first { matches(it, host) }
                assertEquals("$core route $host", "direct", routeRule.getString("outbound"))
                val dnsRule = dns.getJSONArray("rules").objects().first { !it.has("inbound") && matches(it, host) }
                assertEquals("$core dns $host", "direct-dns", dnsRule.getString("server"))
            }
        }
    }
}
