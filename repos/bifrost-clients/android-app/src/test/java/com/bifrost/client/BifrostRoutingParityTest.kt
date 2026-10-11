package com.bifrost.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory

class BifrostRoutingParityTest {
    private val assets = File("src/main/assets/routing").absoluteFile
    private fun config(mode: String = "smart", country: String = "auto", core: String = "sing-box"): JSONObject =
        JSONObject(BifrostConfigCompiler.compile(SmartGateCompilerTest().fixture(), "A", country, mode, core,
            applicationPolicy = BifrostApplicationPolicy.normalize(mode, "none", emptyList(), emptyList()),
            xrayPort = if (core == "xray") 10808 else 0, routingRulesDirectory = assets.path))

    @Test fun bothTransportsShareDesktopDomainAndDnsPrecedence() {
        for (core in listOf("sing-box", "xray")) {
            val config = config(core = core)
            val route = config.getJSONObject("route")
            val rules = route.getJSONArray("rules")
            val sets = (0 until rules.length()).map { rules.getJSONObject(it) }.filter { it.has("rule_set") }
            assertEquals(BifrostRoutingRules.dnsBypassBlockSets +
                listOf("geosite-openai", "geosite-category-ads-all", "geosite-private") +
                BifrostRoutingRules.domesticDirectSets + BifrostRoutingRules.foreignProxySets +
                listOf(BifrostRoutingRules.domesticTldSet, "geosite-cn", "geosite-geolocation-!cn", "geoip-cn"),
                sets.map { it.getJSONArray("rule_set").getString(0) })
            val tld = sets.single { it.getJSONArray("rule_set").getString(0) == BifrostRoutingRules.domesticTldSet }
            val cn = sets.single { it.getJSONArray("rule_set").getString(0) == "geosite-cn" }
            val foreign = sets.single { it.getJSONArray("rule_set").getString(0) == "geosite-geolocation-!cn" }
            assertEquals("direct", tld.getString("outbound"))
            assertEquals("direct", cn.getString("outbound"))
            assertEquals(route.getString("final"), foreign.getString("outbound"))
            assertEquals("reject", sets[BifrostRoutingRules.dnsBypassBlockSets.size + 1].getString("action"))
            for (tag in BifrostRoutingRules.dnsBypassBlockSets)
                assertEquals("reject", sets.single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("action"))
            val dnsRules = org.json.JSONArray(config.getJSONObject("dns").getJSONArray("rules").let { r ->
                (0 until r.length()).map(r::getJSONObject).filter { !it.has("inbound") }
            })
            val openAiDns = (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                .single { it.optJSONArray("domain_suffix")?.toString()?.contains("oaiusercontent.com") == true }
            assertEquals("remote-dns", openAiDns.getString("server"))
            val domesticDns = (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                .single { it.optJSONArray("rule_set")?.optString(0) == "geosite-cn" }
            assertEquals("direct-dns", domesticDns.getString("server"))
            assertEquals("direct-dns", (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                .single { it.optJSONArray("rule_set")?.optString(0) == BifrostRoutingRules.domesticTldSet }.getString("server"))
            for (tag in BifrostRoutingRules.domesticDirectSets) {
                assertEquals("direct", sets.single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("outbound"))
                assertEquals("direct-dns", (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                    .single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("server"))
            }
            for (tag in BifrostRoutingRules.foreignProxySets) {
                assertEquals(route.getString("final"), sets.single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("outbound"))
                assertEquals("remote-dns", (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                    .single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("server"))
            }
            for (tag in BifrostRoutingRules.dnsBypassBlockSets) {
                assertEquals("reject", (0 until dnsRules.length()).map { dnsRules.getJSONObject(it) }
                    .single { it.optJSONArray("rule_set")?.optString(0) == tag }.getString("action"))
            }
            assertEquals(4096, config.getJSONObject("dns").getInt("cache_capacity"))
            assertTrue((0 until rules.length()).map { rules.getJSONObject(it) }
                .any { it.optInt("port", -1) == 853 && it.optString("action") == "reject" })
            assertTrue(openAiDns.getJSONArray("domain_suffix").toString().contains("oaiusercontent.com"))
        }
    }

    @Test fun packagedRoutingManifestExactlyMatchesCompilerCategories() {
        val files = JSONObject(File(assets, "manifest.json").readText()).getJSONArray("files")
        val manifestNames = (0 until files.length()).map { files.getJSONObject(it).getString("name") }.toSet()
        assertEquals(BifrostRoutingRules.categories.map { "$it.json" }.toSet(), manifestNames)
        assertEquals(BifrostRoutingRules.categories.size, manifestNames.size)
        assertEquals(49, manifestNames.size)
    }
    @Test fun playDownloadOwnersAndEndpointsPrecedeDomesticFallbackForBothCores() {
        for (core in listOf("sing-box", "xray")) {
            val compiled = config(core = core)
            val route = compiled.getJSONObject("route")
            val rules = route.getJSONArray("rules").let { r -> (0 until r.length()).map(r::getJSONObject) }
            val ownerIndex = rules.indexOfFirst { it.optJSONArray("package_name")?.toString()?.contains("com.android.vending") == true }
            val domesticIndex = rules.indexOfFirst { it.optJSONArray("rule_set")?.optString(0) == "geosite-cn" }
            assertTrue(ownerIndex >= 0 && ownerIndex < domesticIndex)
            assertEquals(route.getString("final"), rules[ownerIndex].getString("outbound"))
            assertTrue(rules[ownerIndex].getJSONArray("package_name").toString().contains("com.android.providers.downloads"))
            val dnsRules = compiled.getJSONObject("dns").getJSONArray("rules").let { r ->
                (0 until r.length()).map(r::getJSONObject).filter { !it.has("inbound") } }
            val playDns = dnsRules.indexOfFirst { it.optJSONArray("domain_suffix")?.toString()?.contains("gvt2-cn.com") == true }
            val domesticDns = dnsRules.indexOfFirst { it.optJSONArray("rule_set")?.optString(0) == "geosite-cn" }
            assertTrue(playDns >= 0 && playDns < domesticDns)
            assertEquals("remote-dns", dnsRules[playDns].getString("server"))
        }
    }
    @Test fun globalDoesNotInheritDomesticBypass() {
        for (config in listOf(config("global"), config("global", country = "CN"))) {
            assertFalse(config.getJSONObject("route").has("rule_set"))
            val dnsRules = config.getJSONObject("dns").getJSONArray("rules")
            assertEquals(2, dnsRules.length())
            assertEquals("direct-dns", dnsRules.getJSONObject(0).getString("server"))
            assertEquals("dual-stack-dns", dnsRules.getJSONObject(1).getString("server"))
            assertEquals("proxy", config.getJSONObject("route").getString("final"))
        }
    }
    @Test fun smartGateSharesSmartRoutingAndDnsWhileKeepingCountryExit() {
        for (core in listOf("sing-box", "xray")) {
            val ordinary = config(core = core)
            val country = config(country = "CN", core = core)
            assertEquals(ordinary.getJSONObject("route").toString(), country.getJSONObject("route").toString())
            assertEquals(ordinary.getJSONObject("dns").toString(), country.getJSONObject("dns").toString())
            val transport = if (core == "xray") JSONObject(BifrostXrayConfigCompiler.compile(
                SmartGateCompilerTest().fixture(), "A", "CN",
                applicationPolicy = BifrostApplicationPolicy.normalize("smart", "none", emptyList(), emptyList()))) else country
            val outbounds = transport.getJSONArray("outbounds")
            val proxy = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }.single { it.optString("tag") == "proxy" }
            val expected = JSONObject(SmartGateCompilerTest().fixture()).getJSONArray("sources").getJSONObject(0)
                .getJSONObject("profiles").getJSONObject("countries").getJSONObject("CN").getString("uuid")
            val actual = if (core == "xray") proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0).getString("id") else proxy.getString("uuid")
            assertEquals(expected, actual)
        }
    }
    @Test fun androidHostnameRequestsCannotSelectAnUnusableGatewayIpv6Address() {
        for (core in listOf("sing-box", "xray")) {
            for (mode in listOf("smart", "global")) {
                val compiled = config(mode = mode, core = core)
                assertEquals("ipv4_only", compiled.getJSONObject("dns").getString("strategy"))
                // Preserve IPv6 interception: changing DNS must not let a
                // literal IPv6 request escape onto the underlying network.
                assertTrue(compiled.getJSONArray("inbounds").getJSONObject(0)
                    .getJSONArray("address").toString().contains("fdfe:dcba:9876::1/126"))
            }
        }
    }
    @Test fun pinnedCoreLoadsCompletePackagedRoutingDataForBothTransports() {
        val binary = File("../../../build-work/toolchains/sing-box-test/sing-box.exe").canonicalFile
        org.junit.Assume.assumeTrue(binary.isFile)
        val directory = createTempDirectory("bifrost-routing-core-").toFile()
        try {
            for ((core, country) in listOf("sing-box" to "auto", "xray" to "auto", "sing-box" to "CN", "xray" to "CN")) {
                val json = config(core = core, country = country)
                json.remove("inbounds") // Never create a host TUN during verification.
                System.getenv("BIFROST_ROUTING_TEST_EXPORT_DIR")?.let { target ->
                    File(target).mkdirs()
                    File(target, "$core-$country.json").writeText(json.toString())
                }
                val file = File(directory, "$core.json").apply { writeText(json.toString()) }
                val check = ProcessBuilder(binary.path, "check", "-c", file.path).redirectErrorStream(true).start()
                val output = check.inputStream.bufferedReader().readText()
                assertEquals(output, 0, check.waitFor())
                val log = File(directory, "$core.log")
                val process = ProcessBuilder(binary.path, "run", "-c", file.path).redirectErrorStream(true).redirectOutput(log).start()
                try { assertFalse(log.readText(), process.waitFor(2, TimeUnit.SECONDS)) }
                finally { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            }
        } finally { directory.deleteRecursively() }
    }
}
