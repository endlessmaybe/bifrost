package com.bifrost.client

import java.io.File
import kotlin.io.path.createTempDirectory
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class SmartGateCompilerTest {
    @Test fun automaticSmartGateUsesExactSmartDnsAndRouteWithBothRootAndVpn() {
        val payload = JSONObject(fixture())
        payload.getJSONArray("countries").getJSONObject(0).put("status", "enabled")
            .put("socks", JSONObject().put("scheme", "socks5h").put("host", "192.0.2.10")
                .put("port", 8848).put("user", "TEST-ONLY-user").put("password", "TEST-ONLY-password"))
        for (core in listOf("sing-box", "xray")) for (root in listOf(false, true)) {
            fun compiled(country: String): JSONObject {
                val config = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", country, "smart", core,
                    applicationPolicy = policy("smart"), candidateMode = "auto", xrayPort = if (core == "xray") 12345 else 0))
                if (root) BifrostRootDnsRouting.configure(config, listOf("com.tailscale.ipn"))
                return config
            }
            val ordinary = compiled("auto")
            val smartGate = compiled("CN")
            assertEquals("DNS mismatch: $core Root=$root", ordinary.getJSONObject("dns").toString(), smartGate.getJSONObject("dns").toString())
            assertEquals("Route mismatch: $core Root=$root", ordinary.getJSONObject("route").toString(), smartGate.getJSONObject("route").toString())
            assertEquals(ordinary.getJSONArray("inbounds").toString(), smartGate.getJSONArray("inbounds").toString())
        }
    }

    @Test fun signedSocksCountryUsesDirectFrontProfilesOnBothAndroidCores() {
        val payload = JSONObject(fixture())
        val country = payload.getJSONArray("countries").getJSONObject(0)
        country.put("status", "enabled").put("socks", JSONObject().put("scheme", "socks5h")
            .put("host", "192.0.2.10").put("port", 8848).put("user", "TEST-ONLY-user").put("password", "TEST-ONLY-password"))
        // Modern packages need no obsolete per-country VMess credentials.
        payload.getJSONArray("sources").objects().forEach { it.getJSONObject("profiles").remove("countries") }
        val sing = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "CN", "smart", "sing-box",
            applicationPolicy = policy("smart"), candidateMode = "auto"))
        val outbounds = sing.getJSONArray("outbounds").objects()
        val socks = outbounds.filter { it.optString("type") == "socks" }
        assertEquals(2, socks.size)
        assertEquals(2, outbounds.first { it.optString("tag") == "proxy-auto" }.getJSONArray("outbounds").length())
        for (hop in socks) {
            assertEquals("192.0.2.10", hop.getString("server"))
            val front = outbounds.single { it.optString("tag") == hop.getString("detour") }
            assertEquals("vmess", front.getString("type"))
            assertFalse(front.has("detour"))
        }
        val pinned = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "CN", "smart", "sing-box",
            applicationPolicy = policy("smart"), candidateMode = "auto", frontSourceCode = "B"))
        assertEquals(1, pinned.getJSONArray("outbounds").objects().count { it.optString("type") == "socks" })
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(payload.toString(), "A", "CN", applicationPolicy = policy("smart")))
        val proxy = xray.getJSONArray("outbounds").objects().single { it.optString("tag") == "proxy" }
        assertEquals("socks", proxy.getString("protocol"))
        assertEquals("front-vmess", proxy.getJSONObject("proxySettings").getString("tag"))
        assertTrue(proxy.getJSONObject("proxySettings").getBoolean("transportLayer"))
        assertFalse("embedded Xray must not require an unpackaged geoip.dat", xray.toString().contains("geoip:"))
        country.getJSONObject("socks").put("port", 0)
        assertEquals("BF-SMARTGATE-SOCKS", failure { BifrostConfigCompiler.compile(payload.toString(), "A", "CN", "smart", "sing-box", applicationPolicy = policy("smart")) })
        assertEquals("BF-SMARTGATE-SOCKS", failure { BifrostXrayConfigCompiler.compile(payload.toString(), "A", "CN", applicationPolicy = policy("smart")) })
    }
    @Test
    fun threeHundredCandidatesCompileAndLastCandidateRemainsSelectable() {
        val payload = JSONObject(fixture())
        val source = payload.getJSONArray("sources").getJSONObject(0)
        val template = source.getJSONArray("candidates").getJSONObject(0)
        val candidates = JSONArray()
        (1..300).forEach { index -> candidates.put(JSONObject(template.toString())
            .put("label", "A-%02d".format(index)).put("id", "a-$index")
            .put("dial_address", "candidate-$index.test")) }
        source.put("candidates", candidates)
        val auto = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", applicationPolicy = policy("smart"), candidateMode = "auto"))
        assertEquals(300, auto.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy-auto" }.getJSONArray("outbounds").length())
        val manual = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", selectedCandidate = "A-300", applicationPolicy = policy("smart"), candidateMode = "manual"))
        assertEquals("candidate-300.test", manual.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.getString("server"))
        val seeded = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", selectedCandidate = "A-300", applicationPolicy = policy("smart"), candidateMode = "auto"))
        val seededOutbounds = seeded.getJSONArray("outbounds").objects()
        val firstTag = seededOutbounds.first { it.optString("tag") == "proxy-auto" }.getJSONArray("outbounds").getString(0)
        assertEquals("candidate-300.test", seededOutbounds.first { it.optString("tag") == firstTag }.getString("server"))
        candidates.put(JSONObject(template.toString()).put("label", "A-301"))
        assertTrue(failure { BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", applicationPolicy = policy("smart"), candidateMode = "auto") }.startsWith("BF-"))
    }
    @Test
    fun automaticCandidatesUseCoreHttpsHealthAndManualStaysPinned() {
        val payload = JSONObject(fixture())
        val source = payload.getJSONArray("sources").getJSONObject(0)
        val candidates = source.getJSONArray("candidates")
        candidates.put(JSONObject(candidates.getJSONObject(0).toString()).put("label", "a-second").put("id", "a-second").put("dial_address", "192.0.2.2"))
        val config = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", applicationPolicy = policy("smart"), candidateMode = "auto"))
        val outbounds = config.getJSONArray("outbounds").objects()
        val selector = outbounds.first { it.optString("tag") == "proxy" }
        assertEquals("selector", selector.getString("type"))
        assertFalse(selector.getBoolean("interrupt_exist_connections"))
        val group = outbounds.first { it.optString("tag") == "proxy-auto" }
        assertEquals("urltest", group.getString("type"))
        assertEquals(2, group.getJSONArray("outbounds").length())
        assertEquals("https://www.gstatic.com/generate_204", group.getString("url"))
        assertEquals("1m", group.getString("interval"))
        assertEquals(BifrostNodeQuality.AUTO_SELECT_TOLERANCE_MS, group.getInt("tolerance"))
        assertFalse("latency re-selection must not tear down established app connections", group.getBoolean("interrupt_exist_connections"))
        assertTrue(outbounds.filter { it.optString("type") == "vmess" }.all { it.getJSONObject("tls").getJSONObject("utls").getString("fingerprint") == "chrome" })
        assertEquals(1500, config.getJSONArray("inbounds").getJSONObject(0).getInt("mtu"))
        val manual = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box", selectedCandidate = "a-second", applicationPolicy = policy("smart"), candidateMode = "manual"))
        assertTrue(manual.getJSONArray("outbounds").objects().none { it.optString("type") == "urltest" })
        assertEquals("192.0.2.2", manual.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.getString("server"))
    }

    @Test
    fun autoAndBlankUseSignedCountryFrontMappingForBothCompilers() {
        listOf<String?>("auto", null, "", "  ").forEach { requested ->
            val sing = JSONObject(BifrostConfigCompiler.compile(fixture(), "B", "CN", "smart", "sing-box", frontSourceCode = requested, applicationPolicy = policy("smart")))
            assertTrue(sing.getJSONArray("outbounds").objects().any { it.optString("tag") == "front-vmess" })
            assertEquals("front-vmess", sing.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.optString("detour"))
            assertTrue(sing.getJSONArray("outbounds").objects().none { it.optString("tag") == "country-socks" })

            val xray = JSONObject(BifrostXrayConfigCompiler.compile(fixture(), "B", "CN", frontSourceCode = requested, applicationPolicy = policy("smart")))
            assertTrue(xray.getJSONArray("outbounds").objects().any { it.optString("tag") == "front-vmess" })
            assertEquals("front-vmess", xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
                .optJSONObject("proxySettings")?.optString("tag"))
            assertTrue(xray.getJSONArray("outbounds").objects().none { it.optString("tag") == "country-socks" })
        }
    }

    @Test
    fun autoOnSelectedSourceUsesCountryMappingWithoutInventingAFrontHop() {
        val sing = JSONObject(BifrostConfigCompiler.compile(fixture(), "A", "CN", "smart", "sing-box", frontSourceCode = "AUTO", applicationPolicy = policy("smart")))
        assertTrue(sing.getJSONArray("outbounds").objects().none { it.optString("tag") == "front-vmess" })
        assertFalse(sing.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.has("detour"))
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", frontSourceCode = "auto", applicationPolicy = policy("smart")))
        assertTrue(xray.getJSONArray("outbounds").objects().none { it.optString("tag") == "front-vmess" })
        assertFalse(xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.has("proxySettings"))
    }

    @Test
    fun explicitAuthorizedFrontBuildsVmessChainAndSensitiveHopNeverReappears() {
        val sing = JSONObject(BifrostConfigCompiler.compile(fixture(), "A", "CN", "smart", "sing-box", frontSourceCode = "B", applicationPolicy = policy("smart")))
        assertEquals("front-vmess", sing.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.optString("detour"))
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", frontSourceCode = "B", applicationPolicy = policy("smart")))
        assertEquals("front-vmess", xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
            .optJSONObject("proxySettings")?.optString("tag"))
        assertFalse(sing.toString().contains("country-socks"))
        assertFalse(xray.toString().contains("country-socks"))
        assertFalse(sing.toString().contains("password"))
        assertFalse(xray.toString().contains("password"))
    }

    @Test
    fun explicitUnauthorizedFrontFailsClosedOnBothCores() {
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure { BifrostConfigCompiler.compile(fixture(), "A", "CN", "smart", "sing-box", frontSourceCode = "C", applicationPolicy = policy("smart")) })
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure { BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", frontSourceCode = "C", applicationPolicy = policy("smart")) })

        val restricted = JSONObject(fixture()).apply {
            getJSONArray("countries").getJSONObject(0).put("front_source_options", JSONArray().put("A"))
        }.toString()
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure {
            BifrostConfigCompiler.compile(restricted, "B", "CN", "smart", "sing-box", frontSourceCode = "B", applicationPolicy = policy("smart"))
        })
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure {
            BifrostXrayConfigCompiler.compile(restricted, "B", "CN", frontSourceCode = "B", applicationPolicy = policy("smart"))
        })
    }

    @Test
    fun xrayUsesFormalCatchAllAndNeverPrivateFinalTagExtension() {
        val result = JSONObject(BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", frontSourceCode = "auto", applicationPolicy = policy("smart")))
        assertFalse(result.has("bifrost_final_tag"))
        val rules = result.getJSONObject("routing").getJSONArray("rules").objects()
        assertEquals("proxy", rules.last().optString("outboundTag"))
        assertEquals("tcp,udp", rules.last().optString("network"))
    }

    @Test
    fun globalOnlyBypassesPrivateTrafficForBothCores() {
        val sing = JSONObject(BifrostConfigCompiler.compile(fixture(), "A", "CN", "global", "sing-box", applicationPolicy = policy("global")))
        val singRules = sing.getJSONObject("route").getJSONArray("rules").objects()
        assertTrue(singRules.none { it.optJSONArray("domain_suffix")?.toString()?.contains(".cn") == true })
        assertEquals("proxy", sing.getJSONObject("route").optString("final"))
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", mode = "global", applicationPolicy = policy("global")))
        val xrayRules = xray.getJSONObject("routing").getJSONArray("rules").objects()
        assertTrue(xrayRules.none { it.optJSONArray("domain")?.toString()?.contains("geosite:cn") == true })
        assertEquals("proxy", xrayRules.last().optString("outboundTag"))
    }

    @Test
    fun perAppAllowAndExcludeAreMutuallyExclusiveOnBothCores() {
        listOf("sing-box", "xray").forEach { core ->
            val allow = JSONObject(if (core == "sing-box") {
                BifrostConfigCompiler.compile(fixture(), "A", "CN", "per-app", core, includePackages = listOf("com.test.proxy"), appPolicyMode = "allow", applicationPolicy = policy("per-app", "allow", listOf("com.test.proxy")))
            } else {
                BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", mode = "per-app", includePackages = listOf("com.test.proxy"), appPolicyMode = "allow", applicationPolicy = policy("per-app", "allow", listOf("com.test.proxy")))
            })
            assertTrue(allow.length() > 0)
            val exclude = if (core == "sing-box") {
                BifrostConfigCompiler.compile(fixture(), "A", "CN", "per-app", core, excludePackages = listOf("com.test.direct"), appPolicyMode = "exclude", applicationPolicy = policy("per-app", "exclude", emptyList(), listOf("com.test.direct")))
            } else {
                BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", mode = "per-app", excludePackages = listOf("com.test.direct"), appPolicyMode = "exclude", applicationPolicy = policy("per-app", "exclude", emptyList(), listOf("com.test.direct")))
            }
            assertTrue(JSONObject(exclude).length() > 0)
        }
        assertEquals("BF-APP-POLICY-SNAPSHOT", failure { BifrostConfigCompiler.compile(fixture(), "A", "CN", "per-app", "sing-box", includePackages = listOf("com.test.proxy"), excludePackages = listOf("com.test.direct"), appPolicyMode = "allow", applicationPolicy = policy("per-app", "allow", listOf("com.test.proxy"))) })
        assertEquals("BF-APP-POLICY-SNAPSHOT", failure { BifrostXrayConfigCompiler.compile(fixture(), "A", "CN", mode = "per-app", appPolicyMode = "allow", applicationPolicy = policy("global")) })
    }

    @Test
    fun missingMappingAutoFallsBackToSelectedSourceAndExplicitAlternateIsRejected() {
        val noMapping = JSONObject(fixture()).apply {
            getJSONArray("countries").put(JSONObject().put("code", "JP").put("name_zh", "TEST").put("front_source_options", JSONArray()))
        }
        val sing = JSONObject(BifrostConfigCompiler.compile(noMapping.toString(), "A", "JP", "smart", "sing-box", frontSourceCode = "auto", applicationPolicy = policy("smart")))
        assertTrue(sing.getJSONArray("outbounds").objects().none { it.optString("tag") == "front-vmess" })
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(noMapping.toString(), "A", "JP", frontSourceCode = null, applicationPolicy = policy("smart")))
        assertEquals("proxy", xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }.optString("tag"))
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure { BifrostConfigCompiler.compile(noMapping.toString(), "A", "JP", "smart", "sing-box", frontSourceCode = "B", applicationPolicy = policy("smart")) })
        assertEquals("BF-SMARTGATE-FRONT-NOT-MAPPED", failure { BifrostXrayConfigCompiler.compile(noMapping.toString(), "A", "JP", frontSourceCode = "B", applicationPolicy = policy("smart")) })
    }

    @Test
    fun generatedTunConfigUsesModernDnsActionsAndPassesLockedSingBoxParser() {
        val compiled = BifrostConfigCompiler.compile(fixture(), "A", "CN", "smart", "sing-box", applicationPolicy = policy("smart"),
            routingRulesDirectory = File("src/main/assets/routing").absolutePath)
        val json = JSONObject(compiled)
        val rules = json.getJSONObject("route").getJSONArray("rules").objects()
        assertEquals("sniff", rules.first().optString("action"))
        assertEquals("hijack-dns", rules[1].optString("action"))
        assertEquals("dns", rules[1].optString("protocol"))
        assertEquals("remote-dns", json.getJSONObject("route").getJSONObject("default_domain_resolver").optString("server"))
        assertFalse(json.getJSONArray("inbounds").getJSONObject(0).has("sniff"))
        assertTrue(json.getJSONObject("dns").getJSONArray("servers").objects().all { it.optString("type") in setOf("https", "fakeip") })
        val dnsServers = json.getJSONObject("dns").getJSONArray("servers").objects()
        assertEquals("proxy", dnsServers.first { it.optString("tag") == "remote-dns" }.optString("detour"))
        val bootstrapDns = dnsServers.first { it.optString("tag") == "direct-bootstrap-dns" }
        assertFalse(bootstrapDns.has("detour"))
        assertFalse(bootstrapDns.has("domain_resolver"))
        val directDns = dnsServers.first { it.optString("tag") == "direct-dns" }
        assertFalse(directDns.has("detour"))
        assertEquals("direct-bootstrap-dns", directDns.getJSONObject("domain_resolver").optString("server"))

        val windows = System.getProperty("os.name").orEmpty().startsWith("Windows", ignoreCase = true)
        val binary = File(System.getProperty("user.dir"), "../../../build-work/toolchains/sing-box-test/sing-box.exe").canonicalFile
        assumeTrue("locked sing-box parser is available only on the Windows verification lane", windows && binary.isFile)
        val directory = createTempDirectory("bifrost-android-singbox-").toFile()
        try {
            val config = File(directory, "config.json")
            config.writeText(compiled, Charsets.UTF_8)
            val process = ProcessBuilder(binary.absolutePath, "check", "-c", config.absolutePath)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            assertEquals(output, 0, process.waitFor())
            // `check` only constructs DNS transports. The old empty direct
            // detour was rejected later, at service start. Start the same
            // compiled DNS/outbound graph without creating a host TUN.
            json.remove("inbounds")
            config.writeText(json.toString(), Charsets.UTF_8)
            val runtime = ProcessBuilder(binary.absolutePath, "run", "-c", config.absolutePath)
                .redirectErrorStream(true).redirectOutput(File(directory, "runtime.log")).start()
            try {
                assertFalse(File(directory, "runtime.log").readText(), runtime.waitFor(2, java.util.concurrent.TimeUnit.SECONDS))
            } finally {
                runtime.destroyForcibly()
                runtime.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun knownMainlandDohUsesStrictIpTlsToSurviveSniFiltering() {
        val source = JSONObject(fixture())
        source.getJSONObject("routing").getJSONObject("dns_policy")
            .put("direct", "https://dns.alidns.com/dns-query")
        val json = JSONObject(BifrostConfigCompiler.compile(
            source.toString(), "A", "CN", "smart", "sing-box",
            applicationPolicy = policy("smart"),
            routingRulesDirectory = File("src/main/assets/routing").absolutePath,
        ))
        val directDns = json.getJSONObject("dns").getJSONArray("servers").objects()
            .first { it.optString("tag") == "direct-dns" }
        assertEquals("https", directDns.getString("type"))
        assertEquals("223.5.5.5", directDns.getString("server"))
        assertFalse(directDns.has("detour"))
        assertFalse(directDns.has("domain_resolver"))
        assertEquals("dns.alidns.com", directDns.getJSONObject("tls").getString("server_name"))
        assertEquals("dns.alidns.com", directDns.getJSONObject("headers").getString("Host"))
        val bootstrap = json.getJSONObject("dns").getJSONArray("servers").objects()
            .first { it.optString("tag") == "direct-bootstrap-dns" }
        assertEquals("dns.alidns.com", bootstrap.getJSONObject("tls").getString("server_name"))
        assertEquals("dns.alidns.com", bootstrap.getJSONObject("headers").getString("Host"))
    }

    @Test
    fun smartModePinsMainlandAcademicNamespacesToDirectRouteAndDns() {
        val json = JSONObject(BifrostConfigCompiler.compile(
            fixture(), "A", "CN", "smart", "sing-box",
            applicationPolicy = policy("smart"),
            routingRulesDirectory = File("src/main/assets/routing").absolutePath,
        ))
        val routes = json.getJSONObject("route").getJSONArray("rules").objects()
        val academicRoute = routes.firstOrNull { rule ->
            rule.optJSONArray("domain_suffix")?.let { values ->
                (0 until values.length()).any { values.optString(it) == "edu.cn" }
            } == true
        }
        assertNotNull("missing edu.cn direct route", academicRoute)
        assertEquals("direct", academicRoute!!.optString("outbound"))

        val dnsRules = json.getJSONObject("dns").getJSONArray("rules").objects()
        val academicDns = dnsRules.firstOrNull { rule ->
            rule.optJSONArray("domain_suffix")?.let { values ->
                (0 until values.length()).any { values.optString(it) == "edu.cn" }
            } == true && rule.optString("server") == "direct-dns"
        }
        assertNotNull("missing edu.cn direct DNS rule", academicDns)
        assertEquals("direct-dns", academicDns!!.optString("server"))
        assertEquals("route", academicDns.optString("action"))

        val httpDnsRoute = routes.firstOrNull { rule ->
            rule.optJSONArray("rule_set")?.let { values ->
                (0 until values.length()).any { values.optString(it) == "geosite-category-httpdns-cn" }
            } == true
        }
        assertNotNull("mainland HTTPDNS must remain compatible instead of being rejected", httpDnsRoute)
        assertEquals("direct", httpDnsRoute!!.optString("outbound"))
        assertFalse(httpDnsRoute.optString("action") == "reject")

        val httpDnsRule = dnsRules.firstOrNull { rule ->
            rule.optJSONArray("rule_set")?.let { values ->
                (0 until values.length()).any { values.optString(it) == "geosite-category-httpdns-cn" }
            } == true && rule.optString("server") == "direct-dns"
        }
        assertNotNull("mainland HTTPDNS must use direct encrypted DNS", httpDnsRule)
        assertFalse(dnsRules.any { rule ->
            rule.optString("action") == "reject" &&
                rule.optJSONArray("rule_set")?.let { values ->
                    (0 until values.length()).any { values.optString(it) == "geosite-category-httpdns-cn" }
                } == true
        })

        BifrostRoutingRules.healthBootstrapDnsDomains.forEach { host ->
            val bootstrap = dnsRules.firstOrNull { rule ->
                rule.optJSONArray("domain")?.let { values ->
                    (0 until values.length()).any { values.optString(it) == host }
                } == true && rule.optString("server") == "direct-dns" && !rule.has("inbound")
            }
            assertNotNull("$host must resolve independently of the selected proxy", bootstrap)
        }
    }

    @Test
    fun unavailableCountryFailsClosedInsteadOfSelectingAnotherProfile() {
        val unavailable = JSONObject(fixture()).apply {
            getJSONArray("countries").getJSONObject(0).put("status", "disabled")
        }
        assertEquals("BF-COUNTRY-NOT-AVAILABLE", failure {
            BifrostConfigCompiler.compile(unavailable.toString(), "A", "CN", "smart", "sing-box", applicationPolicy = policy("smart"))
        })
    }

    private fun failure(block: () -> String): String = runCatching { block(); "NO_ERROR" }.exceptionOrNull()?.message ?: "NO_MESSAGE"

    private fun policy(
        mode: String,
        appPolicyMode: String = "none",
        include: List<String> = emptyList(),
        exclude: List<String> = emptyList(),
    ) = BifrostApplicationPolicy.normalize(mode, appPolicyMode, include, exclude)

    internal fun fixture(): String = JSONObject()
        .put("routing", JSONObject().put("dns_policy", JSONObject()
            .put("version", "dns-policy-v1")
            .put("remote", "https://remote.example.invalid/dns-query")
            .put("direct", "https://direct.example.invalid/dns-query")
            .put("smart_gate_remote", true)
            .put("plaintext_fallback", false)
            .put("ipv4", "proxy")
            .put("ipv6", "proxy")
            .put("failure", "block")))
        .put("sources", JSONArray().put(source("A", "a.test", "00000000-0000-4000-8000-000000000001"))
            .put(source("B", "b.test", "00000000-0000-4000-8000-000000000002"))
            .put(source("C", "c.test", "00000000-0000-4000-8000-000000000003")))
        .put("countries", JSONArray().put(JSONObject()
            .put("code", "CN")
            .put("name_zh", "TEST")
            .put("front_source_code", "A")
            .put("front_source_options", JSONArray().put("A").put("B"))))
        .toString()

    private fun source(code: String, host: String, uuid: String): JSONObject = JSONObject()
        .put("code", code).put("configured", true).put("server_name", host).put("ws_path", "/test")
        .put("transport", JSONObject().put("network", "ws").put("security", "auto").put("tls", true).put("sni", host).put("host", host))
        .put("candidates", JSONArray().put(JSONObject().put("id", code + "-1").put("label", code + "-01").put("dial_address", "127.0.0.1").put("port", 443)))
        .put("profiles", JSONObject()
            .put("direct", JSONObject().put("profile_id", "profile-$code-direct").put("uuid", uuid))
            .put("countries", JSONObject().put("CN", JSONObject().put("profile_id", "profile-$code-cn").put("uuid", uuid)).put("JP", JSONObject().put("profile_id", "profile-$code-jp").put("uuid", uuid))))

    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).mapNotNull { optJSONObject(it) }
}
