package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostRootDnsRoutingTest {
    @Test fun rootDirectDnsDialersCarryTheDedicatedBypassMarkOnlyInRootConfig() {
        val dns = JSONObject().put("servers", JSONArray()
            .put(JSONObject().put("type", "https").put("tag", "remote-dns").put("server", "8.8.8.8"))
            .put(JSONObject().put("type", "https").put("tag", "direct-bootstrap-dns").put("server", "223.5.5.5"))
            .put(JSONObject().put("type", "https").put("tag", "direct-dns").put("server", "223.5.5.5"))
            .put(JSONObject().put("type", "fakeip").put("tag", "dual-stack-dns")))
            .put("rules", JSONArray())
        val config = JSONObject().put("dns", dns)
            .put("route", JSONObject().put("rules", JSONArray()))
            .put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("tag", "tun-in")))
        BifrostRootDnsRouting.configure(config)
        val servers = config.getJSONObject("dns").getJSONArray("servers")
        fun mark(tag: String) = (0 until servers.length()).map(servers::getJSONObject)
            .first { it.optString("tag") == tag }.optString("routing_mark", "")
        assertEquals("", mark("remote-dns"))
        assertEquals("0x1020000", mark("direct-bootstrap-dns"))
        assertEquals("0x1020000", mark("direct-dns"))
        assertEquals("", mark("dual-stack-dns"))
    }
    @Test fun infrastructureQueriesRetainRealResolversAndRejections() {
        val dns = JSONObject("""{"servers":[],"rules":[
            {"domain_suffix":["qq.com"],"server":"direct-dns"},
            {"domain_suffix":["youtube.com"],"server":"remote-dns"},
            {"rule_set":["geosite-category-ads-all"],"action":"reject"}]}""")
        val route = JSONObject().put("rules", JSONArray())
        BifrostDualStackDns.configure(dns, route, JSONArray())
        val before = JSONObject(dns.toString()).getJSONArray("rules")
        val config = JSONObject().put("dns", dns).put("route", route)
            .put("inbounds", JSONArray().put(JSONObject().put("type", "tun")))
        BifrostRootDnsRouting.configure(config, listOf("com.tailscale.ipn"))
        val inbounds = config.getJSONArray("inbounds")
        for ((index, address) in listOf(3 to "127.0.0.1", 4 to "::1")) {
            assertEquals(address, inbounds.getJSONObject(index).getString("listen"))
            assertEquals(if (address == "::1") 15356 else 15354, inbounds.getJSONObject(index).getInt("listen_port"))
            assertEquals("tproxy", inbounds.getJSONObject(index).getString("type"))
            assertEquals("0x1020000", inbounds.getJSONObject(index).getString("routing_mark"))
        }
        val after = dns.getJSONArray("rules")
        assertEquals(before.length(), after.length())
        for (i in 0 until after.length()) {
            val original = before.getJSONObject(i)
            val rule = after.getJSONObject(i)
            if (original.optString("server") != "dual-stack-dns") {
                assertEquals(original.toString(), rule.toString())
                continue
            }
            assertEquals("dual-stack-dns", rule.getString("server"))
            assertFalse(rule.has("package_name"))
            assertFalse(rule.has("rules"))
            assertEquals(listOf("tun-in", "root-dns", "root-app-dns"),
                rule.getJSONArray("inbound").let { values -> (0 until values.length()).map(values::getString) })
            assertFalse(rule.getJSONArray("inbound").toString().contains("root-vpn-dns"))

        }
    }
    @Test fun scopedWifiQueriesShareTunFakeAddressesWithoutVirtualizingBootstrap() {
        val dns = JSONObject("""{"strategy":"ipv4_only","servers":[],"rules":[
            {"domain_suffix":["qq.com"],"server":"direct-dns"},
            {"domain_suffix":["youtube.com"],"server":"remote-dns"},
            {"rule_set":["geosite-category-ads-all"],"action":"reject"},
            {"rule_set":["geosite-private"],"server":"direct-dns"}]}""")
        val route = JSONObject().put("rules", JSONArray())
        BifrostDualStackDns.configure(dns, route, JSONArray())
        val before = JSONObject(dns.toString())
        val config = JSONObject().put("dns", dns).put("route", route)
            .put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("tag", "tun-in")))
        BifrostRootDnsRouting.configure(config)
        val rules = dns.getJSONArray("rules")
        var virtualized = 0
        for (i in 0 until rules.length()) {
            val rule = rules.getJSONObject(i)
            val expected = before.getJSONArray("rules").getJSONObject(i)
            if (rule.optString("server") == "dual-stack-dns") {
                virtualized++
                assertEquals(listOf("tun-in", "root-dns", "root-app-dns"), rule.getJSONArray("inbound")
                    .let { values -> (0 until values.length()).map(values::getString) })
                assertEquals(listOf("A", "AAAA"), rule.getJSONArray("query_type")
                    .let { values -> (0 until values.length()).map(values::getString) })
                expected.getJSONArray("inbound").put("root-dns").put("root-app-dns")
            }
            assertEquals(expected.toString(), rule.toString())
        }
        assertEquals(2, virtualized) // Proxied public and fallback; direct stays real.
        assertEquals("ipv4_only", dns.getString("strategy"))
        assertEquals(before.getJSONArray("servers").toString(), dns.getJSONArray("servers").toString())
    }

    @Test fun singleStackResolversAreNotChangedByRootIngress() {
        val dns = JSONObject("""{"strategy":"ipv4_only","servers":[],"rules":[
            {"domain_suffix":["youtube.com"],"server":"remote-dns"}]}""")
        val before = dns.toString()
        val config = JSONObject().put("dns", dns).put("route", JSONObject().put("rules", JSONArray()))
            .put("inbounds", JSONArray().put(JSONObject().put("type", "tun")))
        BifrostRootDnsRouting.configure(config)
        assertEquals(before, dns.toString())
    }

    @Test fun scopedWifiDnsUsesLoopbackAndPrecedesPrivateAddressBypass() {
        val config = JSONObject().put("inbounds", JSONArray().put(JSONObject().put("type", "tun")))
            .put("route", JSONObject().put("rules", JSONArray()
                .put(JSONObject().put("ip_is_private", true).put("outbound", "direct"))))
        BifrostRootDnsRouting.configure(config)
        val listener = config.getJSONArray("inbounds").getJSONObject(1)
        assertEquals("tproxy", listener.getString("type"))
        assertEquals("::1", listener.getString("listen"))
        assertEquals(15353, listener.getInt("listen_port"))
        assertEquals("0x1020000", listener.getString("routing_mark"))
        assertFalse(listener.has("network")) // TCP and UDP DNS share the ingress.
        val rules = config.getJSONObject("route").getJSONArray("rules")
        assertEquals("hijack-dns", rules.getJSONObject(0).getString("action"))
        assertEquals("root-dns", rules.getJSONObject(0).getJSONArray("inbound").getString(0))
        assertEquals("direct", rules.getJSONObject(2).getString("outbound"))
    }

    @Test fun ipv4RootDnsMatchesBfr12TransparentIngress() {
        val config = JSONObject().put("inbounds", JSONArray().put(JSONObject().put("type", "tun")))
            .put("route", JSONObject().put("rules", JSONArray()))
        BifrostRootDnsRouting.configure(config, listOf("com.tailscale.ipn"))
        val inbounds = config.getJSONArray("inbounds")
        val app = (0 until inbounds.length()).map(inbounds::getJSONObject).single { it.optString("tag") == "root-app-dns" }
        val infra = (0 until inbounds.length()).map(inbounds::getJSONObject).single { it.optString("tag") == "root-vpn-dns4" }
        for (listener in listOf(app, infra)) {
            assertEquals("tproxy", listener.getString("type"))
            assertEquals("127.0.0.1", listener.getString("listen"))
            assertEquals("0x1020000", listener.getString("routing_mark"))
            assertFalse(listener.has("network")) // DNS TCP fallback remains available.
        }
    }
}
