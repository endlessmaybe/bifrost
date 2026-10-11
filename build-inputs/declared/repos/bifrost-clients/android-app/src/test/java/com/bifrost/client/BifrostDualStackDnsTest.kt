package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostDualStackDnsTest {
    @Test fun publicQueriesMapBothFamiliesButBootstrapAndPrivateDnsRemainReal() {
        val dns = JSONObject("""{"strategy":"ipv4_only","servers":[],"rules":[
            {"rule_set":["geosite-private"],"server":"direct-dns"},
            {"domain_suffix":["local"],"server":"direct-dns"},
            {"domain_suffix":["example.com"],"server":"remote-dns"}]}""")
        val route = JSONObject()
        val outbounds = JSONArray("""[{"type":"direct","tag":"direct"},{"type":"vmess","tag":"proxy"}]""")
        BifrostDualStackDns.configure(dns, route, outbounds)
        val rules = dns.getJSONArray("rules")
        assertEquals("direct-dns", rules.getJSONObject(0).getString("server"))
        assertFalse(rules.getJSONObject(0).has("inbound"))
        assertEquals("direct-dns", rules.getJSONObject(1).getString("server"))
        assertFalse(rules.getJSONObject(1).has("inbound"))
        val proxy = rules.getJSONObject(2)
        assertEquals("dual-stack-dns", proxy.getString("server"))
        assertEquals(listOf("A", "AAAA"), proxy.getJSONArray("query_type").let { (0 until it.length()).map(it::getString) })
        assertEquals("tun-in", proxy.getJSONArray("inbound").getString(0))
        assertEquals("remote-dns", rules.getJSONObject(3).getString("server"))
        assertEquals("ipv4_only", dns.getString("strategy"))
        assertEquals("prefer_ipv4", outbounds.getJSONObject(0).getJSONObject("domain_resolver").getString("strategy"))
        assertEquals("300ms", outbounds.getJSONObject(0).getString("fallback_delay"))
        assertFalse(outbounds.getJSONObject(1).has("domain_resolver"))
        assertEquals(BifrostDualStackDns.FAKE_V6, dns.getJSONArray("servers").getJSONObject(0).getString("inet6_range"))
    }

    @Test fun mainlandAcademicDomainsStayRealIpLikeWindows() {
        val dns = JSONObject("""{"strategy":"ipv4_only","servers":[],"rules":[
            {"domain_suffix":["edu.cn","gov.cn","ac.cn"],"server":"direct-dns"}]}""")
        val route = JSONObject()
        val outbounds = JSONArray("""[{"type":"direct","tag":"direct"},{"type":"vmess","tag":"proxy"}]""")
        BifrostDualStackDns.configure(dns, route, outbounds)
        val rules = dns.getJSONArray("rules")
        assertEquals(2, rules.length())
        assertEquals("direct-dns", rules.getJSONObject(0).getString("server"))
        assertFalse(rules.getJSONObject(0).has("inbound"))
        assertEquals("dual-stack-dns", rules.getJSONObject(1).getString("server"))
    }

    @Test fun domesticMediaUsesRealCdnAddressesBeforeFakeIpFallback() {
        val dns = JSONObject("""{"strategy":"ipv4_only","servers":[],"rules":[
            {"domain_suffix":["bilibili.com","hdslb.com"],"server":"direct-dns"},
            {"rule_set":["geosite-cn"],"server":"direct-dns"},
            {"domain_suffix":["googlevideo.com"],"server":"remote-dns"}]}""")
        BifrostDualStackDns.configure(dns, JSONObject(), JSONArray("""[{"type":"direct","tag":"direct"}]"""))
        val rules = dns.getJSONArray("rules")
        assertEquals("direct-dns", rules.getJSONObject(0).getString("server"))
        assertEquals("direct-dns", rules.getJSONObject(1).getString("server"))
        assertFalse(rules.getJSONObject(0).has("inbound"))
        assertFalse(rules.getJSONObject(1).has("inbound"))
        assertEquals("dual-stack-dns", rules.getJSONObject(2).getString("server"))
        assertEquals("remote-dns", rules.getJSONObject(3).getString("server"))
        assertEquals("dual-stack-dns", rules.getJSONObject(4).getString("server"))
    }
}
