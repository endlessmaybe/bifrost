package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostHotspotRoutingTest {
    private fun config() = JSONObject().put("inbounds", JSONArray())
        .put("dns", JSONObject().put("rules", JSONArray()
            .put(JSONObject().put("inbound", JSONArray().put("tun-in"))
                .put("server", "dual-stack-dns"))
            .put(JSONObject().put("domain_suffix", JSONArray().put("cn")).put("server", "direct-dns"))))
        .put("route", JSONObject().put("rules", JSONArray()
            .put(JSONObject().put("action", "sniff"))
            .put(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
            .put(JSONObject().put("domain_suffix", JSONArray().put("cn")).put("outbound", "direct")))
            .put("final", "proxy"))

    @Test fun directDnsOverridesFakeIpAndPhoneGlobalPolicyWithoutChangingPhoneRules() {
        val parsed = config()
        BifrostHotspotRouting.configure(parsed)
        val dns = parsed.getJSONObject("dns").getJSONArray("rules")
        assertEquals("direct-dns", dns.getJSONObject(0).getString("server"))
        assertEquals("[\"root-hotspot-direct4\",\"root-hotspot-direct6\"]", dns.getJSONObject(0).getJSONArray("inbound").toString())
        val fake = dns.getJSONObject(1).getJSONArray("inbound").toString()
        assertTrue(fake.contains("tun-in"))
        assertTrue(fake.contains("root-hotspot4"))
        assertFalse(fake.contains("root-hotspot-direct"))
        val route = parsed.getJSONObject("route")
        assertEquals("proxy", route.getString("final"))
        assertEquals("sniff", route.getJSONArray("rules").getJSONObject(1).getString("action"))
        assertEquals("direct", route.getJSONArray("rules").getJSONObject(3).getString("outbound"))
    }
    @Test fun allFourTransparentListenersStayLoopbackOnlyWithProtectedReplySockets() {
        val parsed = config()
        BifrostHotspotRouting.configure(parsed)
        val inbounds = parsed.getJSONArray("inbounds")
        assertEquals(4, inbounds.length())
        for (index in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(index)
            assertEquals("tproxy", inbound.getString("type"))
            assertTrue(inbound.getString("listen") in listOf("127.0.0.1", "::1"))
            assertEquals("0x1020000", inbound.getString("routing_mark"))
            assertEquals(if (index < 2) 15357 else 15358, inbound.getInt("listen_port"))
        }
    }
    @Test fun cannotSilentlyDuplicateAnExistingHotspotIngress() {
        val parsed = config()
        parsed.getJSONArray("inbounds").put(JSONObject().put("tag", "root-hotspot4"))
        try { BifrostHotspotRouting.configure(parsed); fail("collision accepted") }
        catch (_: IllegalStateException) { }
    }
}
