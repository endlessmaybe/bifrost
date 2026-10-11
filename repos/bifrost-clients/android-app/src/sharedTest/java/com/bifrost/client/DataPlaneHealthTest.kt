package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DataPlaneHealthTest {
    @Test fun onlyExpectedHttp204IsHealthy() {
        assertTrue(BifrostDataPlaneHealth.isExpectedStatus("HTTP/1.1 204 No Content\r"))
        assertTrue(BifrostDataPlaneHealth.isExpectedStatus("HTTP/1.0 204\r"))
        listOf("HTTP/1.1 200 OK\r", "HTTP/1.1 302 Redirect\r", "HTTP/1.1 503 Unavailable\r", "HTTP/1.1 2040 Fake\r", "204").forEach {
            assertFalse(it, BifrostDataPlaneHealth.isExpectedStatus(it))
        }
    }

    @Test fun probeIsAuthenticatedLoopbackAndUsesSelectedProxyBeforePrivateBypass() {
        val config = JSONObject().put("inbounds", JSONArray())
            .put("route", JSONObject().put("final", "proxy").put("rules", JSONArray().put(JSONObject().put("ip_is_private", true).put("outbound", "direct"))))
        val health = BifrostDataPlaneHealth()
        try {
            health.configure(config)
            val inbound = config.getJSONArray("inbounds").getJSONObject(0)
            assertEquals("127.0.0.1", inbound.getString("listen"))
            assertTrue(inbound.getJSONArray("users").getJSONObject(0).getString("password").length >= 32)
            assertEquals("proxy", config.getJSONObject("route").getJSONArray("rules").getJSONObject(0).getString("outbound"))
            assertFalse(health.check()) // No core listener: default network cannot turn this green.
        } finally { health.close() }
        assertFalse(health.check())
    }
}
