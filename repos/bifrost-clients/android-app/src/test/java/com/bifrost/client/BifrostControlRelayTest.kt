package com.bifrost.client

import java.net.URL
import java.net.HttpURLConnection
import java.net.SocketException
import org.junit.Assert.*
import org.junit.Test

class BifrostControlRelayTest {
    @Test fun aliasOnlyTransportsOwnedClientRequests() {
        assertEquals(BifrostControlRelay.ORIGIN + "/v1/config/packages/70", BifrostControlRelay.alternate(URL("https://edge.bifrostlog.com/v1/config/packages/70"))?.toString())
        for (url in listOf("https://other.test/v1/config/manifest", "http://edge.bifrostlog.com/v1/config/manifest", "https://edge.bifrostlog.com:444/v1/config/manifest", "https://user@edge.bifrostlog.com/v1/config/manifest", "https://edge.bifrostlog.com/v1/admin/accounts", "https://edge.bifrostlog.com/v1/config/manifest?redirect=1", "https://bifrostlog.com/v1/config/manifest")) assertNull(url, BifrostControlRelay.alternate(URL(url)))
    }

    @Test fun primaryResetUsesVerifiedRelayBeforeAnyAuthenticatedBodyIsSent() {
        val seen = java.util.concurrent.CopyOnWriteArrayList<String>()
        val endpoint = URL("https://edge.bifrostlog.com/v1/device/session")
        val result = BifrostControlRelay.resolve(endpoint, "TEST-ONLY-cellular", true) { url ->
            seen += url.toString()
            object : HttpURLConnection(url) {
                override fun connect() = Unit
                override fun disconnect() = Unit
                override fun usingProxy() = false
                override fun getResponseCode(): Int {
                    assertNull(getRequestProperty("Authorization"))
                    assertFalse(doOutput)
                    if (url.host == "edge.bifrostlog.com") throw SocketException("TEST-ONLY reset")
                    return 200
                }
            }
        }
        assertEquals(BifrostControlRelay.ORIGIN + "/v1/device/session", result.toString())
        assertTrue(seen.all { it.endsWith("/health") })
        val cached = BifrostControlRelay.resolve(endpoint, "TEST-ONLY-cellular", false) { error("Cached selection must not probe again") }
        assertEquals(result, cached)
    }
}
