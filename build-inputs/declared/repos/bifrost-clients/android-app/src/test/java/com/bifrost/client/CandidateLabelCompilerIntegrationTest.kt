package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fixed loopback contract: selector emits a display label and both native
 * compiler paths consume that exact value. */
class CandidateLabelCompilerIntegrationTest {
    @Test
    fun connectionRoundIsBoundedAndRetryCursorCanContinueThroughLargeSource() {
        val labels = (1..300).map { "A-%03d".format(it) }
        val completeOrder = BifrostCandidateSelector.connectionCohorts(labels, 298, "A-150")
        assertEquals("A-150", completeOrder.first().first())
        assertTrue(completeOrder.all { it.size <= BifrostCandidateSelector.MAX_PROBES })
        assertEquals(labels.toSet(), completeOrder.flatten().toSet())
        assertEquals(300, completeOrder.flatten().size)

        val firstRound = BifrostCandidateSelector.roundCohorts(labels, 298, "A-150")
        assertTrue(firstRound.size <= BifrostCandidateSelector.MAX_COHORTS_PER_ROUND)
        assertTrue(firstRound.flatten().size <= BifrostCandidateSelector.MAX_TLS_HANDSHAKES_PER_ROUND)
        val nextStart = (298 + firstRound.flatten().size) % labels.size
        val secondRound = BifrostCandidateSelector.roundCohorts(labels, nextStart, "A-150")
        assertTrue(secondRound.flatten().isNotEmpty())
        assertTrue(BifrostCandidateSelector.connectionBudgetMs(300) <= 30_000L)
        assertEquals(listOf(listOf("A-1", "A-2")), BifrostCandidateSelector.connectionCohorts(listOf("A-1", "A-2"), 0))
    }
    @Test
    fun selectorLabelFlowsIntoSingBoxAndXray() {
        val content = fixture()
        val source = JSONObject(content).getJSONArray("sources").getJSONObject(0)
        val candidates = (0 until source.getJSONArray("candidates").length()).map { source.getJSONArray("candidates").getJSONObject(it) }
        val selected = BifrostCandidateSelector.resolveCandidateLabel(candidates, "A-01")
        assertEquals("A-01", selected)
        val sing = JSONObject(BifrostConfigCompiler.compile(content, "A", "auto", "smart", "sing-box", selectedCandidate = selected, applicationPolicy = policy()))
        val singProxy = sing.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
        assertEquals("127.0.0.1", singProxy.optString("server"))
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(content, "A", "auto", selectedCandidate = selected, applicationPolicy = policy()))
        val xrayProxy = xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
        assertEquals("127.0.0.1", xrayProxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).optString("address"))
    }

    @Test
    fun sourceWebSocketPathAndTransportHostArePreservedForBothCores() {
        val content = fixture()
        val sing = JSONObject(BifrostConfigCompiler.compile(content, "A", "auto", "smart", "sing-box", selectedCandidate = "A-01", applicationPolicy = policy()))
        val singProxy = sing.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
        assertEquals("/source-level-vm", singProxy.getJSONObject("transport").optString("path"))
        assertEquals("transport-host.test", singProxy.getJSONObject("transport").getJSONObject("headers").optString("Host"))
        val xray = JSONObject(BifrostXrayConfigCompiler.compile(content, "A", "auto", selectedCandidate = "A-01", applicationPolicy = policy()))
        val xrayProxy = xray.getJSONArray("outbounds").objects().first { it.optString("tag") == "proxy" }
        assertEquals("/source-level-vm", xrayProxy.getJSONObject("streamSettings").getJSONObject("wsSettings").optString("path"))
        assertEquals("transport-host.test", xrayProxy.getJSONObject("streamSettings").getJSONObject("wsSettings").getJSONObject("headers").optString("Host"))
        assertEquals("signed-sni.test", xrayProxy.getJSONObject("streamSettings").getJSONObject("tlsSettings").optString("serverName"))
    }

    @Test
    fun rotatingCohortEventuallyCoversTenCandidatesWithinBudget() {
        val labels = (1..10).map { "A-%02d".format(it) }
        val seen = (0 until 4).flatMap { start -> BifrostCandidateSelector.cohortLabels(labels, start * 4, 4) }.toSet()
        assertEquals(10, seen.size)
        assertTrue(BifrostCandidateSelector.cohortLabels(labels, 0, BifrostCandidateSelector.MAX_PROBES).size <= BifrostCandidateSelector.MAX_PROBES)
    }

    @Test
    fun incumbentIsAlwaysIncludedAndFailedRoundsDoNotAdvanceSuccessTime() {
        val labels = (1..10).map { "A-%02d".format(it) }
        val cohort = BifrostCandidateSelector.cohortLabels(labels, 6, BifrostCandidateSelector.MAX_PROBES, "A-01")
        assertTrue(cohort.contains("A-01"))
        assertTrue(cohort.size <= BifrostCandidateSelector.MAX_PROBES)
        assertEquals(400L, BifrostCandidateSelector.successTimestamp(400L, 900L, false))
        assertEquals(900L, BifrostCandidateSelector.successTimestamp(400L, 900L, true))
    }

    @Test
    fun nativeLeafLabelsMatchCompiledOrderEvenWhenSeedMovesToFront() {
        val payload = JSONObject(fixture())
        val candidates = payload.getJSONArray("sources").getJSONObject(0).getJSONArray("candidates")
        candidates.put(JSONObject(candidates.getJSONObject(0).toString()).put("id", "a-2")
            .put("label", "A-02").put("dial_address", "127.0.0.2"))
        val labels = mutableMapOf("stale" to "B-99")
        val config = JSONObject(BifrostConfigCompiler.compile(payload.toString(), "A", "auto", "smart", "sing-box",
            selectedCandidate = "A-02", applicationPolicy = policy(), candidateMode = "auto", candidateLabels = labels))
        val outbounds = config.getJSONArray("outbounds").objects()
        val first = outbounds.first { it.optString("tag") == "proxy-auto" }.getJSONArray("outbounds").getString(0)
        assertEquals("A-02", labels[first])
        assertEquals("127.0.0.2", outbounds.first { it.optString("tag") == first }.getString("server"))
        assertEquals(setOf("proxy-candidate-0", "proxy-candidate-1"), labels.keys)
        assertEquals("A-01", labels["proxy-candidate-0"])
    }

    private fun fixture(): String {
        val source = JSONObject()
            .put("code", "A")
            .put("configured", true)
            .put("server_name", "source.test")
            .put("ws_path", "/source-level-vm")
            .put("transport", JSONObject().put("network", "ws").put("tls", true).put("sni", "signed-sni.test").put("host", "transport-host.test"))
            .put("candidates", JSONArray().put(JSONObject().put("id", "a-1").put("label", "A-01").put("dial_address", "127.0.0.1").put("port", 443)))
            .put("profiles", JSONObject().put("direct", JSONObject().put("uuid", "00000000-0000-4000-8000-000000000001")))
        return JSONObject()
            .put("routing", JSONObject().put("dns_policy", JSONObject().put("version", "dns-policy-v1").put("remote", "https://remote.example.invalid/dns-query").put("direct", "https://direct.example.invalid/dns-query").put("smart_gate_remote", true).put("plaintext_fallback", false).put("ipv4", "proxy").put("ipv6", "proxy").put("failure", "block")))
            .put("sources", JSONArray().put(source))
            .toString()
    }

    private fun policy() = BifrostApplicationPolicy.normalize("smart", "none", emptyList(), emptyList())

    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).mapNotNull { optJSONObject(it) }
}
