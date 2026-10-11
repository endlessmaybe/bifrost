package com.bifrost.client

import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostNodeQualityTest {
    @Test fun androidHttpResponseTimeDoesNotDisqualifyAConfirmedFastPayloadPath() {
        val quality = BifrostNodeQuality.runtime()
        repeat(2) { pass ->
            quality.record("slow", BifrostQualitySample(1000L + pass, true, 100.0, 20_000.0, 0.0))
            quality.record("fast", BifrostQualitySample(1000L + pass, true, 1500.0, 1_600_000.0, 0.0))
            quality.record("unknown", BifrostQualitySample(1000L + pass, true, 0.0, 9_000_000.0, 0.0))
        }
        val nodes = setOf("slow", "fast", "unknown")
        assertEquals("fast", quality.choose(nodes, nodes, "slow", 2000))
        assertNull(quality.score("unknown", 2000))
    }
    @Test fun sustainedThroughputDropNeedsTwoValidConfirmations() {
        fun sample(ok: Boolean = true, rate: Double = 40.0) = BifrostQualitySample(1000, ok, 100.0, rate, 0.0)
        assertTrue(BifrostNodeQuality.hasSustainedDrop(listOf(sample(), sample()), 100.0))
        assertTrue(BifrostNodeQuality.hasSustainedDrop(listOf(sample(false), sample(false)), 100.0))
        assertFalse(BifrostNodeQuality.hasSustainedDrop(listOf(sample()), 100.0))
        assertFalse(BifrostNodeQuality.hasSustainedDrop(listOf(sample(), sample(rate = 80.0)), 100.0))
        assertFalse(BifrostNodeQuality.hasSustainedDrop(listOf(sample(), sample(false)), 100.0))
        assertFalse(BifrostNodeQuality.hasSustainedDrop(listOf(sample(), sample(rate = Double.NaN)), 100.0))
        assertFalse(BifrostNodeQuality.hasSustainedDrop(listOf(sample(), sample()), Double.NaN))
    }
    @Test fun shortFastPrefixContinuesButSlowPrefixAndWireCapStop() {
        assertTrue(BifrostNodeQuality.continueDownload(128 * 1024, 0.005))
        assertFalse(BifrostNodeQuality.continueDownload(128 * 1024, 0.30))
        assertTrue(BifrostNodeQuality.continueDownload(64 * 1024, 0.30))
        assertFalse(BifrostNodeQuality.continueDownload(512 * 1024, 0.005))
    }
    @Test fun throughputGoodputExcludesHandshakeAndWarmupBytes() {
        assertEquals(10.0 * 1024 * 1024, BifrostNodeQuality.bodyGoodput(528 * 1024, 16 * 1024, 0.05), 1.0)
        assertEquals(0.0, BifrostNodeQuality.bodyGoodput(16 * 1024, 16 * 1024, 0.05), 0.0)
        assertEquals(0.0, BifrostNodeQuality.bodyGoodput(128 * 1024, 16 * 1024, Double.NaN), 0.0)
    }
    @Test fun longFormWinnerRequiresAllFourSamplesAndWeightsWorstRunMost() {
        val quality = BifrostNodeQuality.runtime()
        val now = 10_000L
        listOf(2_000_000.0, 2_100_000.0, 1_900_000.0, 2_050_000.0).forEachIndexed { index, rate ->
            quality.record("stable", BifrostQualitySample(now - 4 + index, true, 100.0, rate, 0.0))
        }
        listOf(4_000_000.0, 4_100_000.0, 300_000.0, 4_200_000.0).forEachIndexed { index, rate ->
            quality.record("bursty", BifrostQualitySample(now - 4 + index, true, 100.0, rate, 0.0))
        }
        val stable = quality.reliableScore("stable", now, 4)!!
        val bursty = quality.reliableScore("bursty", now, 4)!!
        assertTrue("Worst-run weighting must penalize intermittent peaks", stable > bursty)
        assertEquals("stable", quality.confirmReliableWinner("bursty", "stable", now, 4))

        val incomplete = BifrostNodeQuality.runtime()
        repeat(3) { pass -> incomplete.record("fast", BifrostQualitySample(now + pass, true, 100.0, 9_000_000.0, 0.0)) }
        assertNull(incomplete.reliableScore("fast", now + 10, 4))
    }
    @Test fun finalComparisonCanRejectNoisyChampionAndChooseRunnerUp() {
        val rates = mapOf("current" to 10.0, "burst" to 100.0, "fast" to 80.0, "foreign" to 999.0)
        val allowed = setOf("current", "burst", "fast")
        val finalists = BifrostNodeQuality.finalists(rates, allowed, "current")
        assertEquals(listOf("current", "burst", "fast"), finalists)
        val verified = BifrostNodeQuality()
        for (tag in finalists) repeat(2) { pass ->
            verified.record(tag, BifrostQualitySample(1000L + pass, true, 180.0,
                mapOf("current" to 10.0, "burst" to 5.0, "fast" to 50.0).getValue(tag), 0.0))
        }
        assertEquals("fast", verified.choose(allowed, allowed, "current", 2000))
    }
    @Test fun endOfSweepChampionshipKeepsOnlyTheTwoStrongestHealthyChallengers() {
        val rates = mapOf("current" to 70.0, "fast" to 95.0, "runner" to 90.0, "slow" to 40.0, "foreign" to 999.0)
        val allowed = setOf("current", "fast", "runner", "slow")
        val healthy = setOf("current", "fast", "runner", "slow", "foreign")
        assertEquals(listOf("fast", "runner"), BifrostNodeQuality.roundFinalists(rates, allowed, healthy, "current", 2))
    }
    @Test fun fourStreamCapacityRequiresThreeSuccessfulFlowsAndAggregatesGoodput() {
        fun sample(ok: Boolean, rate: Double) = BifrostQualitySample(1000, ok, 100.0, rate, 2.0)
        val valid = BifrostQualityTransport.aggregateCapacity(listOf(
            sample(true, 10.0), sample(true, 20.0), sample(false, 0.0), sample(true, 30.0),
        ), 4)
        assertTrue(valid.ok)
        assertEquals(60.0, valid.bytesPerSecond, 0.001)
        val invalid = BifrostQualityTransport.aggregateCapacity(listOf(
            sample(true, 10.0), sample(false, 0.0), sample(false, 0.0), sample(true, 30.0),
        ), 4)
        assertFalse(invalid.ok)
    }
    @Test fun nativeStartupHasTimeForLargeListsAndStrictHealthRemainsRequired() {
        val config = JSONObject().put("outbounds", org.json.JSONArray().put(JSONObject()
            .put("type", "urltest").put("outbounds", org.json.JSONArray((1..169).map { "node-$it" }))))
        assertEquals(105_000L, BifrostDataPlaneHealth.startupBudgetMs(config))
        assertTrue(BifrostDataPlaneHealth.isExpectedStatus("HTTP/1.1 204 No Content\r"))
        assertFalse(BifrostDataPlaneHealth.isExpectedStatus("HTTP/1.1 200 OK\r"))
        assertFalse(BifrostDataPlaneHealth.isExpectedStatus("HTTP/1.1 302 Found\r"))
    }
    @Test fun everyNodeIsVisitedEvenWhenTheIncumbentAndLatencyOrderChange() {
        for (size in listOf(1, 30, 169, 300, 600)) {
            val all = (1..size).map { "A-%03d".format(java.util.Locale.ROOT, it) }
            val visited = mutableSetOf<String>()
            var incumbent = all.first(); var cursor = ""; var transfers = 0
            for (batch in 0..size) {
                val cohort = BifrostNodeQuality.cohort(all.reversed(), visited, incumbent, cursor, 7)
                if (cohort.isEmpty() && incumbent in visited) break
                val members = (listOf(incumbent) + cohort).distinct()
                visited.addAll(members); transfers += members.size * 2
                if (cohort.isNotEmpty()) { cursor = cohort.last(); incumbent = cohort.last() }
            }
            assertEquals("Full coverage for $size nodes", all.toSet(), visited)
            assertTrue("Payload bounded for $size nodes", transfers <= 2 * (size + (size + 6) / 7))
            assertTrue(transfers * 128L * 1024 + 8L * 1024 * 1024 <= BifrostNodeQuality.maximumRoundPayloadBytes(size))
        }
    }
    @Test fun downloadPolicyMatchesTheSharedContractFixture() {
        val fixture = JSONObject(File("../tests/fixtures/node-quality-v1.json").readText())
        val now = fixture.getLong("now")
        val cases = fixture.getJSONArray("cases")
        for(i in 0 until cases.length()) {
            val case = cases.getJSONObject(i); val policy = BifrostNodeQuality()
            val samples = case.getJSONObject("samples")
            for(tag in samples.keys()) {
                val rows = samples.getJSONArray(tag)
                for(j in 0 until rows.length()) {
                    val r = rows.getJSONArray(j)
                    policy.record(tag, BifrostQualitySample(now - 1000 + j, r.getBoolean(0), r.getDouble(1), r.getDouble(2), r.getDouble(3)))
                }
            }
            fun names(key: String) = case.getJSONArray(key).let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }
            val expected = if(case.isNull("expected")) null else case.getString("expected")
            assertEquals(case.getString("name"), expected, policy.choose(names("allowed"), names("healthy"), case.getString("incumbent"), now))
            assertNull("old samples must expire", policy.choose(names("allowed"), names("healthy"), case.getString("incumbent"), now + 3_600_001))
        }
    }
    @Test fun qualityIngressIsAuthenticatedAndDoesNotChangeUserSelection() {
        val config = JSONObject("""{"inbounds":[],"outbounds":[{"type":"selector","tag":"proxy","outbounds":["proxy-auto","proxy-candidate-A","proxy-candidate-B"],"default":"proxy-auto"}],"route":{"final":"proxy","rules":[]}}""")
        val original = config.getJSONArray("outbounds").getJSONObject(0).toString()
        BifrostQualityTransport.configure(config)
        assertEquals(original, config.getJSONArray("outbounds").getJSONObject(0).toString())
        assertEquals("proxy", config.getJSONObject("route").getString("final"))
        val inbound = config.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("127.0.0.1", inbound.getString("listen"))
        assertTrue(inbound.getJSONArray("users").getJSONObject(0).getString("password").length >= 32)
        assertEquals(BifrostQualityTransport.GROUP, config.getJSONObject("route").getJSONArray("rules").getJSONObject(0).getString("outbound"))
    }
    @Test fun disconnectCancelsAStalledQualitySocket() {
        val server = java.net.ServerSocket(0,1,java.net.InetAddress.getLoopbackAddress())
        val accepted = java.util.concurrent.CountDownLatch(1)
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        val peer = executor.submit<java.net.Socket> { server.accept().also { accepted.countDown() } }
        val transport = BifrostQualityTransport(server.localPort,"TEST-ONLY-password")
        val measurement = executor.submit<BifrostQualitySample> { transport.measure() }
        try {
            assertTrue(accepted.await(2,java.util.concurrent.TimeUnit.SECONDS))
            transport.close()
            assertFalse(measurement.get(2,java.util.concurrent.TimeUnit.SECONDS).ok)
        } finally {
            transport.close(); server.close()
            runCatching { peer.get(1,java.util.concurrent.TimeUnit.SECONDS).close() }
            executor.shutdownNow()
        }
    }
}
