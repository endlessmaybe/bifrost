package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class BifrostOptimizerExecutionTest {
    private class Harness(val count: Int = 23, networkKey: String? = null, startAt: Long = 10_000_000L) : AutoCloseable {
        var now = startAt
        val tags = (0 until count).map { "proxy-candidate-$it" }
        val samples = mutableMapOf<String, Int>()
        val switches = mutableListOf<String>()
        var measuring = ""
        var failTransfers = false
        var failedTags = emptySet<String>()
        var failCommand = false
        var healthy = true
        var rateMultiplier = 1.0
        val rates = mutableMapOf<String, Double>()
        var beforeMeasure: () -> Unit = {}
        var onPause: (Long) -> Unit = {}
        var refreshes = 0
        var refreshAdvanceMs = 0L
        var visible = true
        var interactive = true
        var fullBodiesFail = false
        var requestedBytes = 0L
        var cancelledSamples = 0
        var latencyAgeMs = 0L
        var latencyOffsetMs = 0
        val latencies = mutableMapOf<String, Int>()
        val selected = CountDownLatch(1)
        lateinit var selector: BifrostProgressiveSelector
        init {
            val config = JSONObject().put("inbounds", JSONArray()).put("outbounds", JSONArray().put(
                JSONObject().put("tag", "proxy").put("type", "selector")
                    .put("outbounds", JSONArray(listOf("proxy-auto") + tags))
            )).toString()
            selector = BifrostProgressiveSelector(config,
                selectOutbound = { group, tag ->
                    if (group == "proxy") { synchronized(switches) { switches.add(tag) }; selected.countDown() }
                    else { if (failCommand) error("simulated IPC failure"); measuring = tag }
                },
                requestUrlTest = { refreshes++; now += refreshAdvanceMs; publish() },
                measureSample = { bytes ->
                    requestedBytes += bytes
                    beforeMeasure()
                    samples[measuring] = samples.getOrDefault(measuring, 0) + 1
                    now += 50
                    BifrostQualitySample(now, !failTransfers && measuring !in failedTags, 100.0, (rates[measuring] ?: ((tags.indexOf(measuring) + 1) * 100_000.0)) * rateMultiplier, 0.0)
                },
                measureLongSample = { _ ->
                    requestedBytes += BifrostQualityTransport.LONG_FORM_BYTES
                    beforeMeasure()
                    samples[measuring] = samples.getOrDefault(measuring, 0) + 1
                    now += 50
                    BifrostQualitySample(now, !failTransfers && measuring !in failedTags && !fullBodiesFail,
                        100.0, (rates[measuring] ?: ((tags.indexOf(measuring) + 1) * 100_000.0)) * rateMultiplier, 0.0)
                },
                clock = { now }, pause = { now += it; onPause(it) }, schedule = false,
                automaticWorkAllowed = { visible }, recoveryWorkAllowed = { interactive }, elapsedClock = { now },
                cancelSample = { cancelledSamples++ })
            selector.metered = false
            networkKey?.let(selector::networkChanged)
            publish()
            check(selected.await(3, TimeUnit.SECONDS)) { "Initial selection did not execute" }
        }
        fun publish() = selector.acceptMeasurements("proxy", tags.mapIndexed { index, tag ->
            BifrostMeasuredCandidate(tag, if (healthy) latencies[tag] ?: (latencyOffsetMs + 100 + index % 199) else 0, (now - latencyAgeMs) / 1000)
        })
        fun round() {
            repeat(8000) {
                selector.optimize()
                if (selector.completedQualityRound) return
                now += 15_000; publish()
            }
            error("Full candidate coverage never completed")
        }
        override fun close() = selector.close()
    }

    @Test fun accessNetworkChangeRejectsOldLatencyAndSelectsFromFreshResults() = Harness(3, networkKey = "cellular-test").use { h ->
        val oldCount = h.switches.size
        val oldTime = h.now / 1000
        h.now += 5_000
        h.selector.networkChanged("wifi-test")
        h.selector.acceptMeasurements("proxy", listOf(BifrostMeasuredCandidate(h.tags[0], 1, oldTime)))
        Thread.sleep(100)
        assertEquals(oldCount, h.switches.size)
        h.now += 2_000
        h.selector.acceptMeasurements("proxy", listOf(BifrostMeasuredCandidate(h.tags[2], 120, h.now / 1000)))
        repeat(50) { if (h.switches.size == oldCount) Thread.sleep(20) }
        assertEquals(h.tags[2], h.switches.last())
        assertEquals(0L, h.selector.nextQualityAt)
    }

    @Test fun sparseProxyFailuresBypassMobileCooldownOnlyAfterRepeatedComparison() = Harness(3).use { h ->
        h.selector.metered = true
        h.visible = false // Web browsing may never yield a 30-second quiet window.
        h.selector.nextQualityAt = h.now + 900_000
        h.failedTags = setOf(h.tags.first())
        repeat(3) {
            h.now += 1000
            h.selector.observeTransportFailure("open connection to example.com using outbound/selector[proxy]: i/o timeout")
        }
        h.selector.optimize()
        assertNotEquals(h.tags.first(), h.switches.last())
        assertEquals(6, h.samples[h.tags.first()])
        assertEquals(6, h.samples[h.switches.last()])
        assertTrue(h.requestedBytes <= BifrostQualityWorkPolicy.MAX_BYTES)
    }

    @Test fun passiveFailuresCannotPromoteAnAlternativeThatAlsoFails() = Harness(3).use { h ->
        h.selector.metered = true;h.visible = false;h.failTransfers = true
        repeat(3) { h.now += 1000;h.selector.observeTransportFailure("connection download handshake: connection reset by peer") }
        h.selector.optimize()
        assertEquals(h.tags.first(), h.switches.last())
        assertTrue(h.requestedBytes <= 4L * BifrostQualityTransport.BYTES)
    }

    @Test fun videoTrafficCancelsAnInFlightProbeBeforeItCanSwitchRoutes() = Harness(3).use { h ->
        val initialSwitches = h.switches.size
        h.beforeMeasure = { h.selector.updateUserTraffic(512_000.0) }
        h.selector.optimize()
        assertEquals(1, h.cancelledSamples)
        assertEquals("No further probe after playback starts", 1, h.samples.values.sum())
        assertEquals(initialSwitches, h.switches.size)
    }

    @Test fun stalledSlowMediaBetweenSchedulerTicksStillGetsARealComparison() = Harness(3).use { h ->
        h.visible = false
        repeat(31) { second ->
            h.selector.updateUserTraffic(if (second % 8 < 3) 64.0 * 1024 else 0.0)
            if (second < 30 && second % 15 == 0) h.selector.optimize()
            h.now += 1000
        }
        assertTrue(h.samples.isEmpty())
        h.selector.updateUserTraffic(0.0)
        h.selector.optimize()
        assertTrue(h.samples.isNotEmpty())
        assertTrue(h.requestedBytes <= BifrostQualityWorkPolicy.MAX_BYTES)
    }

    @Test fun wholeRoundMeasuresEveryEligibleNodeTwiceAndSwitchesBeyondSeed() = Harness().use { h ->
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
        assertTrue(h.samples.values.all { it >= 2 })
        val strongestRunnersUp = h.tags.dropLast(1).takeLast(2)
        assertTrue("End-of-sweep finalists must receive the four-stream capacity championship",
            strongestRunnersUp.all { h.samples.getValue(it) >= 10 })
        assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
        assertTrue(h.switches.size > 2)
        assertEquals(h.now + BifrostMaintenancePolicy.QUALITY_INTERVAL_MS, h.selector.nextQualityAt)
        val total = h.samples.values.sum()
        h.now += 60_000
        h.selector.optimize()
        assertEquals(total, h.samples.values.sum())
    }

    @Test fun unqualifiedLatencyWinnerCannotReplaceAHealthyActiveProxy() = Harness(3).use { h ->
        val incumbent = h.switches.last()
        assertEquals(h.tags.first(), incumbent)
        h.latencies[incumbent] = 900
        h.latencies[h.tags[1]] = 30
        h.publish()
        Thread.sleep(300)
        assertEquals(1, h.switches.size)
        assertEquals(incumbent, h.switches.last())
    }

    @Test fun stableWinnerGetsOnlyTwoBoundedRecheckSamplesOnTheAggressiveCadence() = Harness(3).use { h ->
        h.round()
        val winner = h.switches.last()
        val before = h.samples.values.sum()
        h.selector.metered = true
        h.now = h.selector.nextQualityAt
        h.publish()
        h.selector.optimize()
        assertEquals(before + 2, h.samples.values.sum())
        assertEquals(winner, h.switches.last())
        assertEquals(h.now + BifrostMaintenancePolicy.METERED_QUALITY_INTERVAL_MS, h.selector.nextQualityAt)
        h.now = h.selector.nextQualityAt
        h.rateMultiplier = 0.1
        h.publish()
        h.selector.optimize()
        assertTrue("Two low incumbent samples reopen comparison: before=$before after=${h.samples.values.sum()}",
            h.samples.values.sum() > before + 4)
    }

    @Test fun threeHundredEligibleCandidatesHaveNoSmallPoolOrFourSwitchCap() = Harness(300).use { h ->
        h.round()
        assertEquals(300, h.samples.size)
        assertTrue(h.samples.values.all { it >= 2 })
        assertTrue("Exploration must be able to replace the seed", h.switches.size > 1)
        // Every candidate is compared; sustained throughput is authoritative
        // after native health has proved reachability. A higher-RTT path must
        // therefore be allowed to win when its body goodput is much higher.
        val selectedIndex = h.tags.indexOf(h.switches.last())
        assertTrue("A throughput winner must remain a real candidate", selectedIndex >= 0)
        assertTrue("Large-pool refinement must converge near the highest-throughput candidate",
            (selectedIndex + 1) * 1.03 >= h.count)
    }

    @Test fun emptyLatencyResultsRetrySoonAndRecoverWithoutReconnecting() = Harness().use { h ->
        h.healthy = false
        h.publish()
        h.selector.optimize()
        assertEquals(h.now + 2_000, h.selector.nextQualityAt)
        assertTrue(h.samples.isEmpty())
        h.now += 2_000
        h.healthy = true
        h.round()
        assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
    }

    @Test fun commandFailureDoesNotSuppressOptimizationForAnHour() = Harness().use { h ->
        h.failCommand = true
        assertTrue(runCatching { h.selector.optimize() }.isFailure)
        assertEquals(h.now + 2_000, h.selector.nextQualityAt)
        h.now += 2_000
        h.failCommand = false
        h.round()
        assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
    }

    @Test fun failedTransfersCannotBeReportedAsSuccessfulHourlyRound() = Harness().use { h ->
        h.failTransfers = true
        h.selector.optimize()
        assertEquals(h.tags.first(), h.switches.last())
        assertEquals(h.now + 2_000, h.selector.nextQualityAt)
    }

    @Test fun nativeReadbackFollowsAutoAndManualLeavesWithoutReturningSeed() {
        val labels = mapOf("proxy-candidate-0" to "A-01", "proxy-candidate-22" to "B-07")
        assertNull(BifrostRouteReadback.resolve(labels, emptyMap()))
        assertEquals("B-07", BifrostRouteReadback.resolve(labels,
            mapOf("proxy" to "proxy-auto", "proxy-auto" to "proxy-candidate-22")))
        assertEquals("B-07", BifrostRouteReadback.resolve(labels, mapOf("proxy" to "proxy-candidate-22")))
        assertNull(BifrostRouteReadback.resolve(labels, mapOf("proxy" to "foreign")))
        assertNull(BifrostRouteReadback.resolve(labels, mapOf("proxy" to "proxy-auto", "proxy-auto" to "proxy")))
        assertEquals("A-01", BifrostRouteReadback.resolve(mapOf("proxy" to "A-01"), emptyMap()))
    }

    @Test fun recentCachedNativeLatencyDoesNotPreventAnyThroughputMeasurement() = Harness(3).use { h ->
        h.latencyAgeMs = 5_000L
        val started = h.now
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
        assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
        assertTrue("Cached positive results must not wait for every timestamp to change", h.now - started < 600_000)
    }

    @Test fun httpLatencyAbove300msStillReachesTheActualPayloadComparison() = Harness(3).use { h ->
        h.latencyOffsetMs = 1500
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
        assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
    }

    @Test fun nativeResultsArrivingAfterTheRoundStartsAreStillEligible() = Harness(3).use { h ->
        h.refreshAdvanceMs = 1_000
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
        assertTrue("Retain a confirmed exit within the 25% no-churn band", (h.tags.indexOf(h.switches.last()) + 1) * 1.25 >= h.count)
    }

    @Test fun reconnectOnTheSameNetworkReusesTheMeasuredWinnerWithoutADownload() {
        val key = "test-network-${java.util.UUID.randomUUID()}"
        var reconnectedAt = 0L
        Harness(3, key).use { h -> h.round(); assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count); reconnectedAt = h.now + 1 }
        Harness(3, key, reconnectedAt).use { h ->
            assertTrue("Retain only the 3% measurement-noise band", (h.tags.indexOf(h.switches.last()) + 1) * 1.03 >= h.count)
            assertTrue(h.samples.isEmpty())
            val winner = h.switches.last()
            h.latencies[winner] = 1500
            h.publish(); Thread.sleep(300)
            assertEquals(winner, h.switches.last())
        }
        Harness(3, "$key-other").use { h -> assertEquals(h.tags.first(), h.switches.last()) }
    }

    @Test fun partialSweepIsNotPersistedAsAReconnectWinner() {
        val key = "partial-network-${java.util.UUID.randomUUID()}"
        var reconnectAt = 0L
        Harness(6, key).use { h ->
            h.selector.optimize()
            assertFalse(h.selector.completedQualityRound)
            assertTrue(h.samples.isNotEmpty())
            reconnectAt = h.now + 1
        }
        Harness(6, key, reconnectAt).use { h ->
            assertEquals(h.tags.first(), h.switches.last())
            assertTrue(h.samples.isEmpty())
        }
    }

    @Test fun backgroundSkipsLatencyAndBodyTestsAndPausesMidRound() = Harness().use { h ->
        h.visible = false
        repeat(5) { h.selector.optimize() }
        assertEquals(0, h.refreshes)
        assertTrue(h.samples.isEmpty())
        h.visible = true
        h.beforeMeasure = { h.visible = false }
        h.selector.optimize()
        assertEquals(1, h.samples.values.sum())
        assertEquals(1, h.switches.size)
    }

    @Test fun cellularInitialComparisonsAreBoundedAndThenRespectCooldown() = Harness(20).use { h ->
        h.selector.metered = true
        h.selector.optimize()
        assertEquals(2, h.samples.size)
        assertEquals(12, h.samples.values.sum())
        assertEquals(h.now + 2_000, h.selector.nextQualityAt)
        var previous = h.samples.values.sum()
        repeat(4) {
            h.now += 2_000; h.publish(); h.selector.optimize()
            assertTrue(h.samples.values.sum() > previous)
            previous = h.samples.values.sum()
        }
        assertTrue(h.samples.size >= 5)
        assertTrue(h.requestedBytes <= BifrostQualityWorkPolicy.MAX_BYTES)
    }

    @Test fun busyForegroundKeepsDeferringWithoutASecondCallEscape() = Harness().use { h ->
        h.selector.busy = true
        repeat(5) { h.now += 15_000; h.selector.optimize() }
        assertTrue(h.samples.isEmpty())
        assertEquals(0, h.refreshes)
        h.selector.busy = false
        h.round()
        assertTrue("Retain a confirmed exit within the 25% no-churn band", (h.tags.indexOf(h.switches.last()) + 1) * 1.25 >= h.count)
    }

    @Test fun foregroundTrafficStartingMidPairDiscardsItWithoutWaitingOrSwitching() = Harness().use { h ->
        h.beforeMeasure = { h.selector.busy = true }
        h.selector.optimize()
        assertEquals(1, h.samples.values.sum())
        assertEquals(1, h.switches.size)
        h.beforeMeasure = {}; h.selector.busy = false
        h.now += 2_000
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun disconnectAndNetworkReplacementCancelBeforeAnyFurtherTransfers() {
        for (disconnect in listOf(false, true)) Harness().use { h ->
            h.beforeMeasure = { if (disconnect) h.selector.close() else h.selector.networkChanged("new-network") }
            h.selector.optimize()
            assertEquals(1, h.samples.values.sum())
            assertEquals(1, h.switches.size)
        }
    }

    @Test fun slowStreamingInAnotherAppCanRecoverButHighTrafficAndScreenOffCannotProbe() = Harness(3).use { h ->
        h.visible = false; h.selector.busy = true; h.selector.userBytesPerSecond = 64.0 * 1024
        repeat(2) { h.selector.optimize(); h.now += 15_000 }
        assertTrue(h.samples.isEmpty())
        h.selector.optimize()
        assertTrue(h.samples.isNotEmpty())
        val count = h.samples.values.sum()
        h.now += 150_000; h.selector.userBytesPerSecond = 1024.0 * 1024
        h.selector.optimize(); assertEquals(count, h.samples.values.sum())
        h.interactive = false; h.selector.userBytesPerSecond = 64.0 * 1024
        repeat(10) { h.now += 15_000; h.selector.optimize() }
        assertEquals(count, h.samples.values.sum())
    }

    @Test fun aFastShortBodyCannotReplaceTheExitWhenFullDownloadsFail() = Harness(3).use { h ->
        h.fullBodiesFail = true
        h.selector.optimize()
        assertEquals(h.tags.first(), h.switches.last())
        assertEquals(1, h.switches.size)
        assertTrue(h.requestedBytes > 512 * 1024)
    }

    @Test fun diagnosticBudgetRemainsBoundedAcrossA24HourClockSimulation() = Harness(300).use { h ->
        val until = h.now + 24L * 60 * 60 * 1000
        while (h.now < until) {
            h.selector.optimize(); h.now += 15_000; h.publish()
        }
        // Fixed reservation windows may straddle a wall-clock sample boundary;
        // include the one partial window when checking the complete day.
        assertTrue(h.requestedBytes <= 289L * BifrostQualityWorkPolicy.MAX_BYTES)
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun completedRoundOnlySpendsBoundedRechecksOnQuietTimers() = Harness().use { h ->
        h.round()
        val bytes = h.requestedBytes
        repeat(1000) { h.now += 15_000; h.publish(); h.selector.optimize() }
        assertTrue(h.requestedBytes > bytes)
        // The two-minute incumbent cadence intentionally spends more than the
        // old 15-minute policy, but the persistent Wi-Fi budget is still the
        // authoritative hard ceiling for any rolling hour.
        assertTrue(h.requestedBytes - bytes <= 5L * BifrostProbeBudget.WIFI_BYTES)
    }

    @Test fun failedPoolDoesNotClaimCompletionAndRecoversWhenTransfersReturn() = Harness(5).use { h ->
        h.failTransfers = true
        repeat(20) { h.selector.optimize(); h.now += 15_000; h.publish() }
        assertFalse(h.selector.completedQualityRound)
        assertTrue(h.requestedBytes > 0)
        assertEquals(1, h.switches.size)
        h.failTransfers = false
        h.round()
        assertTrue(h.selector.completedQualityRound)
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun passiveSlowTrafficCanReopenACompletedRound() = Harness(3).use { h ->
        h.round()
        val samples = h.samples.values.sum()
        repeat(31) { h.selector.updateUserTraffic(64.0 * 1024); h.now += 1000 }
        h.selector.optimize()
        assertTrue(h.samples.values.sum() > samples)
    }

    @Test fun continuousMobileFailuresStayWithinRollingHourBudget() = Harness(5).use { h ->
        h.selector.metered = true
        h.failedTags = setOf(h.tags.first())
        val until = h.now + 60 * 60_000L
        while (h.now < until) {
            h.selector.observeTransportFailure("open connection using outbound/selector[proxy]: i/o timeout")
            h.selector.updateUserTraffic(64.0 * 1024)
            h.selector.optimize(); h.now += 1000; h.publish()
        }
        assertTrue(h.requestedBytes <= BifrostProbeBudget.MOBILE_BYTES)
    }

    @Test fun repeatedCommandFailuresBackOffButDoNotStopTheCampaign() = Harness(3).use { h ->
        h.failCommand = true
        repeat(3) {
            runCatching { h.selector.optimize() }
            h.now = maxOf(h.now + 1, h.selector.nextQualityAt)
            h.publish()
        }
        assertFalse(h.selector.completedQualityRound)
        h.failCommand = false
        h.round()
        assertTrue(h.selector.completedQualityRound)
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun recentlyAbandonedExitCannotCausePingPongOnOneSlowEpisode() = Harness(2).use { h ->
        h.round()
        val retained = h.switches.last()
        h.rates[h.tags.first()] = 1_000_000.0
        repeat(31) { h.selector.updateUserTraffic(64.0 * 1024); h.now += 1000 }
        h.selector.optimize()
        assertEquals(retained, h.switches.last())
    }

    @Test fun latencyUpdatesCannotUndoAHealthyPayloadWinnerButFailureStillFallsBack() = Harness(3).use { h ->
        h.round()
        val winner = h.switches.last()
        val changes = h.switches.size
        h.latencies[winner] = 1500
        h.publish()
        Thread.sleep(300)
        assertEquals(changes, h.switches.size)
        assertEquals(winner, h.switches.last())
        h.latencies[winner] = 0
        h.publish()
        repeat(50) { if (h.switches.size == changes) Thread.sleep(20) }
        assertEquals(h.tags.first(), h.switches.last())
    }

    @Test fun startupRecoveryCannotPrematurelyFinishInitialCandidateCoverage() = Harness(5).use { h ->
        repeat(31) { h.selector.updateUserTraffic(64.0 * 1024); h.now += 1000 }
        h.selector.optimize()
        assertFalse(h.selector.completedQualityRound)
        h.selector.updateUserTraffic(0.0)
        h.now += 2000
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun userTrafficPreemptionDoesNotExhaustInitialQualification() = Harness(5).use { h ->
        repeat(4) {
            h.selector.updateUserTraffic(0.0)
            h.beforeMeasure = { h.selector.updateUserTraffic(512_000.0) }
            h.selector.optimize(); h.now += 15_000
        }
        assertFalse(h.selector.completedQualityRound)
        h.beforeMeasure = {}
        h.selector.updateUserTraffic(0.0)
        h.round()
        assertEquals(h.tags.toSet(), h.samples.keys)
    }

    @Test fun callbacksFromOldConnectionCannotOverwriteCurrentRoute() {
        val old = BifrostTrafficTelemetry.beginRoute()
        BifrostTrafficTelemetry.acceptRoute(old, "A-01")
        val current = BifrostTrafficTelemetry.beginRoute()
        BifrostTrafficTelemetry.acceptRoute(old, "A-02")
        assertNull(BifrostTrafficTelemetry.route.value)
        BifrostTrafficTelemetry.acceptRoute(current, "B-07")
        BifrostTrafficTelemetry.acceptRoute(old, "A-03")
        assertEquals("B-07", BifrostTrafficTelemetry.route.value)
        BifrostTrafficTelemetry.beginRoute()
    }
}
