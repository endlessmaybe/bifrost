package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostProbeTrafficGuardTest {
    @Test fun coldStartAndBufferedVideoGapsDoNotStartBandwidthProbes() {
        var now = 0L
        val guard = BifrostProbeTrafficGuard { now }
        assertFalse(guard.ready())
        // Video downloads a segment every twenty seconds. Single zero-rate
        // samples between those bursts must not admit the optimizer.
        repeat(120) { second ->
            now = second * 1000L
            guard.observe(if (second % 20 == 0) 600_000.0 else 0.0)
            assertFalse("second=$second", guard.ready())
        }
        for (second in 120..130) { now = second * 1000L; guard.observe(0.0) }
        assertTrue(guard.ready())
    }

    @Test fun staleUnknownAndBackwardTimeCannotClaimIdle() {
        var now = 0L
        val guard = BifrostProbeTrafficGuard { now }
        for (second in 0..30) { now = second * 1000L; guard.observe(0.0) }
        assertTrue(guard.ready())
        now += 4_000; assertFalse(guard.ready())
        guard.observe(Double.NaN); assertFalse(guard.ready())
        now += 1_000; guard.observe(0.0); assertFalse(guard.ready())
        now -= 5_000; guard.observe(0.0); assertFalse(guard.ready())
    }
}
