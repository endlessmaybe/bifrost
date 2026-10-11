package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostQualityWorkPolicyTest {
    @Test fun slowBurstsAndTheirStallsFormOneRecoveryWindow() {
        val policy = BifrostQualityWorkPolicy()
        for (second in 0..31) {
            val rate = if (second % 8 < 3) 64.0 * 1024 else 0.0
            policy.observe(second * 1000L, rate)
        }
        assertEquals(true, policy.admit(31_000, 0.0, false, true))
        for (second in 32..100) policy.observe(second * 1000L, 64.0 * 1024)
        assertNull(policy.admit(100_000, 64.0 * 1024, false, true))
        for (second in 101..152) policy.observe(second * 1000L, 64.0 * 1024)
        assertEquals(true, policy.admit(152_000, 0.0, false, true))
    }

    @Test fun idleAloneAndStaleSlowSessionsDoNotRequestRecovery() {
        val policy = BifrostQualityWorkPolicy()
        for (second in 0..90) policy.observe(second * 1000L, 0.0)
        assertNull(policy.admit(90_000, 0.0, false, true))
        policy.observe(91_000, 64.0 * 1024)
        for (second in 92..122) policy.observe(second * 1000L, 0.0)
        assertNull(policy.admit(122_000, 0.0, false, true))
    }

    @Test fun fastTrafficCounterGapsNetworkResetAndScreenOffDiscardSlowEvidence() {
        for (reset in 0..4) {
            val policy = BifrostQualityWorkPolicy()
            for (second in 0..29) policy.observe(second * 1000L, 64.0 * 1024)
            when (reset) {
                0 -> policy.observe(30_000, 512.0 * 1024)
                1 -> policy.observe(30_000, Double.NaN)
                2 -> policy.observe(61_000, 0.0)
                3 -> policy.resetActivity()
                4 -> assertNull(policy.admit(30_000, 0.0, false, false))
            }
            assertNull(policy.admit(62_000, 0.0, false, true))
        }
    }

    @Test fun continuationThresholdsMatchWindowsForegroundPolicy() {
        assertTrue(BifrostQualityWorkPolicy.canContinue(64.0 * 1024, false))
        assertFalse(BifrostQualityWorkPolicy.canContinue(128.0 * 1024, false))
        assertTrue(BifrostQualityWorkPolicy.canContinue(256.0 * 1024, true))
        assertFalse(BifrostQualityWorkPolicy.canContinue(512.0 * 1024, true))
    }
}
