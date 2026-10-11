package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostQualityMemoryTest {
    @Test fun measurementTrafficDoesNotHideRealUserTrafficOrPauseItself() {
        assertFalse(BifrostUserTrafficLoad.busy(512 * 1024L, 1024, 512 * 1024L))
        assertTrue(BifrostUserTrafficLoad.busy(544 * 1024L, 1024, 512 * 1024L))
        assertTrue(BifrostUserTrafficLoad.busy(20 * 1024L, 0, 0))
        assertTrue(BifrostUserTrafficLoad.busy(0, 20 * 1024L, 512 * 1024L))
    }
    @Test fun throughputPreferenceExpiresAndCannotCrossNetworkOrConfigKeys() {
        val key = "memory-${java.util.UUID.randomUUID()}"
        BifrostQualityMemory.remember(key, "candidate-8", 800_000.0, 5_000)
        assertEquals("candidate-8", BifrostQualityMemory.read(key, 6_000)?.tag)
        assertNull(BifrostQualityMemory.read("$key-changed-profile", 6_000))
        assertNull(BifrostQualityMemory.read(key, 1_205_001))
        assertNull(BifrostQualityMemory.read(key, 4_000))
    }
    @Test fun cellularDownloadBudgetSurvivesASelectorRestartAndAFailedRound() {
        val key = "metered-${java.util.UUID.randomUUID()}"
        BifrostQualityMemory.deferMetered(key, 905_000)
        assertEquals(905_000L, BifrostQualityMemory.read(key, 6_000)?.nextMeteredAt)
        BifrostQualityMemory.remember(key, "candidate-8", 800_000.0, 7_000)
        assertEquals(905_000L, BifrostQualityMemory.read(key, 8_000)?.nextMeteredAt)
    }
}
