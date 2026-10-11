package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostMaintenancePolicyTest {
    @Test fun throughputMaintenanceMatchesWindowsAggressiveCadence() {
        assertEquals(2 * 60_000L, BifrostMaintenancePolicy.QUALITY_INTERVAL_MS)
        assertEquals(2 * 60_000L, BifrostMaintenancePolicy.METERED_QUALITY_INTERVAL_MS)
        assertEquals(60 * 60_000L, BifrostMaintenancePolicy.FULL_SWEEP_INTERVAL_MS)
    }
    @Test fun idleBackgroundAndScreenOffDoNotGenerateHealthTraffic() {
        for (now in 10_000L..3_600_000L step 5_000L) {
            assertFalse(BifrostMaintenancePolicy.shouldProbe(now, 0, false, true, 0, 0, 0))
            assertFalse(BifrostMaintenancePolicy.shouldProbe(now, 0, true, false, 0, 0, 3))
        }
    }
    @Test fun receivingVideoSuppressesProbeButStalledDemandRecoversInBackground() {
        assertFalse(BifrostMaintenancePolicy.shouldProbe(300_000, 0, true, true, 299_000, 299_000, 0))
        assertTrue(BifrostMaintenancePolicy.shouldProbe(300_000, 280_000, false, false, 250_000, 299_000, 0))
        assertFalse(BifrostMaintenancePolicy.shouldProbe(300_000, 290_000, false, false, 250_000, 299_000, 0))
    }
    @Test fun visibleIdleUsesThreeMinuteCadence() {
        assertFalse(BifrostMaintenancePolicy.shouldProbe(179_999, 0, true, true, 0, 0, 0))
        assertTrue(BifrostMaintenancePolicy.shouldProbe(180_000, 0, true, true, 0, 0, 0))
    }
    @Test fun transportFailureDrivesBackgroundRecoveryWithoutPeriodicIdleTraffic() {
        assertTrue(BifrostMaintenancePolicy.shouldProbe(
            300_000, 280_000, false, false, 299_000, 0, 0, 299_000))
        assertFalse(BifrostMaintenancePolicy.shouldProbe(
            300_000, 295_000, false, false, 299_000, 0, 0, 299_000))
        // Once a health probe has failed, follow-up confirmation remains
        // eligible even after the original native failure marker ages out.
        assertTrue(BifrostMaintenancePolicy.shouldProbe(
            360_000, 320_000, false, false, 359_000, 0, 1, 300_000))
    }
}
