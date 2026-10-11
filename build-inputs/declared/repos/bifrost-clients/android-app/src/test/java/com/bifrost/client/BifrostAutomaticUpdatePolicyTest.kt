package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostAutomaticUpdatePolicyTest {
    private fun idle(interactive: Boolean = false, state: BifrostLeakState = BifrostLeakState.HEALTHY,
        owner: Boolean = true, installing: Boolean = false, sampleAt: Long = 600_000,
        down: Long = 0, lastTraffic: Long = 400_000, running: Long = 600_000) =
        BifrostAutomaticUpdatePolicy.idle(interactive, state, owner, installing, 600_000,
            BifrostTrafficRate(down, 0, sampleAt), running, lastTraffic)
    @Test fun browsingBusyOrUnknownTrafficNeverPermitsBackgroundInstallation() {
        assertTrue(idle())
        assertFalse(idle(interactive = true))
        assertFalse(idle(down = 2048))
        assertFalse(idle(lastTraffic = 500_000))
        assertFalse(idle(sampleAt = 594_999))
        assertFalse(idle(sampleAt = 600_001))
        assertFalse(idle(lastTraffic = 600_001))
        assertFalse(idle(running = 179_999))
    }
    @Test fun connectionTransitionsAndOtherInstallationsAreExcluded() {
        assertFalse(idle(installing = true))
        assertFalse(idle(owner = false))
        assertFalse(idle(state = BifrostLeakState.STARTING))
        assertFalse(idle(state = BifrostLeakState.BLOCKING))
        assertFalse(idle(state = BifrostLeakState.UNPROTECTED))
        assertFalse(idle(state = BifrostLeakState.STOPPED))
        assertTrue(idle(state = BifrostLeakState.STOPPED, owner = false, sampleAt = 0))
    }
}
