package com.bifrost.client
import org.junit.Assert.*
import org.junit.Test

class BifrostProbeBudgetTest {
    @Test fun rollingWindowDoesNotDoubleAllowanceAtFixedHourBoundary() {
        val budget = BifrostProbeBudget()
        assertTrue(budget.reserve(299_000, BifrostProbeBudget.MOBILE_BYTES, true, false))
        assertFalse(budget.reserve(301_000, 1, true, false))
        assertTrue(budget.reserve(599_000, 1, true, false))
    }
    @Test fun reconstructionAndWifiSwitchDoNotResetMobileReservations() {
        var stored = emptyList<BifrostProbeBudget.Entry>()
        fun open() = BifrostProbeBudget({ stored }, { stored = it })
        assertTrue(open().reserve(100, BifrostProbeBudget.MOBILE_BYTES, true, false))
        assertTrue(open().reserve(200, 1024, false, false))
        assertFalse(open().reserve(300, 1, true, false))
        assertTrue(open().reserve(300_100, 1, true, false))
    }
    @Test fun failedPersistenceCannotAuthorizeUntrackedTraffic() {
        val budget = BifrostProbeBudget(write = { error("disk unavailable") })
        assertFalse(budget.reserve(100, 1024, true, false))
    }
    @Test fun backwardClockCannotGrantFreshAllowance() {
        val budget = BifrostProbeBudget()
        assertTrue(budget.reserve(10_000, BifrostProbeBudget.MOBILE_BYTES, true, false))
        assertFalse(budget.reserve(1_000, 1, true, false))
    }
}
