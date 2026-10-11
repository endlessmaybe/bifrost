package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostRootRecoveryTest {
    @Test fun failedHelperReleasesOldDescriptorBeforeCreatingNewFence() {
        for (alive in listOf(true, false)) {
            val steps = mutableListOf<String>()
            BifrostRootRecoverySequence.prepare(alive, { steps += "block" }, { steps += "stop" })
            assertEquals(if (alive) listOf("block", "stop") else listOf("stop", "block"), steps)
        }
    }
    @Test fun failedStopCannotCreateASecondBoundary() {
        var blocked = false
        try {
            BifrostRootRecoverySequence.prepare(false, { blocked = true }, { error("BF-CORE-STOP") })
            fail("stop failure swallowed")
        } catch (_: IllegalStateException) { assertFalse(blocked) }
    }
    @Test fun coexistenceJournalSeparatesInfrastructureFromAppPolicy() {
        assertEquals("BFR13 10403 none 0 1 10500 0 smart\n", BifrostRootCoexistence.wire(10403, "none", emptyList(), listOf(10500, 10500)))
        assertEquals("BFR13 10403 allow 2 10500 10600 1 10500 0 smart\n", BifrostRootCoexistence.wire(10403, "allow", listOf(10500, 10600), listOf(10500)))
        assertEquals("BFR13 10403 none 0 0 0 smart\n", BifrostRootCoexistence.wire(10403, "none", emptyList(), emptyList()))
        assertEquals("BFR13 10403 none 0 1 10500 1 192.168.1.1 smart\n", BifrostRootCoexistence.wire(10403, "none", emptyList(), listOf(10500), listOf("192.168.1.1", "192.168.1.1")))
        for (uid in listOf(0, 9999, 10403, 110500)) {
            try { BifrostRootCoexistence.wire(10403, "none", emptyList(), listOf(uid)); fail("invalid infrastructure UID") }
            catch (_: IllegalStateException) { }
        }
    }
    @Test fun tileRetriesFailedOwnersWithoutInterruptingHealthyOrPendingConnections() {
        assertTrue(BifrostQuickConnectionPolicy.canStart(BifrostLeakState.STOPPED, null))
        assertTrue(BifrostQuickConnectionPolicy.canStart(BifrostLeakState.BLOCKING, BifrostServiceOwnershipPhase.BLOCKED_FAILED))
        assertTrue(BifrostQuickConnectionPolicy.canStart(BifrostLeakState.UNPROTECTED, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED))
        for (state in BifrostLeakState.entries) {
            assertFalse(BifrostQuickConnectionPolicy.canStart(state, BifrostServiceOwnershipPhase.PENDING))
            assertFalse(BifrostQuickConnectionPolicy.canStart(state, BifrostServiceOwnershipPhase.DISCONNECTING))
        }
        assertFalse(BifrostQuickConnectionPolicy.canStart(BifrostLeakState.HEALTHY, BifrostServiceOwnershipPhase.COMMITTED))
    }
    @Test fun automaticRestartsAreBoundedAndANewUserRequestCanRetry() {
        val budget = BifrostRootRecoveryBudget()
        repeat(3) { assertTrue(budget.claim("request-a", 1000 + it * 1000L)) }
        assertFalse(budget.claim("request-a", 4000))
        assertFalse(budget.claim("request-a", 600_999))
        assertTrue(budget.claim("request-a", 601_000))
        assertTrue(budget.claim("request-b", 601_001))
    }
    @Test fun missingIndependentRuntimeCanReleaseOnlyItsExactLocalOwner() {
        val token = BifrostServiceTransactionToken("a".repeat(32), "b".repeat(32), "c".repeat(64), "[]")
        val other = token.copy(transactionId = "d".repeat(32))
        val state = BifrostServiceTransactionOwnership()
        assertTrue(state.begin(token))
        assertTrue(state.markFenceEstablished(token))
        assertTrue(state.ready(token))
        assertFalse(state.abandonMissingRuntime(other))
        assertEquals(BifrostServiceOwnershipPhase.COMMITTED, state.phase())
        assertTrue(state.abandonMissingRuntime(token))
        assertEquals(BifrostServiceOwnershipPhase.IDLE, state.phase())
        assertFalse(state.hasOwner())
    }
    @Test fun deniedOrRevokedAccountsCannotTriggerAutomaticReconnection() {
        for (code in listOf("BF-ROOT-PERMISSION", "BF-NOT-ENROLLED", "BF-AUTH-003", "BF-CONNECTION-RELEASED"))
            assertFalse(code, BifrostRootConnectionIntent.retryable(IllegalStateException(code)))
        assertTrue(BifrostRootConnectionIntent.retryable(IllegalStateException("BF-ROOT-READBACK")))
    }
}
