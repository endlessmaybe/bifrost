package com.bifrost.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test

/** Executable Activity/Service transaction and ownership lifecycle coverage. */
class BifrostConnectionTransactionTest {
    @Test
    fun preparationRefreshCannotRestartCancelledDispatchedOrReplacedIntent() {
        val gate = BifrostConnectionTransactionGate()
        val first = BifrostConnectionTransactionToken("first", "generation", "digest", "bindings")
        val next = first.copy(transactionId = "next")
        assertFalse(gate.canRefreshPreparation(first))
        assertTrue(gate.begin(first))
        assertTrue(gate.canRefreshPreparation(first))
        assertFalse(gate.canRefreshPreparation(first.copy(bindings = "changed")))
        assertTrue(gate.cancelBeforeServiceDispatch(first))
        assertFalse(gate.canRefreshPreparation(first))
        assertTrue(gate.begin(next))
        assertFalse(gate.canRefreshPreparation(first))
        assertTrue(gate.canRefreshPreparation(next))
        assertTrue(gate.markServiceDispatched(next))
        assertFalse(gate.canRefreshPreparation(next))
        assertTrue(gate.beginDisconnectExact(next))
        assertFalse(gate.canRefreshPreparation(next))
    }
    @Test
    fun cancelAfterDispatchPreservesTheHandoffUntilTheWorkerConfirmsTeardown() {
        val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        val owner = token(generation = snapshot.generation, digest = snapshot.digest)
        val serviceOwner = serviceToken(generation = snapshot.generation, digest = snapshot.digest)
        val gate = BifrostConnectionTransactionGate()
        assertTrue(BifrostApplicationPolicySnapshotRegistry.register(owner.transactionId, snapshot))
        assertTrue(gate.begin(owner))
        assertTrue(gate.markServiceDispatched(owner))
        // The Activity cancels before the Service worker handles its queued Intent.
        assertTrue(gate.beginDisconnectExact(owner))
        BifrostServiceOwnershipRegistry.requestDisconnect(serviceOwner)
        val handedOff = BifrostApplicationPolicySnapshotRegistry.lookup(owner.transactionId)
        assertNotNull(handedOff)
        val ownership = BifrostServiceTransactionOwnership()
        assertTrue(ownership.begin(serviceOwner))
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.PENDING, serviceOwner,
            handedOff!!, BifrostServiceConnectionDescription("sing-box", "global", "A", "auto", "auto", "A-01"))
        assertTrue(BifrostServiceOwnershipRegistry.isDisconnectRequested(serviceOwner))
        val result = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(serviceOwner)
        assertTrue(result.released)
        assertNotNull(result.receipt)
        assertTrue(gate.releaseDisconnectExact(owner))
        assertNull(BifrostApplicationPolicySnapshotRegistry.lookup(owner.transactionId))
        assertTrue(gate.begin(token(id = "e".repeat(32))))
    }

    @Test
    fun cancelDuringLocalPreparationAllowsImmediateReconnectAndRejectsLateCallbacks() {
        val gate = BifrostConnectionTransactionGate()
        repeat(20) { attempt ->
            val old = token(id = attempt.toString(16).padStart(32, '0'))
            assertTrue(gate.begin(old))
            assertTrue(gate.cancelBeforeServiceDispatch(old))
            assertFalse(gate.cancelBeforeServiceDispatch(old))
            assertFalse(gate.markServiceDispatched(old))
            assertEquals(BifrostConnectionAckDecision.Ignored,
                gate.acknowledge(old.transactionId, true, old.digest, old.generation, old.bindings, "BF-SERVICE-ACK"))
        }
        val next = token(id = "f".repeat(32))
        assertTrue(gate.begin(next))
        assertTrue(gate.markServiceDispatched(next))
        assertFalse(gate.cancelBeforeServiceDispatch(next))
        assertTrue(gate.beginDisconnectExact(next))
        assertFalse(gate.begin(token()))
        assertTrue(gate.releaseDisconnectExact(next))
        assertTrue(gate.begin(token()))
    }

    @Test
    fun staleCancellationCannotReleaseANewerLocalOrDispatchedOwner() {
        val gate = BifrostConnectionTransactionGate()
        val old = token()
        val next = token(id = "e".repeat(32))
        assertTrue(gate.begin(old))
        assertTrue(gate.cancelBeforeServiceDispatch(old))
        assertTrue(gate.begin(next))
        assertFalse(gate.cancelBeforeServiceDispatch(old))
        assertFalse(gate.markServiceDispatched(old))
        assertTrue(gate.isActive(next))
        assertTrue(gate.markServiceDispatched(next))
        assertFalse(gate.cancelBeforeServiceDispatch(next.copy(bindings = "wrong")))
        assertFalse(gate.cancelBeforeServiceDispatch(next))
    }

    @After
    fun clearServiceRegistry() {
        val reset = BifrostServiceOwnershipRegistry::class.java.getDeclaredMethod("resetState")
        reset.isAccessible = true
        reset.invoke(BifrostServiceOwnershipRegistry)
        BifrostApplicationPolicySnapshotRegistry.clear()
    }

    private fun token(
        id: String = "a".repeat(32),
        generation: String = "b".repeat(32),
        digest: String = "c".repeat(64),
        bindings: String = "[]",
    ) = BifrostConnectionTransactionToken(id, generation, digest, bindings)

    private fun serviceToken(
        id: String = "a".repeat(32),
        generation: String = "b".repeat(32),
        digest: String = "c".repeat(64),
        bindings: String = "[]",
    ) = BifrostServiceTransactionToken(id, generation, digest, bindings)

    @Test
    fun synchronousStartFailureLeavesNoPendingTransaction() {
        val gate = BifrostConnectionTransactionGate()
        val pending = token()
        assertTrue(gate.begin(pending))
        assertTrue(gate.fail(pending))
        assertEquals(BifrostConnectionTransactionPhase.FAILED, gate.phase())
        assertFalse(gate.isActive(pending))
    }

    @Test
    fun everyFailureAckRequiresGenerationDigestAndBindings() {
        val mismatches = listOf<(BifrostConnectionTransactionToken) -> BifrostConnectionTransactionToken>(
            { it.copy(generation = "d".repeat(32)) },
            { it.copy(digest = "d".repeat(64)) },
            { it.copy(bindings = "[{\"forged\":true}]") },
        )
        mismatches.forEach { mutate ->
            val gate = BifrostConnectionTransactionGate()
            val pending = token()
            val wrong = mutate(pending)
            assertTrue(gate.begin(pending))
            assertEquals(
                BifrostConnectionAckDecision.Ignored,
                gate.acknowledge(
                    pending.transactionId, false, wrong.digest, wrong.generation,
                    wrong.bindings, "BF-APP-PACKAGE-INVALID",
                ),
            )
            assertTrue(gate.isActive(pending))
        }
    }

    @Test
    fun oldFailureDuplicateFailureAndLateSuccessCannotTouchNewTransaction() {
        val gate = BifrostConnectionTransactionGate()
        val old = token()
        val newer = token(id = "d".repeat(32), generation = "e".repeat(32))
        assertTrue(gate.begin(old))
        assertTrue(gate.fail(old))
        assertTrue(gate.begin(newer))
        assertEquals(BifrostConnectionAckDecision.Ignored, gate.acknowledge(
            old.transactionId, false, old.digest, old.generation, old.bindings, "BF-OLD",
        ))
        assertTrue(gate.isActive(newer))
        assertEquals(BifrostConnectionAckDecision.Ignored, gate.acknowledge(
            newer.transactionId, false, "0".repeat(64), newer.generation, newer.bindings, "BF-FAIL",
        ))
        assertTrue(gate.isActive(newer))
        assertEquals(BifrostConnectionAckDecision.Ignored, gate.acknowledge(
            old.transactionId, true, old.digest, old.generation, old.bindings, "BF-OK",
        ))
        assertTrue(gate.isActive(newer))
    }

    @Test
    fun mismatchedSuccessCannotCloseOrCommitTheActiveTransaction() {
        val gate = BifrostConnectionTransactionGate()
        val pending = token()
        assertTrue(gate.begin(pending))
        assertEquals(BifrostConnectionAckDecision.Ignored, gate.acknowledge(
            pending.transactionId, true, pending.digest, "d".repeat(32), pending.bindings, "BF-OK",
        ))
        assertTrue(gate.isActive(pending))
        assertEquals(BifrostConnectionAckDecision.Ignored, gate.acknowledge(
            pending.transactionId, true, pending.digest, pending.generation, "forged", "BF-OK",
        ))
        assertTrue(gate.isActive(pending))
    }

    @Test
    fun blockedFailureRetainsExactTokenUntilExplicitDisconnect() {
        val gate = BifrostConnectionTransactionGate()
        val pending = token()
        assertTrue(gate.begin(pending))
        val decision = gate.acknowledge(
            pending.transactionId, false, pending.digest, pending.generation,
            pending.bindings, "BF-TUN-ESTABLISH", blockedFailure = true,
        )
        assertEquals(BifrostConnectionAckDecision.Failed("BF-TUN-ESTABLISH", false, true, pending), decision)
        assertEquals(pending, gate.blockedToken())
        assertFalse(gate.begin(token(id = "d".repeat(32))))
        assertTrue(gate.beginDisconnectExact(pending))
        assertFalse(gate.releaseDisconnectExact(pending.copy(digest = "d".repeat(64))))
        assertTrue(gate.releaseDisconnectExact(pending))
        assertEquals(BifrostConnectionTransactionPhase.IDLE, gate.phase())
    }

    @Test
    fun readyThenPersistenceFailureCompensatesOnlyMatchingPendingGeneration() {
        val gate = BifrostConnectionTransactionGate()
        val pending = token()
        assertTrue(gate.begin(pending))
        assertTrue(gate.acknowledge(
            pending.transactionId, true, pending.digest, pending.generation, pending.bindings, "BF-OK",
        ) is BifrostConnectionAckDecision.Ready)
        assertTrue(gate.fail(pending))
        assertFalse(gate.cancelExact(token(id = "e".repeat(32), generation = "f".repeat(32))))
    }

    @Test
    fun timeoutCancelLifecycleAndCommittedDisconnectAreExact() {
        val gate = BifrostConnectionTransactionGate()
        val pending = token()
        assertTrue(gate.begin(pending))
        assertTrue(gate.cancelExact(pending))
        assertTrue(gate.begin(pending))
        assertTrue(gate.acknowledge(
            pending.transactionId, true, pending.digest, pending.generation, pending.bindings, "BF-OK",
        ) is BifrostConnectionAckDecision.Ready)
        assertTrue(gate.commit(pending))
        assertFalse(gate.cancelExact(pending))
        assertTrue(gate.beginDisconnectExact(pending))
        assertTrue(gate.releaseDisconnectExact(pending))
        assertEquals(BifrostConnectionTransactionPhase.IDLE, gate.phase())
    }

    @Test
    fun recreatedActivityCanCompleteOnlyAnExactDiscoveredReceipt() {
        val gate = BifrostConnectionTransactionGate()
        val discovered = token()
        assertTrue(gate.completeDiscoveredRelease(discovered))
        assertEquals(BifrostConnectionTransactionPhase.IDLE, gate.phase())
        val newer = token(id = "d".repeat(32), generation = "e".repeat(32))
        assertTrue(gate.begin(newer))
        assertFalse(gate.completeDiscoveredRelease(discovered))
        assertTrue(gate.isActive(newer))
    }

    @Test
    fun serviceOwnershipRetainsBlockedBoundaryAndRejectsMismatchedDisconnect() {
        val ownership = BifrostServiceTransactionOwnership()
        val pending = serviceToken()
        val forged = pending.copy(generation = "d".repeat(32))
        assertTrue(ownership.begin(pending))
        assertEquals(BifrostServiceOwnershipPhase.PENDING, ownership.phase())
        assertEquals(BifrostServiceRuntimeAction.STARTING, ownership.decision().runtimeAction)
        assertEquals(BifrostServiceForegroundAction.PRESERVE, ownership.decision().foregroundAction)
        assertTrue(ownership.markFenceEstablished(pending))
        assertTrue(ownership.failAfterFence(pending))
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        assertEquals(BifrostServiceRuntimeAction.BLOCK, ownership.decision().runtimeAction)
        assertFalse(ownership.decision().stopSelf)
        assertFalse(ownership.beginDisconnect(forged))
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        assertTrue(ownership.beginDisconnect(pending))
        assertTrue(ownership.completeDisconnect(pending))
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
        assertEquals(BifrostServiceRuntimeAction.DISCONNECT, ownership.decision().runtimeAction)
        assertTrue(ownership.decision().stopSelf)
    }

    @Test
    fun serviceOwnershipFreshFailureCanStopAndNewTransactionCanReuseAfterDisconnect() {
        val ownership = BifrostServiceTransactionOwnership()
        val first = serviceToken()
        val second = serviceToken(id = "d".repeat(32), generation = "e".repeat(32))
        assertTrue(ownership.begin(first))
        assertTrue(ownership.failBeforeFence(first))
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
        assertEquals(BifrostServiceForegroundAction.STOP_REMOVE, ownership.decision().foregroundAction)
        assertTrue(ownership.decision().stopSelf)
        assertTrue(ownership.begin(second))
        assertTrue(ownership.markFenceEstablished(second))
        assertTrue(ownership.ready(second))
        assertFalse(ownership.beginDisconnect(first))
        assertTrue(ownership.beginDisconnect(second))
        assertTrue(ownership.completeDisconnect(second))
    }

    @Test
    fun unavailableFenceRetainsExplicitUnprotectedRetryOwner() {
        val ownership = BifrostServiceTransactionOwnership()
        val token = serviceToken()
        assertTrue(ownership.begin(token))
        assertTrue(ownership.markFenceEstablished(token))
        assertTrue(ownership.failFenceUnavailable(token))
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, ownership.phase())
        assertTrue(ownership.hasOwner())
        assertEquals(token, ownership.unprotectedToken())
        assertTrue(ownership.beginDisconnect(token))
        assertTrue(ownership.completeDisconnect(token))
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
    }

    @Test
    fun serviceValidationToctouEstablishAndReadbackFailuresRetainReleaseableBoundary() {
        listOf("BF-APP-PACKAGE-INVALID", "BF-TUN-ESTABLISH", "BF-APP-POLICY-READBACK").forEach { code ->
            val ownership = BifrostServiceTransactionOwnership()
            val pending = serviceToken(id = code.takeLast(32).padStart(32, 'a'))
            assertTrue(ownership.begin(pending))
            assertTrue(ownership.markFenceEstablished(pending))
            assertTrue(ownership.failAfterFence(pending))
            assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
            assertEquals(BifrostServiceRuntimeAction.BLOCK, ownership.decision().runtimeAction)
            assertTrue(ownership.beginDisconnect(pending))
            assertTrue(ownership.completeDisconnect(pending))
            assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
        }
    }

    @Test
    fun freshInvalidAndUnmatchedCommandsStopOnlyFreshServiceWhileDuplicatesPreserveOwner() {
        val fresh = BifrostServiceTransactionOwnership()
        val unknown = serviceToken()
        assertFalse(fresh.beginDisconnect(unknown))
        assertEquals(BifrostServiceForegroundAction.STOP_REMOVE, fresh.decision().foregroundAction)
        assertTrue(fresh.decision().stopSelf)

        val committed = BifrostServiceTransactionOwnership()
        val owner = serviceToken()
        val duplicate = serviceToken(id = "d".repeat(32))
        assertTrue(committed.begin(owner))
        assertTrue(committed.markFenceEstablished(owner))
        assertTrue(committed.ready(owner))
        assertFalse(committed.begin(duplicate))
        assertEquals(BifrostServiceForegroundAction.PRESERVE, committed.decision().foregroundAction)
        assertFalse(committed.beginDisconnect(duplicate))
        assertEquals(BifrostServiceOwnershipPhase.COMMITTED, committed.phase())
    }

    @Test
    fun disconnectHandshakeBlocksNewConnectionUntilExactIdle() {
        val gate = BifrostConnectionTransactionGate()
        val owner = token()
        assertTrue(gate.begin(owner))
        assertTrue(gate.acknowledge(
            owner.transactionId, true, owner.digest, owner.generation, owner.bindings, "BF-OK",
        ) is BifrostConnectionAckDecision.Ready)
        assertTrue(gate.commit(owner))
        assertTrue(gate.beginDisconnectExact(owner))
        assertEquals(BifrostConnectionTransactionPhase.DISCONNECTING, gate.phase())
        assertFalse(gate.begin(token(id = "d".repeat(32))))
        assertFalse(gate.releaseDisconnectExact(owner.copy(digest = "d".repeat(64))))
        assertTrue(gate.releaseDisconnectExact(owner))
        assertEquals(BifrostConnectionTransactionPhase.IDLE, gate.phase())
        assertTrue(gate.begin(token(id = "d".repeat(32))))
    }

    @Test
    fun committedServiceFailureTransitionsToExactBlockedOwner() {
        val ownership = BifrostServiceTransactionOwnership()
        val owner = serviceToken()
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        assertTrue(ownership.runtimeFenceEstablished(owner))
        assertTrue(ownership.failAfterCommit(owner))
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        assertFalse(ownership.failAfterCommit(owner.copy(generation = "d".repeat(32))))
        assertTrue(ownership.beginDisconnect(owner))
        assertTrue(ownership.completeDisconnect(owner))
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
    }

    @Test
    fun gateFailureRemovesExactSnapshotCapabilityOnce() {
        val id = "e".repeat(32)
        val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        BifrostApplicationPolicySnapshotRegistry.remove(id)
        assertTrue(BifrostApplicationPolicySnapshotRegistry.register(id, snapshot))
        val gate = BifrostConnectionTransactionGate()
        val owner = token(id = id, generation = snapshot.generation, digest = snapshot.digest)
        assertTrue(gate.begin(owner))
        assertTrue(gate.fail(owner))
        assertEquals(null, BifrostApplicationPolicySnapshotRegistry.lookup(id))
    }

    private fun serviceSnapshotAndDescription(): Triple<BifrostApplicationPolicySnapshot, BifrostServiceTransactionToken, BifrostServiceConnectionDescription> {
        val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        val owner = serviceToken(generation = snapshot.generation, digest = snapshot.digest)
        val description = BifrostServiceConnectionDescription("sing-box", "global", "A", "auto", "auto", "A-01")
        return Triple(snapshot, owner, description)
    }

    private fun issueRelease(
        token: BifrostServiceTransactionToken,
        snapshot: BifrostApplicationPolicySnapshot,
        description: BifrostServiceConnectionDescription,
        request: Boolean = true,
    ): BifrostServiceReleaseReceipt {
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, token, snapshot, description)
        assertTrue(ownership.begin(token))
        assertTrue(ownership.markFenceEstablished(token))
        assertTrue(ownership.ready(token))
        if (request) BifrostServiceOwnershipRegistry.requestDisconnect(token)
        val result = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(token)
        assertTrue(result.released)
        assertNotNull(result.receipt)
        return result.receipt!!
    }

    private fun resetServiceRegistryForTest() {
        val reset = BifrostServiceOwnershipRegistry::class.java.getDeclaredMethod("resetState")
        reset.isAccessible = true
        reset.invoke(BifrostServiceOwnershipRegistry)
    }

    @Test
    fun productionDisconnectCoordinatorAcknowledgesOnlyAfterSuccessfulTeardown() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val events = mutableListOf<String>()
        val coordinator = BifrostServiceCommandCoordinator(ownership) {
            events += "teardown"
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }
        val result = coordinator.disconnect(owner)
        events += if (result.released) "ack" else "failure"
        assertTrue(result.accepted)
        assertTrue(result.released)
        assertTrue(result.idle)
        assertEquals(listOf("teardown", "ack"), events)
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
        assertNull(BifrostServiceOwnershipRegistry.current())
        assertNotNull(result.receipt)
        assertEquals(result.receipt, BifrostServiceOwnershipRegistry.releaseReceipt(owner))
        val duplicate = coordinator.disconnect(owner)
        assertTrue(duplicate.released)
        assertEquals(result.receipt, duplicate.receipt)
        assertEquals(listOf("teardown", "ack"), events)
    }

    @Test
    fun acknowledgementAndCleanupInjectionFailuresCannotUndoReleaseProof() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val events = mutableListOf<String>()
        val result = BifrostServiceCommandCoordinator(ownership) {
            events += "teardown"
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(
            owner,
            onAcknowledgement = { events += "ack"; throw IllegalStateException("receiver failed") },
            onCleanup = { events += "cleanup"; throw IllegalStateException("notification cleanup failed") },
        )
        assertTrue(result.released)
        assertEquals(listOf("teardown", "ack", "cleanup"), events)
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
        assertNotNull(BifrostServiceOwnershipRegistry.releaseReceipt(owner))
    }

    @Test
    fun disconnectFailureRetainsBlockedExactOwnerAndRetryCannotUseAnotherToken() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        var fail = true
        val coordinator = BifrostServiceCommandCoordinator(ownership) {
            if (fail) BifrostRuntimeDisconnectOutcome(false, true, "BF-CORE-STOP")
            else BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }
        val first = coordinator.disconnect(owner)
        assertFalse(first.released)
        assertTrue(first.blocked)
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, BifrostServiceOwnershipRegistry.current()?.phase)
        val forged = owner.copy(generation = "d".repeat(32))
        assertFalse(coordinator.disconnect(forged).accepted)
        fail = false
        val second = coordinator.disconnect(owner)
        assertTrue(second.released)
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
    }

    @Test
    fun originallyBlockedOwnerWithFalsePhysicalOutcomeBecomesUnprotectedAndRetries() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.BLOCKED_FAILED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.failAfterFence(owner))
        var blockedEvidence = false
        val coordinator = BifrostServiceCommandCoordinator(ownership) {
            if (blockedEvidence) BifrostRuntimeDisconnectOutcome(false, true, "BF-CORE-STOP")
            else BifrostRuntimeDisconnectOutcome(false, false, "BF-BLACKHOLE-UNAVAILABLE")
        }
        val first = coordinator.disconnect(owner)
        assertFalse(first.released)
        assertFalse(first.blocked)
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, ownership.phase())
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, BifrostServiceOwnershipRegistry.current()?.phase)
        blockedEvidence = true
        val retryBlocked = coordinator.disconnect(owner)
        assertFalse(retryBlocked.released)
        assertTrue(retryBlocked.blocked)
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        val released = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(owner)
        assertTrue(released.released)
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
    }

    @Test
    fun originallyBlockedOwnerWithCurrentBlockedEvidenceRemainsBlockedAndRetries() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.BLOCKED_FAILED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.failAfterFence(owner))
        var release = false
        val coordinator = BifrostServiceCommandCoordinator(ownership) {
            if (release) BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
            else BifrostRuntimeDisconnectOutcome(false, true, "BF-CORE-STOP")
        }
        val blockedResult = coordinator.disconnect(owner)
        assertFalse(blockedResult.released)
        assertTrue(blockedResult.blocked)
        assertEquals(BifrostServiceOwnershipPhase.BLOCKED_FAILED, ownership.phase())
        release = true
        val released = coordinator.disconnect(owner)
        assertTrue(released.released)
        assertEquals(BifrostServiceOwnershipPhase.IDLE, ownership.phase())
    }

    @Test
    fun failedBoundaryDoesNotClaimBlockedWhenFenceWasUnavailable() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val result = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(false, false, "BF-BLACKHOLE-UNAVAILABLE")
        }.disconnect(owner)
        assertFalse(result.released)
        assertFalse(result.blocked)
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, ownership.phase())
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, BifrostServiceOwnershipRegistry.current()?.phase)
    }

    @Test
    fun releaseReceiptSurvivesServiceStatusAndRetiresDelayedSameTokenPublish() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val result = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(owner)
        val receipt = result.receipt
        assertNotNull(receipt)
        BifrostServiceOwnershipRegistry.clear()
        val status = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, true, "BF-NOT-USED")
        }.status(owner)
        assertNull(status.live)
        assertEquals(receipt, status.receipt)
        assertTrue(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(owner, receipt!!.epoch))
        var republished = false
        try {
            BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.PENDING, owner, snapshot, description)
            republished = true
        } catch (_: IllegalStateException) {
            // Expected: a delayed original connect cannot resurrect a retired token.
        }
        assertFalse(republished)
    }

    @Test
    fun noOwnerStatusCannotClaimIdleWithoutReceiptAndUnrelatedOwnerIsUntouched() {
        val (_, owner, _) = serviceSnapshotAndDescription()
        val status = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, true, "BF-NOT-USED")
        }.status(owner)
        assertFalse(status.exact)
        val (otherSnapshot, other, otherDescription) = serviceSnapshotAndDescription()
        val otherOwner = other.copy(transactionId = "d".repeat(32))
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, otherOwner, otherSnapshot, otherDescription)
        val unrelated = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, true, "BF-NOT-USED")
        }.status(owner)
        assertFalse(unrelated.exact)
        assertEquals(otherOwner, BifrostServiceOwnershipRegistry.current()?.token)
    }

    @Test
    fun readyMetadataRequiresEveryFieldAndRejectsEachMutation() {
        val expected = BifrostServiceConnectionDescription("sing-box", "global", "A", "auto", "auto", "A-01")
        assertTrue(BifrostServiceConnectionMetadata.complete(expected, BifrostServiceConnectionMetadata.REQUIRED_FIELDS))
        BifrostServiceConnectionMetadata.REQUIRED_FIELDS.forEach { missing ->
            assertFalse(BifrostServiceConnectionMetadata.complete(expected, BifrostServiceConnectionMetadata.REQUIRED_FIELDS - missing))
        }
        val mutations = listOf(
            expected.copy(core = "xray"),
            expected.copy(mode = "per-app"),
            expected.copy(source = "B"),
            expected.copy(country = "CN"),
            expected.copy(frontSource = "B"),
            expected.copy(candidate = "A-02"),
        )
        mutations.forEach { actual ->
            assertTrue(BifrostServiceConnectionMetadata.complete(actual, BifrostServiceConnectionMetadata.REQUIRED_FIELDS))
            assertFalse(BifrostServiceConnectionMetadata.matches(expected, actual))
        }
        assertTrue(BifrostServiceConnectionMetadata.matches(expected, expected))
    }

    @Test
    fun unrelatedStatusNeverAuthorizesForegroundCleanupForAnyLivePhase() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val unrelated = owner.copy(transactionId = "d".repeat(32))
        val coordinator = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, false, "BF-NOT-USED")
        }
        listOf(
            BifrostServiceOwnershipPhase.PENDING,
            BifrostServiceOwnershipPhase.COMMITTED,
            BifrostServiceOwnershipPhase.BLOCKED_FAILED,
            BifrostServiceOwnershipPhase.DISCONNECTING,
        ).forEach { phase ->
            BifrostServiceOwnershipRegistry.publish(phase, owner, snapshot, description)
            val status = coordinator.status(unrelated)
            assertFalse(status.exact)
            assertEquals(owner, status.globalOwner?.token)
            assertEquals(owner, status.live?.token)
            assertNull(status.exactLive)
            assertFalse(status.cleanupOwnService)
            BifrostServiceOwnershipRegistry.clearExactInternal(owner)
        }
    }

    @Test
    fun ownerlessStatusIsTheOnlyStatusThatMayCleanUpItsServiceInstance() {
        val (_, owner, _) = serviceSnapshotAndDescription()
        val status = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, false, "BF-NOT-USED")
        }.status(owner)
        assertFalse(status.exact)
        assertNull(status.globalOwner)
        assertTrue(status.cleanupOwnService)
    }

    @Test
    fun exactReceiptDoesNotCleanUpAReplacementOwner() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val first = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(owner)
        assertTrue(first.released)
        val replacement = owner.copy(transactionId = "d".repeat(32))
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, replacement, snapshot, description)
        val status = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, false, "BF-NOT-USED")
        }.status(owner)
        assertEquals(first.receipt, status.receipt)
        assertEquals(replacement, status.globalOwner?.token)
        assertTrue(status.exact)
        assertFalse(status.cleanupOwnService)
        var cleanup = 0
        val duplicate = BifrostServiceCommandCoordinator(BifrostServiceTransactionOwnership()) {
            BifrostRuntimeDisconnectOutcome(false, false, "BF-NOT-USED")
        }.disconnect(owner, onAcknowledgement = {}, onCleanup = { cleanup++ })
        assertTrue(duplicate.released)
        assertFalse(duplicate.cleanupOwnService)
        assertEquals(0, cleanup)
        assertEquals(replacement, BifrostServiceOwnershipRegistry.current()?.token)
    }

    @Test
    fun receiptIssuanceRequiresExactDisconnectingOwnerAndDuplicateIsIdempotent() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        assertNull(BifrostServiceOwnershipRegistry.noteReleased(owner))
        val other = owner.copy(transactionId = "d".repeat(32))
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, other, snapshot, description)
        assertNull(BifrostServiceOwnershipRegistry.noteReleased(owner))
        assertNull(BifrostServiceOwnershipRegistry.noteReleased(other))
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.DISCONNECTING, other, snapshot, description)
        assertNull(BifrostServiceOwnershipRegistry.noteReleased(other))
        val receipt = BifrostServiceOwnershipRegistry.noteReleasedExact(other)
        assertNotNull(receipt)
        assertEquals(receipt, BifrostServiceOwnershipRegistry.noteReleasedExact(other))
        assertEquals(1L, receipt!!.epoch)
    }

    @Test
    fun releaseDiscoverySurvivesRecreationUntilExactConsumptionOnly() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.DISCONNECTING, owner, snapshot, description)
        BifrostServiceOwnershipRegistry.requestDisconnect(owner)
        val receipt = BifrostServiceOwnershipRegistry.noteReleasedExact(owner)
        assertNotNull(receipt)
        assertEquals(owner, BifrostServiceOwnershipRegistry.releaseDiscoveryToken(owner))
        val wrong = owner.copy(transactionId = "d".repeat(32))
        assertFalse(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(wrong, receipt!!.epoch))
        assertTrue(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(owner, receipt.epoch))
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(owner))
        assertNull(BifrostServiceOwnershipRegistry.requestedDisconnect())
        assertFalse(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(owner, receipt.epoch))
    }

    @Test
    fun receiptWithoutActivityRequestHasNoDiscoveryAuthority() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.DISCONNECTING, owner, snapshot, description)
        assertNotNull(BifrostServiceOwnershipRegistry.noteReleasedExact(owner))
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscovery())
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken())
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(owner))
        assertNull(BifrostServiceOwnershipRegistry.requestedDisconnectFor(owner))
    }

    @Test
    fun exactRequestCannotDiscoverAnotherReceiptWhenThatReceiptIsOlder() {
        val (snapshot, seed, description) = serviceSnapshotAndDescription()
        val older = seed.copy(transactionId = "1".repeat(32))
        val requested = seed.copy(transactionId = "2".repeat(32))
        BifrostServiceOwnershipRegistry.requestDisconnect(older)
        issueRelease(older, snapshot, description)
        BifrostServiceOwnershipRegistry.requestDisconnect(requested)
        issueRelease(requested, snapshot, description)
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscovery())
        assertEquals(requested, BifrostServiceOwnershipRegistry.releaseDiscoveryToken(requested))
        assertEquals(older, BifrostServiceOwnershipRegistry.releaseDiscoveryToken(older))
        val forged = requested.copy(transactionId = older.transactionId, bindings = "[forged]")
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(forged))
    }

    @Test
    fun independentReceiptsConsumeInEitherOrderAndDuplicateCannotStrandTheOther() {
        listOf(listOf(1, 0), listOf(0, 1)).forEach { order ->
            resetServiceRegistryForTest()
            val (snapshot, seed, description) = serviceSnapshotAndDescription()
            val first = seed.copy(transactionId = "3".repeat(32))
            val second = seed.copy(transactionId = "4".repeat(32))
            val firstReceipt = issueRelease(first, snapshot, description)
            val secondReceipt = issueRelease(second, snapshot, description)
            val tokens = listOf(first to firstReceipt, second to secondReceipt)
            val consumed = mutableSetOf<Int>()
            order.forEach { index ->
                val (token, receipt) = tokens[index]
                assertTrue(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(token, receipt.epoch))
                assertFalse(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(token, receipt.epoch))
                consumed += index
                val other = tokens[1 - index]
                if (1 - index !in consumed) {
                    assertEquals(other.first, BifrostServiceOwnershipRegistry.releaseDiscoveryToken(other.first))
                } else {
                    assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(other.first))
                }
            }
            assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(first))
            assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(second))
        }
    }

    @Test
    fun receiptEvictionRemovesItsActivityRequestAndCannotBeRediscovered() {
        val (snapshot, seed, description) = serviceSnapshotAndDescription()
        val issued = (0..8).map { index ->
            val token = seed.copy(transactionId = index.toString(16).padStart(32, '0'))
            issueRelease(token, snapshot, description)
            token
        }
        assertNull(BifrostServiceOwnershipRegistry.releaseDiscoveryToken(issued.first()))
        assertEquals(issued.last(), BifrostServiceOwnershipRegistry.releaseDiscoveryToken(issued.last()))
        assertTrue(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(issued.last(), 9L))
        assertFalse(BifrostServiceOwnershipRegistry.consumeReleaseReceipt(issued.last(), 9L))
    }

    @Test
    fun publicResetCannotEraseAServiceOwnerOrReleaseEpoch() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        BifrostServiceOwnershipRegistry.reset()
        assertEquals(owner, BifrostServiceOwnershipRegistry.current()?.token)
        assertEquals(BifrostServiceOwnershipPhase.COMMITTED, BifrostServiceOwnershipRegistry.current()?.phase)
    }

    @Test
    fun boundedRetiredHistoryRejectsDelayedTokenAfterReceiptWindowRolls() {
        val (snapshot, seed, description) = serviceSnapshotAndDescription()
        val issued = (0..64).map { index ->
            seed.copy(transactionId = index.toString(16).padStart(32, '0'))
        }
        issued.forEach { token ->
            BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.DISCONNECTING, token, snapshot, description)
            assertNotNull(BifrostServiceOwnershipRegistry.noteReleasedExact(token))
        }
        var resurrected = false
        try {
            BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.PENDING, issued.first(), snapshot, description)
            resurrected = true
        } catch (_: IllegalStateException) {
            // The bounded Bloom history rejects delayed retired tokens even
            // after the receipt/epoch map has rotated older entries out.
        }
        assertFalse(resurrected)
    }

    @Test
    fun unexpectedRuntimeThrowableRetainsExactUnprotectedOwnerWithoutBlockedClaim() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        assertTrue(ownership.ready(owner))
        val result = BifrostServiceCommandCoordinator(ownership) {
            throw IllegalStateException("before boundary proof")
        }.disconnect(owner)
        assertFalse(result.released)
        assertFalse(result.blocked)
        assertTrue(result.accepted)
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, ownership.phase())
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, BifrostServiceOwnershipRegistry.current()?.phase)
        assertEquals(owner, BifrostServiceOwnershipRegistry.current()?.token)
    }

    @Test
    fun postCoreReadyFailureRetainsUnprotectedOwnerAndExactRetryCanRelease() {
        val (snapshot, owner, description) = serviceSnapshotAndDescription()
        val ownership = BifrostServiceTransactionOwnership()
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.PENDING, owner, snapshot, description)
        assertTrue(ownership.begin(owner))
        assertTrue(ownership.markFenceEstablished(owner))
        val failure = BifrostServiceFailureCoordinator(ownership).apply(
            owner,
            BifrostRuntimeCoreFailureOutcome(blocked = false, teardownConfirmed = false, code = "BF-CORE-STOP-UNCONFIRMED"),
        )
        assertTrue(failure.retained)
        assertTrue(failure.unprotected)
        assertEquals(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, failure.phase)
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.UNPROTECTED_FAILED, owner, snapshot, description)
        val retry = BifrostServiceCommandCoordinator(ownership) {
            BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
        }.disconnect(owner)
        assertTrue(retry.released)
        assertNull(BifrostServiceOwnershipRegistry.current())
    }
}
