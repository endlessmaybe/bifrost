package com.bifrost.client

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostCandidateProbeCoordinatorTest {
    @Test
    fun connectionAfterCompletedProbeKeepsPreflightGeneration() {
        val scheduler = ManualProbeScheduler()
        val delivered = mutableListOf<BifrostProbeCoordinatorResult>()
        val value = input("A")
        val coordinator = lifecycle(scheduler, load = { value },
            probe = { _, _, _, _ -> "A-01" }, publish = { delivered += it })
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        val expected = coordinator.captureConnectionGeneration(value)
        coordinator.acquireLease("connection:tx", "A")
        coordinator.refreshNow("A", forceTransition = false)
        scheduler.advanceBy(0)
        assertEquals(2, delivered.size)
        assertEquals(expected, delivered.last().key.generation)
        coordinator.close()
    }

    @Test
    fun loadFailureRetainsItsDiagnosticInsteadOfPretendingConfigIsMissing() {
        val scheduler = ManualProbeScheduler()
        var failure: Throwable? = null
        val expected = IllegalStateException("BF-CONFIG-CACHE-CORRUPT")
        val coordinator = lifecycle(scheduler, load = { throw expected },
            probe = { _, _, _, _ -> "never" }, unavailable = { _, error -> failure = error })
        coordinator.acquireLease("connection:tx", "A")
        scheduler.advanceBy(0)
        assertTrue(failure === expected)
        coordinator.close()
    }

    @Test
    fun activityAndServiceLeasesCoalesceSameImmediateKey() {
        val scheduler = ManualProbeScheduler()
        val published = mutableListOf<String>()
        val probes = AtomicInteger(0)
        val coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { input, _, _, _ ->
                probes.incrementAndGet()
                "${input.source}-01"
            },
            publish = { if (it.label != null) published += it.label },
        )
        coordinator.acquireLease("activity", "A")
        coordinator.acquireLease("service", "A")
        coordinator.acquireLease("connection:tx", "A")
        scheduler.advanceBy(0)
        assertEquals(1, probes.get())
        assertEquals(listOf("A-01"), published)
        coordinator.close()
    }

    @Test
    fun serviceLeaseKeepsCadenceAfterActivityStopsAndAllLeasesCancelWork() {
        val scheduler = ManualProbeScheduler()
        val probes = AtomicInteger(0)
        val coordinator = lifecycle(
            scheduler,
            cadenceMs = 7_200_000,
            load = { input("A") },
            probe = { _, _, _, _ -> probes.incrementAndGet(); "A-01" },
        )
        val activity = coordinator.acquireLease("activity", "A")
        val service = coordinator.acquireLease("service:tx", "A")
        scheduler.advanceBy(0)
        assertEquals(1, probes.get())
        activity.close()
        scheduler.advanceBy(7_200_000)
        assertEquals(2, probes.get())
        service.close()
        assertFalse(coordinator.hasDemand())
        val blank = coordinator.acquireLease("activity-recreated", null)
        scheduler.advanceBy(0)
        assertEquals(2, probes.get())
        blank.close()
        coordinator.networkChanged()
        scheduler.advanceBy(1_500)
        assertEquals(2, probes.get())
        coordinator.close()
    }

    @Test
    fun networkDebounceRequiresQuietWindowAndCadenceRequiresDemand() {
        val scheduler = ManualProbeScheduler()
        val probes = AtomicInteger(0)
        val coordinator = lifecycle(
            scheduler,
            debounceMs = 1_500,
            cadenceMs = 7_200_000,
            load = { input("A", network = "net-${probes.get()}") },
            probe = { _, _, _, _ -> probes.incrementAndGet(); "A-01" },
        )
        val lease = coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        assertEquals(1, probes.get())
        coordinator.networkChanged()
        scheduler.advanceBy(1_499)
        assertEquals(1, probes.get())
        scheduler.advanceBy(1)
        assertEquals(2, probes.get())
        scheduler.advanceBy(7_199_999)
        assertEquals(2, probes.get())
        scheduler.advanceBy(1)
        assertEquals(3, probes.get())
        lease.close()
        scheduler.advanceBy(7_200_000)
        assertEquals(3, probes.get())
    }

    @Test
    fun networkQuietWindowCannotBeBypassedByAnAlreadyScheduledCadence() {
        val scheduler = ManualProbeScheduler()
        val probes = AtomicInteger(0)
        val coordinator = lifecycle(
            scheduler,
            debounceMs = 1_500,
            cadenceMs = 1_000,
            load = { input("A", network = "net-${probes.get()}") },
            probe = { _, _, _, _ -> probes.incrementAndGet(); "A-01" },
        )
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        coordinator.networkChanged()
        scheduler.advanceBy(1_000)
        assertEquals(1, probes.get())
        scheduler.advanceBy(499)
        assertEquals(1, probes.get())
        scheduler.advanceBy(1)
        assertEquals(2, probes.get())
        coordinator.close()
    }

    @Test
    fun synchronousNetworkInvalidationCancelsBlockedProbeBeforeRelease() {
        val scheduler = ManualProbeScheduler()
        val started = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val release = CountDownLatch(1)
        val published = AtomicInteger(0)
        val writes = AtomicInteger(0)
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        var activeKey: BifrostProbeRoundKey? = null
        coordinator = lifecycle(
            scheduler,
            load = { input("A") },
            probe = { _, key, cancellation, isCurrent ->
                activeKey = key
                started.countDown()
                while (!cancellation.isCancelled()) {
                    Thread.yield()
                }
                cancelled.countDown()
                release.await(2, TimeUnit.SECONDS)
                assertFalse(isCurrent())
                "A-01"
            },
            publish = { published.incrementAndGet() },
        )
        coordinator.acquireLease("activity", "A")
        val probeThread = Thread { scheduler.advanceBy(0) }.apply { start() }
        assertTrue(started.await(1, TimeUnit.SECONDS))
        val networkThread = Thread { coordinator.networkChanged() }.apply { start() }
        assertTrue(cancelled.await(1, TimeUnit.SECONDS))
        assertFalse(coordinator.commitIfCurrent(activeKey!!, ProbeCancellation()) { writes.incrementAndGet() })
        release.countDown()
        networkThread.join(1_000)
        probeThread.join(1_000)
        assertEquals(0, published.get())
        assertEquals(0, writes.get())
        coordinator.close()
    }

    @Test
    fun eachListenerAdmissionIsFencedAfterAnEarlierListenerTransitions() {
        val admission = BifrostProbeDeliveryAdmission(key("A", "net-a", 1, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1))
        val first = BifrostProbeListenerRegistration(listener = { admission.invalidate() })
        val secondCalls = AtomicInteger(0)
        val second = BifrostProbeListenerRegistration(listener = { secondCalls.incrementAndGet() })
        assertTrue(admission.deliver { first.dispatch(result()) })
        assertFalse(admission.deliver { second.dispatch(result()) })
        assertEquals(0, secondCalls.get())
        first.close()
        second.close()
    }

    @Test
    fun unavailableFailureAdmissionCannotCompleteAfterAuthorityTransition() {
        val admission = BifrostProbeFailureAdmission("A", 1L)
        admission.invalidate()
        val delivered = AtomicInteger(0)
        assertFalse(admission.isActiveForTest())
        assertFalse(admission.deliver { delivered.incrementAndGet() })
        assertEquals(0, delivered.get())
    }

    @Test
    fun failureCallbackCanReenterEveryTransitionWithoutAnAdmissionLifecycleDeadlock() {
        val transitions = listOf<((BifrostProbeLifecycleCoordinator) -> Unit)>(
            { it.updateSource("B") },
            { it.refreshNow("A") },
            { it.networkChanged() },
            { it.close() },
        )
        transitions.forEach { transition ->
            val scheduler = ManualProbeScheduler()
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val transitionDone = CountDownLatch(1)
            lateinit var coordinator: BifrostProbeLifecycleCoordinator
            coordinator = lifecycle(
                scheduler,
                load = { null },
                probe = { _, _, _, _ -> "never" },
                unavailableAdmitted = { _, _, admission ->
                    admission.deliver {
                        entered.countDown()
                        assertTrue(release.await(2, TimeUnit.SECONDS))
                        // Re-entry is deliberately on the consumer thread.
                        coordinator.hasDemand()
                    }
                },
            )
            coordinator.acquireLease("activity", "A")
            val run = Thread { scheduler.advanceBy(0) }.apply { start() }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val transitionThread = Thread { transition(coordinator); transitionDone.countDown() }.apply { start() }
            release.countDown()
            assertTrue(transitionDone.await(1, TimeUnit.SECONDS))
            run.join(1_000)
            transitionThread.join(1_000)
            coordinator.close()
        }
    }

    @Test
    fun observerOwnerRollsBackNullAndThrowAndClosesExactlyOnce() {
        val nullOwner = BifrostNetworkObserverOwner { null }
        try { nullOwner.acquire {} ; throw AssertionError("null observer accepted") }
        catch (_: IllegalStateException) { }
        assertEquals(0, nullOwner.demandCountForTest())
        assertFalse(nullOwner.hasObserverForTest())
        var closeCount = 0
        val throwingOwner = BifrostNetworkObserverOwner { error("TEST-ONLY observer failure") }
        try { throwingOwner.acquire {} ; throw AssertionError("throwing observer accepted") }
        catch (_: IllegalStateException) { }
        assertEquals(0, throwingOwner.demandCountForTest())
        val owner = BifrostNetworkObserverOwner {
            Closeable { closeCount += 1 }
        }
        val lease = owner.acquire {}
        assertEquals(1, owner.demandCountForTest())
        lease.close(); lease.close()
        assertEquals(1, closeCount)
        owner.close(); owner.close()
        assertEquals(1, closeCount)
    }

    @Test
    fun observerOwnerConcurrentAcquisitionInstallsOneCallbackAndCloseSuppressesEvents() {
        val installs = AtomicInteger(0)
        val closes = AtomicInteger(0)
        val callbacks = AtomicInteger(0)
        var observedCallback: (() -> Unit)? = null
        val owner = BifrostNetworkObserverOwner { callback ->
            installs.incrementAndGet()
            observedCallback = callback
            Closeable { closes.incrementAndGet() }
        }
        val leases = java.util.Collections.synchronizedList(mutableListOf<Closeable>())
        val threads = (0 until 8).map {
            Thread { leases += owner.acquire { callbacks.incrementAndGet() } }.apply { start() }
        }
        threads.forEach { it.join(1_000) }
        assertEquals(1, installs.get())
        assertEquals(8, owner.demandCountForTest())
        leases.forEach { it.close() }
        assertEquals(1, closes.get())
        owner.close()
        assertEquals(1, closes.get())
        observedCallback?.invoke()
        assertEquals(0, callbacks.get())
    }

    @Test
    fun lastLeaseReleaseInvalidatesAnUnavailabilityAdmissionBeforeDelivery() {
        val scheduler = ManualProbeScheduler()
        var captured: BifrostProbeFailureAdmission? = null
        val coordinator = lifecycle(
            scheduler,
            load = { null },
            probe = { _, _, _, _ -> "never" },
            unavailableAdmitted = { _, _, admission -> captured = admission },
        )
        val lease = coordinator.acquireLease("connection", "A")
        scheduler.advanceBy(0)
        val admission = captured ?: throw AssertionError("failure admission missing")
        lease.close()
        assertFalse(admission.deliver { throw AssertionError("late failure delivered after final release") })
        coordinator.close()
    }

    @Test
    fun eachRoundLoadsLatestConfigAndKeyChangesForGraphFields() {
        val scheduler = ManualProbeScheduler()
        var version = 1L
        var digest = "a".repeat(64)
        var candidate = "b".repeat(64)
        var transport = "c".repeat(64)
        val keys = mutableListOf<BifrostProbeRoundKey>()
        val coordinator = lifecycle(
            scheduler,
            load = { input("A", version = version, digest = digest, candidate = candidate, transport = transport) },
            probe = { _, key, _, _ -> keys += key; "A-01" },
        )
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        version = 2L
        digest = "d".repeat(64)
        coordinator.refreshNow("A")
        scheduler.advanceBy(0)
        candidate = "e".repeat(64)
        coordinator.refreshNow("A")
        scheduler.advanceBy(0)
        transport = "f".repeat(64)
        coordinator.refreshNow("A")
        scheduler.advanceBy(0)
        assertEquals(listOf(1L, 2L, 2L, 2L), keys.map { it.configVersion })
        assertEquals(4, keys.map { it.cacheKey() }.toSet().size)
    }

    @Test
    fun verifiedRefreshRetiresBlockedOldRoundBeforeItCanCommitOrPublish() {
        val scheduler = ManualProbeScheduler()
        val started = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val release = CountDownLatch(1)
        val oldWrites = AtomicInteger(0)
        val newWrites = AtomicInteger(0)
        val oldPublished = AtomicInteger(0)
        val newPublished = AtomicInteger(0)
        var version = 1L
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        coordinator = lifecycle(
            scheduler,
            load = { input("A", version = version, digest = if (version == 1L) "a".repeat(64) else "d".repeat(64)) },
            probe = { input, key, cancellation, isCurrent ->
                if (input.configVersion == 1L) {
                    started.countDown()
                    while (!cancellation.isCancelled()) Thread.yield()
                    cancelled.countDown()
                    release.await(2, TimeUnit.SECONDS)
                    assertFalse(isCurrent())
                    assertFalse(coordinator.commitIfCurrent(key, cancellation) { oldWrites.incrementAndGet() })
                } else {
                    assertTrue(coordinator.commitIfCurrent(key, cancellation) { newWrites.incrementAndGet() })
                }
                "A-01"
            },
            publish = { result ->
                if (result.key.configVersion == 1L) oldPublished.incrementAndGet()
                if (result.key.configVersion == 2L) newPublished.incrementAndGet()
            },
        )
        coordinator.acquireLease("activity", "A")
        val oldRound = Thread { scheduler.advanceBy(0) }.apply { start() }
        assertTrue(started.await(1, TimeUnit.SECONDS))
        version = 2L
        coordinator.refreshNow("A")
        assertTrue(cancelled.await(1, TimeUnit.SECONDS))
        release.countDown()
        oldRound.join(2_000)
        assertEquals(0, oldWrites.get())
        assertEquals(0, oldPublished.get())
        scheduler.advanceBy(0)
        assertEquals(1, newWrites.get())
        assertEquals(1, newPublished.get())
        coordinator.close()
    }

    @Test
    fun staleAbaRoundCannotPublishAfterSourceChanges() {
        val scheduler = ManualProbeScheduler()
        val published = mutableListOf<String>()
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        var firstA = true
        coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { input, _, _, isCurrent ->
                if (input.source == "A" && firstA) {
                    firstA = false
                    coordinator.updateSource("B")
                    assertFalse(isCurrent())
                }
                "${input.source}-01"
            },
            publish = { if (it.label != null) published += it.label },
        )
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        scheduler.advanceBy(0)
        coordinator.updateSource("A")
        scheduler.advanceBy(0)
        assertEquals(listOf("B-01", "A-01"), published)
    }

    @Test
    fun staleAbaRoundWithTheSameKeyCannotUseAReplacementGeneration() {
        val scheduler = ManualProbeScheduler()
        val writes = AtomicInteger(0)
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        var first = true
        coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { input, key, cancellation, isCurrent ->
                if (first) {
                    first = false
                    coordinator.updateSource("B")
                    coordinator.updateSource("A")
                    assertFalse(isCurrent())
                    assertFalse(coordinator.commitIfCurrent(key, cancellation) { writes.incrementAndGet() })
                }
                "${input.source}-01"
            },
        )
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        assertEquals(0, writes.get())
        coordinator.close()
    }

    @Test
    fun transitionAfterComputationInvalidatesDeliveryBeforeCallback() {
        val scheduler = ManualProbeScheduler()
        val computed = CountDownLatch(1)
        val release = CountDownLatch(1)
        val delivered = AtomicInteger(0)
        val published = AtomicInteger(0)
        val coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { _, _, _, _ -> "A-01" },
            beforePublish = {
                computed.countDown()
                assertTrue(release.await(2, TimeUnit.SECONDS))
            },
            publish = { result ->
                published.incrementAndGet()
                if (result.delivery?.deliver { delivered.incrementAndGet() } == true) Unit
            },
        )
        coordinator.acquireLease("activity", "A")
        val round = Thread { scheduler.advanceBy(0) }.apply { start() }
        assertTrue(computed.await(1, TimeUnit.SECONDS))
        coordinator.networkChanged()
        release.countDown()
        round.join(2_000)
        assertEquals(1, published.get())
        assertEquals(0, delivered.get())
        coordinator.close()
    }

    @Test
    fun oldDeliveryCannotCompleteANewSameSourceConnectionRequest() {
        val oldKey = key("A", "net-a", 1, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1)
        val newKey = key("A", "net-b", 1, "a".repeat(64), "b".repeat(64), "c".repeat(64), 2)
        val callbacks = AtomicInteger(0)
        val request = BifrostConnectionProbeRequest(
            callback = { callbacks.incrementAndGet() },
            expectedBinding = BifrostProbeConnectionBinding.from(input("A", network = "net-b"), 2),
        )
        val oldResult = BifrostProbeCoordinatorResult("A", oldKey, "A-01", null)
        assertFalse(request.completeFromProbe(oldResult))
        assertEquals(0, callbacks.get())
        val newResult = BifrostProbeCoordinatorResult("A", newKey, "A-02", null)
        assertTrue(request.completeFromProbe(newResult))
        assertEquals(1, callbacks.get())
    }

    @Test
    fun selectionReceiptBindsEveryConnectionFieldAndRejectsNetworkOrConfigMutation() {
        val binding = BifrostProbeConnectionBinding.from(input("A", network = "net-a", version = 1L), 1L)
        val receipt = BifrostCandidateSelectionReceipt("A-01", binding)
        assertTrue(receipt.matches(input("A", network = "net-a", version = 1L), 1L))
        assertFalse(receipt.matches(input("A", network = "net-b", version = 1L), 1L))
        assertFalse(receipt.matches(input("A", network = "net-a", version = 2L, digest = "d".repeat(64)), 1L))
        assertFalse(receipt.matches(input("A", network = "net-a", version = 1L), 2L))
    }

    @Test
    fun blockingDeliveryDoesNotHoldLifecycleGateAndInterruptedCloseWaits() {
        val scheduler = ManualProbeScheduler()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val transitionDone = CountDownLatch(1)
        val coordinator = lifecycle(
            scheduler,
            load = { input("A") },
            probe = { _, _, _, _ -> "A-01" },
            publish = { result ->
                result.delivery?.deliver {
                    entered.countDown()
                    assertTrue(release.await(2, TimeUnit.SECONDS))
                }
            },
        )
        coordinator.acquireLease("activity", "A")
        val round = Thread { scheduler.advanceBy(0) }.apply { start() }
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        Thread { coordinator.updateSource("B"); transitionDone.countDown() }.start()
        // updateSource has released lifecycle.gate before the admission fence
        // is retired; it must complete even while the already-admitted
        // consumer is blocked.
        assertTrue(coordinator.hasDemand())
        assertTrue(transitionDone.await(1, TimeUnit.SECONDS))
        release.countDown()
        round.join(2_000)
        coordinator.close()
    }

    @Test
    fun interruptedListenerCloseWaitsUntilDispatchCompletesAndRestoresInterrupt() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val interruptedAfterFence = AtomicInteger(0)
        val registration = BifrostProbeListenerRegistration(listener = {
            entered.countDown()
            assertTrue(release.await(2, TimeUnit.SECONDS))
        })
        val dispatch = Thread { registration.dispatch(result()) }.apply { start() }
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        val closer = Thread {
            registration.close()
            if (Thread.currentThread().isInterrupted) interruptedAfterFence.incrementAndGet()
            returned.countDown()
        }.apply { start() }
        closer.interrupt()
        assertFalse(returned.await(100, TimeUnit.MILLISECONDS))
        release.countDown()
        assertTrue(returned.await(1, TimeUnit.SECONDS))
        dispatch.join(1_000)
        closer.join(1_000)
        assertEquals(1, interruptedAfterFence.get())
        registration.dispatch(result())
    }

    @Test
    fun nestedSameThreadDispatchKeepsDepthAndSelfCloseFencesFutureCallbacks() {
        val callbacks = AtomicInteger(0)
        lateinit var registration: BifrostProbeListenerRegistration
        registration = BifrostProbeListenerRegistration(listener = {
            if (callbacks.incrementAndGet() == 1) {
                registration.dispatch(result())
                registration.close()
            }
        })
        registration.dispatch(result())
        registration.dispatch(result())
        assertEquals(2, callbacks.get())
    }

    @Test
    fun finalPrecommitLatchSuppressesLateWriteWhenCurrentKeyChanges() {
        val scheduler = ManualProbeScheduler()
        val published = mutableListOf<String>()
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { input, _, _, isCurrent ->
                coordinator.networkChanged()
                assertFalse(isCurrent())
                "${input.source}-01"
            },
            publish = { if (it.label != null) published += it.label },
        )
        coordinator.acquireLease("activity", "A")
        scheduler.advanceBy(0)
        assertTrue(published.isEmpty())
    }

    @Test
    fun atomicCommitPermitBlocksTransitionUntilTheCompleteWriteFinishes() {
        val scheduler = ManualProbeScheduler()
        val commitEntered = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val transitionStarted = CountDownLatch(1)
        val transitionDone = CountDownLatch(1)
        val writes = AtomicInteger(0)
        lateinit var coordinator: BifrostProbeLifecycleCoordinator
        coordinator = lifecycle(
            scheduler,
            load = { source -> input(source) },
            probe = { input, key, cancellation, _ ->
                if (input.source == "A") {
                    assertTrue(coordinator.commitIfCurrent(key, cancellation) {
                        commitEntered.countDown()
                        assertTrue(releaseCommit.await(2, TimeUnit.SECONDS))
                        writes.incrementAndGet()
                    })
                }
                "A-01"
            },
        )
        coordinator.acquireLease("activity", "A")
        val probeThread = Thread { scheduler.advanceBy(0) }.apply { start() }
        assertTrue(commitEntered.await(1, TimeUnit.SECONDS))
        val transitionThread = Thread {
            transitionStarted.countDown()
            coordinator.updateSource("B")
            transitionDone.countDown()
        }.apply { start() }
        assertTrue(transitionStarted.await(1, TimeUnit.SECONDS))
        assertFalse(transitionDone.await(100, TimeUnit.MILLISECONDS))
        releaseCommit.countDown()
        probeThread.join(2_000)
        assertTrue(transitionDone.await(1, TimeUnit.SECONDS))
        transitionThread.join(1_000)
        assertEquals(1, writes.get())
        coordinator.close()
    }

    @Test
    fun missingConfigNotifiesAnEphemeralDemandInsteadOfWaitingForCadence() {
        val scheduler = ManualProbeScheduler()
        val unavailable = CountDownLatch(1)
        var unavailableSource = ""
        var unavailableCode = ""
        val coordinator = lifecycle(
            scheduler,
            cadenceMs = 7_200_000,
            load = { null },
            probe = { _, _, _, _ -> "never" },
            unavailable = { source, error ->
                unavailableSource = source
                unavailableCode = error.message.orEmpty()
                unavailable.countDown()
            },
        )
        coordinator.acquireLease("connection:tx", "A")
        scheduler.advanceBy(0)
        assertTrue(unavailable.await(1, TimeUnit.SECONDS))
        assertEquals("A", unavailableSource)
        assertEquals("BF-CONFIG-CACHE-MISSING", unavailableCode)
        coordinator.close()
    }

    @Test
    fun listenerCloseJoinsAnInFlightDispatchAndSuppressesLateCallbacks() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closeReturned = CountDownLatch(1)
        val callbacks = AtomicInteger(0)
        val registration = BifrostProbeListenerRegistration(listener = {
            entered.countDown()
            assertTrue(release.await(2, TimeUnit.SECONDS))
            callbacks.incrementAndGet()
        })
        val dispatchThread = Thread { registration.dispatch(result()) }.apply { start() }
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        val closeThread = Thread {
            registration.close()
            closeReturned.countDown()
        }.apply { start() }
        assertFalse(closeReturned.await(100, TimeUnit.MILLISECONDS))
        release.countDown()
        assertTrue(closeReturned.await(1, TimeUnit.SECONDS))
        dispatchThread.join(1_000)
        closeThread.join(1_000)
        registration.dispatch(result())
        assertEquals(1, callbacks.get())
    }

    @Test
    fun connectionRequestClosesLeaseExactlyOnceWhenCallbackPrecedesAttach() {
        val callbacks = AtomicInteger(0)
        val closes = AtomicInteger(0)
        val request = BifrostConnectionProbeRequest(callback = { result ->
            assertTrue(result.isSuccess)
            callbacks.incrementAndGet()
        })
        request.complete(Result.success(receipt("A-01")))
        request.attach(Closeable { closes.incrementAndGet() })
        request.close()
        assertEquals(1, callbacks.get())
        assertEquals(1, closes.get())
    }

    @Test
    fun cancelledConnectionRequestSuppressesLateCompletionAndReleasesItsLease() {
        val callbacks = AtomicInteger(0)
        val closes = AtomicInteger(0)
        val request = BifrostConnectionProbeRequest(callback = { callbacks.incrementAndGet() })
        request.attach(Closeable { closes.incrementAndGet() })
        request.close()
        request.complete(Result.success(receipt("A-01")))
        assertEquals(0, callbacks.get())
        assertEquals(1, closes.get())
    }

    @Test
    fun cacheVersionThreeRejectsLegacyAndCorruption() {
        val legacy = JSONObject().put("version", 2).put("buckets", JSONObject()).toString()
        val unknown = JSONObject().put("version", 99).put("buckets", JSONObject()).toString()
        val validBucket = JSONObject()
            .put("source", "A")
            .put("network", "net-a")
            .put("config_version", 1)
            .put("config_digest", "a".repeat(64))
            .put("candidate_fingerprint", "b".repeat(64))
            .put("transport_fingerprint", "c".repeat(64))
            .put("generation", 1)
            .put("label", "A-01")
            .put("at", 1)
            .put("last_attempt", 1)
            .put("last_used", 1)
            .put("cohort", 0)
            .put("history", JSONObject())
        val valid = JSONObject().put("version", 3).put("buckets", JSONObject().put("k", validBucket)).toString()
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(legacy).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(unknown).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache("{").length())
        assertEquals(1, BifrostCandidateSelector.parseProbeCache(valid).getJSONObject("buckets").length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", 3).put("buckets", JSONObject().put("k", validBucket.put("unexpected", true))).toString(),
        ).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", "3").put("buckets", JSONObject().put("k", validBucketCopy())).toString(),
        ).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", 3).put("buckets", JSONObject().put("k", validBucketCopy().put("config_version", "1"))).toString(),
        ).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", 3).put("buckets", JSONObject().put("k", validBucketCopy().put("generation", -1))).toString(),
        ).length())
        val oversizedHistory = JSONObject()
        repeat(65) { index -> oversizedHistory.put("h$index", JSONObject().put("at", index)) }
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", 3).put("buckets", JSONObject().put("k", validBucketCopy().put("history", oversizedHistory))).toString(),
        ).length())
    }

    @Test
    fun sourceAuthorityHasNoFallbackChoicesWithoutVerifiedConfig() {
        val empty = BifrostSourceAuthority.empty()
        assertTrue(empty.sources.isEmpty())
        assertEquals(listOf("auto"), empty.frontSources)
        assertEquals(null, empty.accept("A"))
        val configured = BifrostSourceAuthority.fromVerifiedConfig(
            JSONObject().put("sources", org.json.JSONArray()
                .put(JSONObject().put("code", "A").put("configured", true))
                .put(JSONObject().put("code", "B").put("configured", false))).toString(),
        )
        assertEquals(listOf("A"), configured.sources)
        assertEquals("A", configured.accept("a"))
        assertEquals(null, configured.accept("B"))
    }

    @Test
    fun writerBoundsHistoryBeforeTheV3CommitAtEntryAndByteLimits() {
        val history = JSONObject()
        repeat(64) { index -> history.put("old-$index", historyEntry(index)) }
        history.put("new-a", historyEntry(100))
        history.put("new-b", historyEntry(101))
        history.put("new-c", historyEntry(102))
        val bounded = BifrostCandidateSelector.boundHistoryForCommit(history, setOf("new-a", "new-b", "new-c"))
        assertTrue(bounded.length() <= 64)
        assertTrue(bounded.toString().toByteArray(Charsets.UTF_8).size <= 64 * 1024)
        assertTrue(bounded.has("new-a") && bounded.has("new-b") && bounded.has("new-c"))
        val pressured = JSONObject()
        repeat(512) { index -> pressured.put("${"x".repeat(256)}-$index", historyEntry(index)) }
        assertTrue(pressured.toString().toByteArray(Charsets.UTF_8).size > 64 * 1024)
        val boundedPressure = BifrostCandidateSelector.boundHistoryForCommit(pressured, emptySet())
        assertTrue(boundedPressure.length() <= 64)
        assertTrue(boundedPressure.toString().toByteArray(Charsets.UTF_8).size <= 64 * 1024)
        val bucket = validBucketCopy().put("history", bounded)
        val parsed = BifrostCandidateSelector.parseProbeCache(
            JSONObject().put("version", 3).put("buckets", JSONObject().put("k", bucket)).toString(),
        )
        assertEquals(1, parsed.getJSONObject("buckets").length())
    }

    @Test
    fun allPreferredHistoryStillDropsEntriesOnlyAsRequiredByBothBounds() {
        val history = JSONObject()
        val preferred = (0 until 72).map { index -> "preferred-${"x".repeat(900)}-$index" }
        preferred.forEachIndexed { index, label -> history.put(label, historyEntry(index)) }
        val bounded = BifrostCandidateSelector.boundHistoryForCommit(history, preferred.toSet())
        assertTrue(bounded.length() <= 64)
        assertTrue(bounded.toString().toByteArray(Charsets.UTF_8).size <= 64 * 1024)
        assertTrue(bounded.keys().asSequence().all { preferred.contains(it) })
    }

    @Test
    fun cacheRejectsMalformedNestedHistoryNumbersAndNonFiniteValues() {
        val badNumericString = validBucketCopy().put(
            "history",
            JSONObject().put("A-01", historyEntry(1).put("consecutive_failures", "1")),
        )
        fun root(bucket: JSONObject) = JSONObject().put("version", 3)
            .put("buckets", JSONObject().put("k", bucket)).toString()
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(root(badNumericString)).length())
        assertEquals(0, BifrostCandidateSelector.parseProbeCache(
            """{"version":3,"buckets":{"k":{"source":"A","network":"net-a","config_version":1,"config_digest":"${"a".repeat(64)}","candidate_fingerprint":"${"b".repeat(64)}","transport_fingerprint":"${"c".repeat(64)}","generation":1,"label":"A-01","at":1,"last_attempt":1,"last_used":1,"cohort":0,"history":{"A-01":{"success_ewma":0.5,"rtt_ewma":1e309,"jitter_ewma":2.0,"loss_ewma":0.0,"consecutive_failures":0,"cooldown_until":0}}}}}""",
        ).length())
    }

    @Test
    fun cacheLruRetainsOnlyMostRecentlyUsedBuckets() {
        val buckets = JSONObject()
        repeat(10) { index -> buckets.put("k$index", JSONObject().put("last_used", index)) }
        val retained = BifrostCandidateSelector.retainedBucketKeys(buckets)
        assertEquals(8, retained.size)
        assertTrue(retained.containsAll(listOf("k9", "k8", "k2")))
        assertFalse(retained.contains("k1"))
        assertFalse(retained.contains("k0"))
    }

    @Test
    fun probeKeyBindsEveryImmutableDimension() {
        val base = key("A", "net-a", 7, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1)
        assertNotEquals(base.cacheKey(), key("B", "net-a", 7, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-b", 7, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-a", 8, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-a", 7, "d".repeat(64), "b".repeat(64), "c".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-a", 7, "a".repeat(64), "d".repeat(64), "c".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-a", 7, "a".repeat(64), "b".repeat(64), "d".repeat(64), 1).cacheKey())
        assertNotEquals(base.cacheKey(), key("A", "net-a", 7, "a".repeat(64), "b".repeat(64), "c".repeat(64), 2).cacheKey())
    }

    @Test
    fun closePreventsLatePublishAndLeavesNoDemand() {
        val scheduler = ManualProbeScheduler()
        val published = mutableListOf<String>()
        val coordinator = lifecycle(
            scheduler,
            load = { input("A") },
            probe = { input, _, _, _ -> "${input.source}-01" },
            publish = { if (it.label != null) published += it.label },
        )
        coordinator.acquireLease("activity", "A")
        coordinator.close()
        scheduler.advanceBy(0)
        assertTrue(published.isEmpty())
        assertFalse(coordinator.hasDemand())
    }

    private fun lifecycle(
        scheduler: ManualProbeScheduler,
        debounceMs: Long = 10,
        cadenceMs: Long = 100,
        load: (String) -> BifrostProbeRoundInput?,
        probe: (BifrostProbeRoundInput, BifrostProbeRoundKey, ProbeCancellation, () -> Boolean) -> String,
        publish: (BifrostProbeCoordinatorResult) -> Unit = {},
        unavailable: (source: String, error: Throwable) -> Unit = { _, _ -> },
        unavailableAdmitted: ((source: String, error: Throwable, admission: BifrostProbeFailureAdmission) -> Unit)? = null,
        beforePublish: (() -> Unit)? = null,
    ) = BifrostProbeLifecycleCoordinator(
        scheduler = scheduler,
        debounceMs = debounceMs,
        cadenceMs = cadenceMs,
        load = load,
        probe = probe,
        publish = publish,
        unavailable = unavailable,
        unavailableAdmitted = unavailableAdmitted,
        beforePublish = beforePublish,
    )

    private fun input(
        source: String,
        network: String = "net-a",
        version: Long = 1L,
        digest: String = "a".repeat(64),
        candidate: String = "b".repeat(64),
        transport: String = "c".repeat(64),
    ) = BifrostProbeRoundInput(
        content = "{}",
        source = source,
        networkFingerprint = network,
        configVersion = version,
        configDigest = digest,
        candidateFingerprint = candidate,
        transportFingerprint = transport,
    )

    private fun key(
        source: String,
        network: String,
        version: Long,
        digest: String,
        candidate: String,
        transport: String,
        generation: Long,
    ) = BifrostProbeRoundKey(source, network, version, digest, candidate, transport, generation)

    private fun result() = BifrostProbeCoordinatorResult(
        source = "A",
        key = key("A", "net-a", 1, "a".repeat(64), "b".repeat(64), "c".repeat(64), 1),
        label = "A-01",
        error = null,
    )

    private fun receipt(label: String) = BifrostCandidateSelectionReceipt(
        label,
        BifrostProbeConnectionBinding.from(input("A"), 1L),
    )

    private fun validBucketCopy(): JSONObject = JSONObject()
        .put("source", "A")
        .put("network", "net-a")
        .put("config_version", 1)
        .put("config_digest", "a".repeat(64))
        .put("candidate_fingerprint", "b".repeat(64))
        .put("transport_fingerprint", "c".repeat(64))
        .put("generation", 1)
        .put("label", "A-01")
        .put("at", 1)
        .put("last_attempt", 1)
        .put("last_used", 1)
        .put("cohort", 0)
        .put("history", JSONObject())

    private fun historyEntry(index: Int): JSONObject = JSONObject()
        .put("success_ewma", 0.5)
        .put("rtt_ewma", 10.0 + index)
        .put("jitter_ewma", 2.0)
        .put("loss_ewma", 0.0)
        .put("consecutive_failures", 0)
        .put("cooldown_until", 0L)

    private class ManualProbeScheduler : BifrostProbeScheduler {
        private data class Task(val at: Long, val order: Long, val runnable: () -> Unit, var cancelled: Boolean = false) : Closeable {
            override fun close() { cancelled = true }
        }

        private var now = 0L
        private var order = 0L
        private val tasks = mutableListOf<Task>()

        override fun schedule(delayMs: Long, task: () -> Unit): Closeable {
            val scheduled = Task(now + delayMs.coerceAtLeast(0L), order++, task)
            tasks += scheduled
            return scheduled
        }

        fun advanceBy(deltaMs: Long) {
            now += deltaMs
            while (true) {
                val next = tasks
                    .filter { !it.cancelled && it.at <= now }
                    .minWithOrNull(compareBy<Task> { it.at }.thenBy { it.order })
                    ?: return
                tasks -= next
                if (!next.cancelled) next.runnable()
            }
        }

        override fun close() {
            tasks.forEach { it.cancelled = true }
            tasks.clear()
        }
    }
}
