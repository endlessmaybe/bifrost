package com.bifrost.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class BifrostLeakGuardTest {
    @Test
    @Suppress("DEPRECATION")
    fun coreFailureWithoutBlackholeIsExplicitlyUnprotected() {
        val snapshot = BifrostLeakGuard.coreFailure()
        assertFalse(snapshot.shouldBlock)
        assertFalse(snapshot.strictProtection)
    }

    @Test
    fun strictProtectionRequiresOsLockdownEvidence() {
        assertFalse(BifrostLeakGuard.healthy(false).strictProtection)
        assertTrue(BifrostLeakGuard.healthy(true).strictProtection)
    }

    @Test
    fun stoppedNeverClaimsProtected() {
        val snapshot = BifrostLeakGuard.stopped(true)
        assertFalse(snapshot.strictProtection)
        assertFalse(snapshot.shouldBlock)
    }
}

class BifrostLeakBoundaryTest {
    private class FakeBlackhole(private val succeeds: Boolean) : BifrostBlackholeController {
        var enters = 0
        var releases = 0
        override fun enter(): Boolean { enters++; return succeeds }
        override fun release() { releases++ }
    }

    @Test
    fun crashRetainsOwnedBlackholeUntilReconnectOrDisconnect() {
        val fake = FakeBlackhole(true)
        val boundary = BifrostLeakBoundary(fake)
        boundary.starting(false)
        assertTrue(boundary.coreFailed())
        assertTrue(boundary.snapshot.shouldBlock)
        assertTrue(boundary.starting(false))
        boundary.coreHealthy(false)
        assertFalse(boundary.snapshot.shouldBlock)
        assertTrue(fake.releases > 0)
        boundary.disconnect()
        assertTrue(fake.releases > 1)
    }

    @Test
    fun establishFailureNeverClaimsBlocking() {
        val boundary = BifrostLeakBoundary(FakeBlackhole(false))
        assertFalse(boundary.starting(false))
        assertFalse(boundary.coreFailed())
        assertFalse(boundary.snapshot.shouldBlock)
        assertFalse(boundary.snapshot.strictProtection)
    }

    @Test
    fun strictProtectionNeedsHealthyCoreAndOsEvidence() {
        val boundary = BifrostLeakBoundary(FakeBlackhole(true))
        assertTrue(boundary.starting(false))
        boundary.coreHealthy(false)
        assertFalse(boundary.snapshot.strictProtection)
        assertTrue(boundary.starting(false))
        boundary.coreHealthy(true)
        assertTrue(boundary.snapshot.strictProtection)
    }

    @Test
    fun destroyedAndRevokePathsReleaseOwnedBlackholeWithoutProtectedClaim() {
        val fake = FakeBlackhole(true)
        val boundary = BifrostLeakBoundary(fake)
        boundary.starting(false)
        boundary.coreFailed()
        boundary.destroyed()
        assertFalse(boundary.snapshot.shouldBlock)
        assertFalse(boundary.snapshot.strictProtection)
        assertTrue(fake.releases > 0)
    }
}

class BifrostRuntimeCoordinatorTest {
    private class FakeBlackhole(private val succeeds: Boolean) : BifrostBlackholeController {
        var enters = 0
        var releases = 0
        override fun enter(): Boolean { enters++; return succeeds }
        override fun release() { releases++ }
    }

    private class FakeWatchdog : BifrostRuntimeWatchdog {
        var starts = 0
        var stops = 0
        private var onFailure: (() -> Unit)? = null
        override fun start(onCoreFailure: () -> Unit) { starts++; onFailure = onCoreFailure }
        override fun stop() { stops++ }
        fun crashCore() { onFailure?.invoke() }
    }

    @Test
    fun failureIsFencedBeforeCoreStopAndDuplicateCallbacksAreIdempotent() {
        val order = mutableListOf<String>()
        val blackhole = object : BifrostBlackholeController {
            override fun enter(): Boolean { order += "blackhole"; return true }
            override fun release() { order += "release" }
        }
        val boundary = BifrostLeakBoundary(blackhole)
        val coordinator = BifrostRuntimeCoordinator(boundary, { order += "stop" }, lockdownEvidence = { false })
        coordinator.starting()
        assertTrue(coordinator.coreFailure())
        assertTrue(coordinator.coreFailure())
        assertEquals(listOf("blackhole", "stop"), order)
        assertEquals(BifrostLeakState.BLOCKING, coordinator.snapshot.state)
    }

    @Test
    fun blockingReconnectReleasesOnlyAfterReadyAndLifecycleIsTerminal() {
        val blackhole = FakeBlackhole(true)
        var stops = 0
        val coordinator = BifrostRuntimeCoordinator(BifrostLeakBoundary(blackhole), { stops++ }, lockdownEvidence = { false })
        coordinator.starting()
        assertTrue(coordinator.coreFailure())
        coordinator.starting()
        assertEquals(BifrostLeakState.STARTING, coordinator.snapshot.state)
        coordinator.coreReady()
        assertEquals(BifrostLeakState.HEALTHY, coordinator.snapshot.state)
        coordinator.revoke()
        coordinator.destroy()
        assertEquals(2, stops)
        assertEquals(BifrostLeakState.STOPPED, coordinator.snapshot.state)
    }

    @Test
    fun blackholeFailureIsUnprotectedAndNeverClaimsStrictProtection() {
        val coordinator = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(false)),
            {},
            lockdownEvidence = { true },
        )
        coordinator.starting()
        assertFalse(coordinator.coreFailure())
        assertEquals(BifrostLeakState.UNPROTECTED, coordinator.snapshot.state)
        assertFalse(coordinator.snapshot.strictProtection)
    }

    @Test
    fun watchdogIsStartedOnlyAfterReadyAndStopsBeforeFailureTeardown() {
        val events = mutableListOf<String>()
        val watchdog = FakeWatchdog()
        val boundary = BifrostLeakBoundary(object : BifrostBlackholeController {
            override fun enter(): Boolean { events += "blackhole"; return true }
            override fun release() { events += "release" }
        })
        val coordinator = BifrostRuntimeCoordinator(
            boundary,
            { events += "stop" },
            { false },
            watchdog,
        )
        coordinator.starting()
        assertEquals(0, watchdog.starts)
        coordinator.coreReady()
        assertEquals(1, watchdog.starts)
        watchdog.crashCore()
        assertEquals(listOf("blackhole", "release", "blackhole", "stop"), events)
        assertTrue(watchdog.stops >= 1)
    }

    @Test
    fun coreReadyCannotReleaseFenceWhenStartWasNotEstablished() {
        val boundary = BifrostLeakBoundary(FakeBlackhole(false))
        assertFalse(boundary.starting(false))
        assertFalse(boundary.coreHealthy(false))
        assertEquals(BifrostLeakState.UNPROTECTED, boundary.snapshot.state)
    }

    @Test
    fun coordinatorStartFailureStopsWithoutStartingCore() {
        var stopped = 0
        val coordinator = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(false)),
            { stopped++ },
            lockdownEvidence = { false },
        )
        assertFalse(coordinator.starting())
        coordinator.abortStart()
        assertEquals(1, stopped)
        assertEquals(BifrostLeakState.UNPROTECTED, coordinator.snapshot.state)
    }

    @Test
    fun disconnectStopFailureRetainsFenceAndExactRetryCanFinish() {
        val events = mutableListOf<String>()
        val boundary = BifrostLeakBoundary(object : BifrostBlackholeController {
            override fun enter(): Boolean { events += "enter"; return true }
            override fun release() { events += "release" }
        })
        var fail = true
        val coordinator = BifrostRuntimeCoordinator(
            boundary,
            {
                events += "stop"
                if (fail) throw IllegalStateException("injected core stop")
            },
            lockdownEvidence = { false },
        )
        assertTrue(coordinator.starting())
        assertTrue(coordinator.coreReady())
        val first = coordinator.disconnect()
        assertFalse(first.success)
        assertTrue(first.blocked)
        assertEquals(BifrostLeakState.BLOCKING, coordinator.snapshot.state)
        fail = false
        val second = coordinator.disconnect()
        assertTrue(second.success)
        assertEquals(BifrostLeakState.STOPPED, coordinator.snapshot.state)
        assertEquals(listOf("enter", "release", "enter", "stop", "stop", "release"), events)
    }

    @Test
    fun disconnectReleaseFailureDoesNotPublishStoppedUntilRetry() {
        var releases = 0
        val boundary = BifrostLeakBoundary(object : BifrostBlackholeController {
            override fun enter(): Boolean = true
            override fun release() {
                releases++
                if (releases == 2) throw IllegalStateException("injected blackhole release")
            }
        })
        val coordinator = BifrostRuntimeCoordinator(boundary, {}, lockdownEvidence = { false })
        assertTrue(coordinator.starting())
        assertTrue(coordinator.coreReady())
        val first = coordinator.disconnect()
        assertFalse(first.success)
        assertTrue(first.blocked)
        assertEquals(BifrostLeakState.BLOCKING, coordinator.snapshot.state)
        val second = coordinator.disconnect()
        assertTrue(second.success)
        assertEquals(BifrostLeakState.STOPPED, coordinator.snapshot.state)
    }

    @Test
    fun disconnectPreBoundaryFailuresNeverReportBlocked() {
        var watchdogArmed = false
        val watchdogThrow = object : BifrostRuntimeWatchdog {
            override fun start(onCoreFailure: () -> Unit) = Unit
            override fun stop() { if (watchdogArmed) throw IllegalStateException("watchdog") }
        }
        val watchdogRuntime = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(true)), {}, lockdownEvidence = { false }, watchdogThrow,
        )
        assertTrue(watchdogRuntime.starting())
        watchdogArmed = true
        assertFalse(watchdogRuntime.disconnect().blocked)
        assertEquals("BF-WATCHDOG-STOP", watchdogRuntime.disconnect().code)

        var evidenceArmed = false
        val evidenceRuntime = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(true)), {}, lockdownEvidence = {
                if (evidenceArmed) throw IllegalStateException("evidence") else false
            },
        )
        assertTrue(evidenceRuntime.starting())
        evidenceArmed = true
        assertFalse(evidenceRuntime.disconnect().blocked)
        assertEquals("BF-LOCKDOWN-EVIDENCE", evidenceRuntime.disconnect().code)

        val noBlackholeRuntime = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(false)), {}, lockdownEvidence = { false },
        )
        assertFalse(noBlackholeRuntime.starting())
        assertFalse(noBlackholeRuntime.disconnect().blocked)
        assertEquals("BF-BLACKHOLE-UNAVAILABLE", noBlackholeRuntime.disconnect().code)
    }

    @Test
    fun coreStopAndBlackholeReleaseFailuresRetainPhysicalBlockedEvidence() {
        val stopRuntime = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(FakeBlackhole(true)),
            { throw IllegalStateException("stop") },
            lockdownEvidence = { false },
        )
        assertTrue(stopRuntime.starting())
        assertTrue(stopRuntime.coreReady())
        val stopFailure = stopRuntime.disconnect()
        assertFalse(stopFailure.success)
        assertTrue(stopFailure.blocked)
        assertEquals(BifrostLeakState.BLOCKING, stopRuntime.snapshot.state)

        var releases = 0
        val releaseRuntime = BifrostRuntimeCoordinator(
            BifrostLeakBoundary(object : BifrostBlackholeController {
                override fun enter() = true
                override fun release() {
                    releases++
                    if (releases >= 2) throw IllegalStateException("release")
                }
            }),
            {},
            lockdownEvidence = { false },
        )
        assertTrue(releaseRuntime.starting())
        assertTrue(releaseRuntime.coreReady())
        val releaseFailure = releaseRuntime.disconnect()
        assertFalse(releaseFailure.success)
        assertTrue(releaseFailure.blocked)
        assertEquals(BifrostLeakState.BLOCKING, releaseRuntime.snapshot.state)
    }
}
