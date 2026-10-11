package com.bifrost.client

/**
 * The single lifecycle state machine used by the real VPN service and JVM
 * tests.  It deliberately owns ordering: a failed core is fenced first and
 * only then stopped, while a replacement core must report ready before the
 * fence is released.  All entry points are idempotent so libbox callbacks,
 * watchdogs and Android lifecycle callbacks cannot race a second teardown.
 */
internal interface BifrostRuntimeWatchdog {
    /** Start an independent health loop; callback must be idempotent. */
    fun start(onCoreFailure: () -> Unit)

    fun stop()
}

internal data class BifrostRuntimeDisconnectOutcome(
    val success: Boolean,
    val blocked: Boolean,
    val code: String,
)

internal data class BifrostRuntimeCoreFailureOutcome(
    val blocked: Boolean,
    val teardownConfirmed: Boolean,
    val code: String,
)

private object NoopBifrostRuntimeWatchdog : BifrostRuntimeWatchdog {
    override fun start(onCoreFailure: () -> Unit) = Unit
    override fun stop() = Unit
}

internal class BifrostRuntimeCoordinator(
    private val boundary: BifrostLeakBoundary,
    private val stopCore: () -> Unit,
    private val lockdownEvidence: () -> Boolean,
    private val watchdog: BifrostRuntimeWatchdog = NoopBifrostRuntimeWatchdog,
) {
    private val gate = Any()
    private var failureHandled = false
    private var destroyed = false
    @Volatile private var lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, true, "BF-NONE")

    val lastCoreFailureOutcome: BifrostRuntimeCoreFailureOutcome
        get() = synchronized(gate) { lastCoreFailure }

    val snapshot: BifrostLeakSnapshot
        get() = synchronized(gate) { boundary.snapshot }

    fun starting(): Boolean = synchronized(gate) {
        if (destroyed) return@synchronized false
        failureHandled = false
        watchdog.stop()
        boundary.starting(lockdownEvidence())
    }

    /** Reattach only after the independent runtime proves its owned boundary. */
    fun adoptHealthy(verified: () -> Boolean): Boolean = synchronized(gate) {
        if (destroyed || !verified()) return@synchronized false
        if (!boundary.adoptHealthy(lockdownEvidence())) return@synchronized false
        failureHandled = false
        watchdog.start { coreFailure() }
        true
    }

    fun coreReady(): Boolean = synchronized(gate) {
        if (destroyed) return@synchronized false
        // The boundary releases the retained blackhole only here, after the
        // caller has already observed a real core/TUN ready signal.
        if (!boundary.coreHealthy(lockdownEvidence())) return@synchronized false
        watchdog.start { coreFailure() }
        failureHandled = false
        true
    }

    fun coreFailure(): Boolean = coreFailureOutcome().blocked

    fun coreFailureOutcome(): BifrostRuntimeCoreFailureOutcome = synchronized(gate) {
        if (destroyed) {
            lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, false, "BF-RUNTIME-DESTROYED")
            return@synchronized lastCoreFailure
        }
        if (failureHandled) return@synchronized lastCoreFailure
        failureHandled = true
        try {
            watchdog.stop()
        } catch (_: Throwable) {
            lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, false, "BF-WATCHDOG-STOP")
            return@synchronized lastCoreFailure
        }
        val evidence = try {
            lockdownEvidence()
        } catch (_: Throwable) {
            lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, false, "BF-LOCKDOWN-EVIDENCE")
            return@synchronized lastCoreFailure
        }
        val blocked = boundary.coreFailed(evidence)
        var teardownConfirmed = true
        // Ordering is security relevant: never stop the failed core before
        // the Bifrost-owned blackhole has been established.
        try {
            stopCore()
        } catch (_: Throwable) {
            teardownConfirmed = false
        }
        val physicallyBlocked = blocked && boundary.snapshot.state == BifrostLeakState.BLOCKING
        lastCoreFailure = BifrostRuntimeCoreFailureOutcome(
            physicallyBlocked,
            teardownConfirmed,
            when {
                physicallyBlocked && teardownConfirmed -> "BF-CORE-BLOCKED"
                physicallyBlocked -> "BF-CORE-BLOCKED-STOP-UNCONFIRMED"
                teardownConfirmed -> "BF-CORE-UNPROTECTED"
                else -> "BF-CORE-STOP-UNCONFIRMED"
            },
        )
        lastCoreFailure
    }

    fun disconnect(): BifrostRuntimeDisconnectOutcome = synchronized(gate) {
        if (destroyed) return@synchronized BifrostRuntimeDisconnectOutcome(false, false, "BF-RUNTIME-DESTROYED")
        try {
            watchdog.stop()
        } catch (_: Throwable) {
            return@synchronized BifrostRuntimeDisconnectOutcome(false, false, "BF-WATCHDOG-STOP")
        }
        val evidence = try {
            lockdownEvidence()
        } catch (_: Throwable) {
            return@synchronized BifrostRuntimeDisconnectOutcome(false, false, "BF-LOCKDOWN-EVIDENCE")
        }
        if (!boundary.beginDisconnect(evidence)) {
            return@synchronized BifrostRuntimeDisconnectOutcome(false, false, "BF-BLACKHOLE-UNAVAILABLE")
        }
        try {
            // Native/core and platform teardown are deliberately not wrapped
            // in a swallowing runCatching.  A thrown close/deactivate leaves
            // the fence retained and remains retryable by the exact token.
            stopCore()
        } catch (_: Throwable) {
            failureHandled = true
            return@synchronized BifrostRuntimeDisconnectOutcome(false, true, "BF-CORE-STOP")
        }
        if (!boundary.disconnect(evidence)) {
            failureHandled = true
            return@synchronized BifrostRuntimeDisconnectOutcome(false, true, "BF-BLACKHOLE-RELEASE")
        }
        failureHandled = false
        BifrostRuntimeDisconnectOutcome(true, false, "BF-CONNECTION-DISCONNECTED")
    }

    fun abortStart() = synchronized(gate) {
        if (destroyed) return@synchronized
        watchdog.stop()
        runCatching { stopCore() }
        boundary.abortStart(lockdownEvidence())
        failureHandled = false
    }

    /** Root daemon loss is stronger evidence than a transport health failure:
     * the remote process itself reported no owner (or a different epoch).
     * Publish UNPROTECTED without trying to block/stop through that dead
     * capability; the caller can immediately establish a fresh fenced start. */
    fun ownerLost(): BifrostRuntimeCoreFailureOutcome = synchronized(gate) {
        if (destroyed) {
            lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, true, "BF-RUNTIME-DESTROYED")
            return@synchronized lastCoreFailure
        }
        watchdog.stop()
        boundary.ownerLost(runCatching { lockdownEvidence() }.getOrDefault(false))
        failureHandled = true
        lastCoreFailure = BifrostRuntimeCoreFailureOutcome(false, true, "BF-ROOT-OWNER-LOST")
        lastCoreFailure
    }

    fun revoke() = synchronized(gate) {
        if (destroyed) return@synchronized
        destroyed = true
        watchdog.stop()
        runCatching { stopCore() }
        boundary.destroyed()
    }

    fun destroy() = synchronized(gate) {
        if (destroyed) return@synchronized
        destroyed = true
        watchdog.stop()
        runCatching { stopCore() }
        boundary.destroyed()
    }
}
