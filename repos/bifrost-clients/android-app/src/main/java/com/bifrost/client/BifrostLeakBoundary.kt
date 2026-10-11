package com.bifrost.client

/** Small dependency-injected boundary used by the service and JVM tests. */
interface BifrostBlackholeController {
    fun enter(): Boolean
    fun release()
}

class BifrostLeakBoundary(private val blackhole: BifrostBlackholeController) {
    var snapshot: BifrostLeakSnapshot = BifrostLeakGuard.stopped()
        private set
    private var fenced = false

    internal fun adoptHealthy(lockdownEvidence: Boolean): Boolean {
        if (fenced || snapshot.state != BifrostLeakState.STOPPED) return false
        snapshot = BifrostLeakGuard.healthy(lockdownEvidence)
        BifrostRuntimeStatus.publish(snapshot)
        return true
    }

    /**
     * Fence ordinary application traffic before any probe, core, or TUN work
     * starts.  Re-entering while already fenced is idempotent and is used by
     * the BLOCKING -> STARTING reconnect path.
     */
    fun starting(lockdownEvidence: Boolean): Boolean {
        if (!fenced) fenced = runCatching { blackhole.enter() }.getOrDefault(false)
        snapshot = if (fenced) {
            BifrostLeakGuard.starting(lockdownEvidence)
        } else {
            BifrostLeakGuard.unprotected(lockdownEvidence)
        }
        BifrostRuntimeStatus.publish(snapshot)
        return fenced
    }

    fun coreHealthy(lockdownEvidence: Boolean): Boolean {
        // A core can only become healthy when the pre-start fence is still
        // held.  Never release a blackhole for a core that failed to start.
        if (snapshot.state != BifrostLeakState.STARTING) return false
        // Release a retained blackhole only after the replacement core is ready.
        return try {
            blackhole.release()
            fenced = false
            snapshot = BifrostLeakGuard.healthy(lockdownEvidence)
            BifrostRuntimeStatus.publish(snapshot)
            true
        } catch (_: Throwable) {
            // A failed release is not a healthy core: retain the fence and
            // expose a blocking state for the caller's exact failure path.
            fenced = true
            snapshot = BifrostLeakGuard.blocking(lockdownEvidence)
            BifrostRuntimeStatus.publish(snapshot)
            false
        }
    }

    fun coreFailed(lockdownEvidence: Boolean = false): Boolean {
        val blocked = if (fenced) true else runCatching { blackhole.enter() }.getOrDefault(false)
        fenced = blocked
        snapshot = if (blocked) BifrostLeakGuard.blocking(lockdownEvidence) else BifrostLeakGuard.unprotected(lockdownEvidence)
        BifrostRuntimeStatus.publish(snapshot)
        return blocked
    }

    /** Enter a retained fence before stopping a healthy core.  Disconnect
     * cannot release ordinary traffic while native teardown is unconfirmed. */
    fun beginDisconnect(lockdownEvidence: Boolean = false): Boolean {
        if (!fenced) fenced = runCatching { blackhole.enter() }.getOrDefault(false)
        snapshot = if (fenced) BifrostLeakGuard.blocking(lockdownEvidence)
        else BifrostLeakGuard.unprotected(lockdownEvidence)
        BifrostRuntimeStatus.publish(snapshot)
        return fenced
    }

    /** Release the fence only after core/platform teardown succeeds. */
    fun disconnect(lockdownEvidence: Boolean = false): Boolean {
        if (!fenced) {
            return try {
                // Idempotent close for callers that already released the
                // fence (the runtime coordinator normally re-enters it first).
                blackhole.release()
                snapshot = BifrostLeakGuard.stopped(lockdownEvidence)
                BifrostRuntimeStatus.publish(snapshot)
                true
            } catch (_: Throwable) {
                snapshot = BifrostLeakGuard.unprotected(lockdownEvidence)
                BifrostRuntimeStatus.publish(snapshot)
                false
            }
        }
        return try {
            blackhole.release()
            fenced = false
            snapshot = BifrostLeakGuard.stopped(lockdownEvidence)
            BifrostRuntimeStatus.publish(snapshot)
            true
        } catch (_: Throwable) {
            fenced = true
            snapshot = BifrostLeakGuard.blocking(lockdownEvidence)
            BifrostRuntimeStatus.publish(snapshot)
            false
        }
    }

    /** Mark a failed pre-start attempt without releasing an already-held fence. */
    fun abortStart(lockdownEvidence: Boolean = false) {
        // If establishing the initial fence failed there is no descriptor to
        // release.  A failed attempt after a fence is kept blocking by the
        // normal coreFailed path instead of entering this method.
        if (!fenced) blackhole.release()
        snapshot = BifrostLeakGuard.unprotected(lockdownEvidence)
        BifrostRuntimeStatus.publish(snapshot)
    }

    /** The independent Root process disappeared and therefore cannot own a
     * Bifrost fence anymore.  This is an authoritative unprotected state, not
     * a best-effort blackhole transition: do not call the dead remote merely
     * to rediscover that its boundary is gone. */
    internal fun ownerLost(lockdownEvidence: Boolean = false) {
        fenced = false
        snapshot = BifrostLeakGuard.unprotected(lockdownEvidence)
        BifrostRuntimeStatus.publish(snapshot)
    }

    fun destroyed() = disconnect(false)
}

/** Process-local status bridge consumed by Activity and notification. */
object BifrostRuntimeStatus {
    @Volatile var current: BifrostLeakSnapshot = BifrostLeakGuard.stopped()
        private set
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<(BifrostLeakSnapshot) -> Unit>()

    fun publish(snapshot: BifrostLeakSnapshot) {
        current = snapshot
        listeners.forEach { listener -> runCatching { listener(snapshot) } }
    }

    fun addListener(listener: (BifrostLeakSnapshot) -> Unit): AutoCloseable {
        listeners += listener
        listener(current)
        return AutoCloseable { listeners -= listener }
    }
}
