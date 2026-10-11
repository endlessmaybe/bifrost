package com.bifrost.client

/** Admission controls apply to diagnostic transfers, never to user traffic. */
internal class BifrostQualityWorkPolicy(private val probeBudget: BifrostProbeBudget = BifrostProbeBudget()) {
    private var lowSince: Long? = null
    private var lastLowTrafficAt: Long? = null
    private var lastObservedAt: Long? = null
    private var nextRecovery = 0L
    private var windowStarted = -1L
    private var spent = 0L

    @Synchronized fun resetActivity() { lowSince = null; lastLowTrafficAt = null; lastObservedAt = null }

    /** Observe each status update, so the fifteen-second scheduler cannot miss
     * short slow transfers. Brief stalls belong to the same slow session;
     * a fast burst, invalid counter or thirty seconds without activity ends it. */
    @Synchronized fun observe(now: Long, rate: Double) {
        if (lastObservedAt?.let { now < it || now - it > 30_000 } == true) resetActivity()
        lastObservedAt = now
        if (!rate.isFinite() || rate < 0 || rate >= RECOVERY_CEILING) {
            lowSince = null; lastLowTrafficAt = null; return
        }
        if (lastLowTrafficAt?.let { now - it >= 30_000 } == true) {
            lowSince = null; lastLowTrafficAt = null
        }
        if (rate > IDLE_RATE) {
            if (lowSince == null) lowSince = now
            lastLowTrafficAt = now
        }
    }

    @Synchronized fun admit(now: Long, rate: Double, visible: Boolean, interactive: Boolean): Boolean? {
        observe(now, rate)
        if (!rate.isFinite() || rate < 0 || rate >= RECOVERY_CEILING) return null
        if (!interactive) { resetActivity(); return null }
        if (rate <= IDLE_RATE && visible) return false
        if (lowSince == null) return null
        if (now - lowSince!! < 30_000 || now < nextRecovery) return null
        nextRecovery = now + 120_000
        lowSince = null; lastLowTrafficAt = null
        return true
    }

    @Synchronized fun reserve(now: Long, bytes: Long, keepHealthReserve: Boolean = false, metered: Boolean = false): Boolean {
        if (bytes <= 0 || bytes > MAX_BYTES) return false
        if (windowStarted < 0 || now < windowStarted || now - windowStarted >= WINDOW_MS) {
            windowStarted = now; spent = 0
        }
        val limit = MAX_BYTES - if (keepHealthReserve) 256 * 1024L else 0L
        if (spent + bytes > limit) return false
        if (!probeBudget.reserve(now, bytes, metered, keepHealthReserve)) return false
        spent += bytes
        return true
    }

    fun retryDelay(now: Long): Long = probeBudget.retryDelay(now)

    companion object {
        const val IDLE_RATE = 16.0 * 1024
        const val INTERACTIVE_CEILING = 128.0 * 1024
        const val RECOVERY_CEILING = 512.0 * 1024
        const val WINDOW_MS = 300_000L
        // Diagnostic bytes stay bounded and are cancelled when foreground
        // traffic resumes, but this must be large enough to inspect a full
        // provider instead of turning "save probe traffic" into hours of slow
        // node retention.
        const val MAX_BYTES = 768L * 1024 * 1024
        fun canContinue(rate: Double, recovery: Boolean): Boolean = rate.isFinite() && rate >= 0 &&
            rate < if (recovery) RECOVERY_CEILING else INTERACTIVE_CEILING
    }
}
