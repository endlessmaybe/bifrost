package com.bifrost.client

/** Video traffic arrives in bursts. One quiet status sample is not an idle
 * connection; wait for a sustained quiet period before bandwidth probes. */
internal class BifrostProbeTrafficGuard(private val clock: () -> Long) {
    private var quietSince = clock()
    private var lastSampleAt: Long? = null
    private var validSample = false

    @Synchronized fun observe(rate: Double) {
        val now = clock()
        if (lastSampleAt == null || now - lastSampleAt!! !in 0..3_000 ||
            now < quietSince || !rate.isFinite() || rate < 0 || rate > ACTIVITY_RATE) quietSince = now
        validSample = rate.isFinite() && rate >= 0
        lastSampleAt = now
    }

    @Synchronized fun ready(): Boolean {
        val now = clock()
        val sampleAt = lastSampleAt ?: return false
        return validSample && now - sampleAt in 0..3_000 && now - quietSince >= QUIET_MS
    }

    companion object {
        const val QUIET_MS = 30_000L
        const val ACTIVITY_RATE = 4.0 * 1024
    }
}
