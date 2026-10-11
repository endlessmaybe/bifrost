package com.bifrost.client

/** Passive failures request a bounded comparison, never an unmeasured switch. */
internal class BifrostFailureRecovery {
    private val failures = ArrayDeque<Long>()
    private var pendingUntil = 0L
    private var nextAttempt = 0L
    private var ignoreUntil = 0L

    @Synchronized fun networkChanged(now: Long) {
        failures.clear(); pendingUntil = 0; nextAttempt = 0; ignoreUntil = now + 8_000
    }
    @Synchronized fun observe(now: Long, message: String) {
        if (now < ignoreUntil || now < nextAttempt || !isTransportFailure(message)) return
        while (failures.isNotEmpty() && now - failures.first() > 120_000) failures.removeFirst()
        if (failures.lastOrNull()?.let { now - it < 500 } == true) return
        failures.addLast(now)
        if (failures.size >= 3) { pendingUntil = now + 60_000; failures.clear() }
    }
    @Synchronized fun claim(now: Long, rate: Double, interactive: Boolean): Boolean {
        if (!interactive || !rate.isFinite() || rate < 0 || rate > BifrostQualityWorkPolicy.IDLE_RATE ||
            pendingUntil == 0L || now > pendingUntil || now < nextAttempt) return false
        pendingUntil = 0; nextAttempt = now + 120_000; failures.clear()
        return true
    }
    companion object {
        fun isTransportFailure(message: String): Boolean {
            val value = message.lowercase()
            val proxiedOpen = value.contains("open connection to") &&
                (value.contains("outbound/selector[proxy]") || value.contains("outbound/vmess[proxy"))
            val handshake = value.contains("connection download handshake")
            return (proxiedOpen || handshake) &&
                listOf("timeout", "deadline exceeded", "connection reset", "connection refused", "eof")
                    .any(value::contains)
        }
    }
}
