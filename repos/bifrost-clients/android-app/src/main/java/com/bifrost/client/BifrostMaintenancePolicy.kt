package com.bifrost.client

/** Scheduling policy only: it never throttles user packets or changes routes. */
internal object BifrostMaintenancePolicy {
    const val CONFIG_INTERVAL_MS = 15 * 60_000L
    // Match the Windows throughput-first maintenance strategy: a confirmed
    // winner is rechecked every two minutes and a complete catalogue sweep is
    // reopened every hour. Android keeps its independent rolling byte budget
    // and foreground-traffic guard, so these timers can never override mobile
    // data limits or compete with user traffic.
    const val QUALITY_INTERVAL_MS = 2 * 60_000L
    const val METERED_QUALITY_INTERVAL_MS = 2 * 60_000L
    const val FULL_SWEEP_INTERVAL_MS = 60 * 60_000L
    private var lastConfigAttempt: Long? = null
    @Synchronized fun claimConfigRefresh(now: Long): Boolean {
        val previous = lastConfigAttempt
        if (previous != null && now >= previous && now - previous < CONFIG_INTERVAL_MS) return false
        lastConfigAttempt = now
        return true
    }

    fun shouldProbe(now: Long, lastProbe: Long, visible: Boolean, interactive: Boolean,
        lastReceive: Long, lastSend: Long, failures: Int, lastTransportFailure: Long = 0L): Boolean {
        val receiving = lastReceive > 0 && now - lastReceive in 0..30_000
        val demand = lastSend > 0 && now - lastSend in 0..15_000
        val transportFailure = lastTransportFailure > 0 && now - lastTransportFailure in 0..30_000
        val followUpRecovery = failures > 0 && lastProbe > 0 && now - lastProbe in 0..180_000
        val recovering = transportFailure || followUpRecovery
        // A native DNS/transport failure is evidence of real demand even when
        // name resolution failed before traffic accounting could observe >1 KB
        // of uplink. Keep ordinary background idle traffic probe-free, but do
        // not let unrelated receive bytes suppress confirmation/recovery.
        if (receiving && !recovering || !(visible && interactive) && !demand && !recovering) return false
        val interval = if (demand || transportFailure) 15_000L else if (failures > 0)
            minOf(180_000L, 15_000L * (1L shl failures.coerceIn(0, 4))) else 180_000L
        return now - lastProbe >= interval
    }
}

internal object BifrostAppVisibility {
    @Volatile var visible = false
        private set
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<(Boolean) -> Unit>()
    fun update(value: Boolean) {
        if (visible == value) return
        visible = value
        listeners.forEach { it(value) }
    }
    fun observe(listener: (Boolean) -> Unit): AutoCloseable {
        listeners.add(listener)
        return AutoCloseable { listeners.remove(listener) }
    }
}
