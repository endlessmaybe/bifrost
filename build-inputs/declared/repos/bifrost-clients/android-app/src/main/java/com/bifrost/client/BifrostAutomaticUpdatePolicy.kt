package com.bifrost.client

internal object BifrostAutomaticUpdatePolicy {
    fun idle(interactive: Boolean, state: BifrostLeakState, hasOwner: Boolean, installing: Boolean,
        now: Long, traffic: BifrostTrafficRate, runningMillis: Long, lastTrafficAt: Long): Boolean {
        if (interactive || installing) return false
        if (state == BifrostLeakState.STOPPED && !hasOwner) return true
        return state == BifrostLeakState.HEALTHY && hasOwner && traffic.fresh(now) &&
            traffic.down < 1024 && traffic.up < 1024 && traffic.down + traffic.up < 1024 &&
            runningMillis >= 180_000 && lastTrafficAt <= now && now - lastTrafficAt >= 180_000
    }
}
