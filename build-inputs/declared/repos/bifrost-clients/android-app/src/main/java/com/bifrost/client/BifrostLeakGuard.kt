package com.bifrost.client

/**
 * Local, side-effect-free safety state for the Android data plane.  The
 * operating system's Always-on VPN + "block connections without VPN" mode is
 * the only strict leak boundary.  The service attempts a Bifrost-owned
 * blackhole TUN on core failure; BLOCKING is reported only after establish
 * succeeds, otherwise the state is explicitly UNPROTECTED.
 */
enum class BifrostLeakState { STOPPED, STARTING, HEALTHY, BLOCKING, UNPROTECTED, ERROR }

data class BifrostLeakSnapshot(
    val state: BifrostLeakState,
    val lockdownEvidence: Boolean,
) {
    val strictProtection: Boolean get() = state == BifrostLeakState.HEALTHY && lockdownEvidence
    val shouldBlock: Boolean get() = state == BifrostLeakState.BLOCKING
}

object BifrostLeakGuard {
    fun starting(lockdownEvidence: Boolean = false) = BifrostLeakSnapshot(BifrostLeakState.STARTING, lockdownEvidence)
    fun healthy(lockdownEvidence: Boolean) = BifrostLeakSnapshot(BifrostLeakState.HEALTHY, lockdownEvidence)
    fun blocking(lockdownEvidence: Boolean = false) = BifrostLeakSnapshot(BifrostLeakState.BLOCKING, lockdownEvidence)
    fun unprotected(lockdownEvidence: Boolean = false) = BifrostLeakSnapshot(BifrostLeakState.UNPROTECTED, lockdownEvidence)
    @Deprecated("Use unprotected or blocking based on actual blackhole establish result")
    fun coreFailure(lockdownEvidence: Boolean = false) = unprotected(lockdownEvidence)
    fun stopped(lockdownEvidence: Boolean = false) = BifrostLeakSnapshot(BifrostLeakState.STOPPED, lockdownEvidence)
}
