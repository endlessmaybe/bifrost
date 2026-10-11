package com.bifrost.client

/** A dead helper cannot accept BLOCK while the old core still owns its FD. */
internal object BifrostRootRecoverySequence {
    fun prepare(boundaryAlive: Boolean, block: () -> Unit, stopCore: () -> Unit) {
        if (boundaryAlive) block()
        // A failed stop must never be ignored: a second core cannot inherit
        // an FD still used by the first one.
        stopCore()
        if (!boundaryAlive) block()
    }
}
