package com.bifrost.client

/** Pure release authority transition used by the updater and JVM fixtures. */
internal object ReleaseStateMachine {
    data class State(val sequence: Long, val manifestDigest: String, val authorityGeneration: Long = 1, val authorityDigest: String = "0".repeat(64), val signingKeyFingerprint: String = "0".repeat(64))
    data class Incoming(val sequence: Long, val manifestDigest: String, val floor: Long, val authorityGeneration: Long = 1, val authorityDigest: String = "0".repeat(64), val signingKeyFingerprint: String = "0".repeat(64))

    fun classify(current: State?, incoming: Incoming): String {
        check(incoming.sequence >= 1 && incoming.floor >= 1 && incoming.manifestDigest.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-STATE" }
        check(incoming.authorityGeneration >= 1 && incoming.authorityDigest.matches(Regex("[0-9a-f]{64}")) && incoming.signingKeyFingerprint.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-AUTHORITY" }
        if (current == null) return "first-install"
        check(current.sequence >= 0 && current.manifestDigest.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-STATE" }
        check(current.authorityGeneration >= 1 && current.authorityDigest.matches(Regex("[0-9a-f]{64}")) && current.signingKeyFingerprint.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-AUTHORITY" }
        if (incoming.sequence < current.sequence || incoming.sequence < incoming.floor) return "rollback"
        if (incoming.authorityGeneration < current.authorityGeneration) return "authority-rollback"
        if (incoming.authorityGeneration == current.authorityGeneration && (incoming.authorityDigest != current.authorityDigest || incoming.signingKeyFingerprint != current.signingKeyFingerprint)) return "authority-equivocation"
        if (incoming.sequence == current.sequence) return if (incoming.manifestDigest == current.manifestDigest && incoming.authorityGeneration == current.authorityGeneration) "idempotent" else "equivocation"
        return "advance"
    }
}
