package com.bifrost.client

/**
 * Startup/pre-connect update gate.  An unavailable control plane is an
 * explicit outcome; it can never replace or mutate the verified LKG.
 */
internal data class BifrostOfflineUpdateResult(
    val outcome: String,
    val version: Long,
    val digest: String,
    val contentDigest: String,
)

internal class BifrostOfflineUpdateCoordinator<T>(
    private val readStable: () -> T?,
    private val identity: (T) -> Triple<Long, String, String>,
) {
    fun run(update: () -> Unit): BifrostOfflineUpdateResult {
        val before = readStable() ?: throw IllegalStateException("BF-CONFIG-CACHE-MISSING")
        val beforeId = identity(before)
        runCatching { update() }
        val after = readStable() ?: throw IllegalStateException("BF-CONFIG-LKG-LOST")
        val afterId = identity(after)
        check(beforeId == afterId) { "BF-CONFIG-OFFLINE-MUTATED" }
        return BifrostOfflineUpdateResult("offline", beforeId.first, beforeId.second, beforeId.third)
    }
}
