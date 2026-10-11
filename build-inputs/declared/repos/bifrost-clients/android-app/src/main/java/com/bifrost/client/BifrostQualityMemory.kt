package com.bifrost.client

/** Small process-local cache; another network or configuration cannot reuse it. */
internal object BifrostQualityMemory {
    data class Entry(val tag: String? = null, val rate: Double = 0.0, val measuredAt: Long = 0,
        val nextMeteredAt: Long = 0)
    private val entries = LinkedHashMap<String, Entry>()
    private const val MAX_AGE = 20 * 60_000L
    @Synchronized fun read(key: String, now: Long): Entry? = entries[key]?.let { entry ->
        if (now - entry.measuredAt in 0..MAX_AGE) entry
        else if (entry.nextMeteredAt > now) entry.copy(tag = null, rate = 0.0) else null
    }
    @Synchronized fun remember(key: String, tag: String, rate: Double, now: Long) {
        if (!rate.isFinite() || rate <= 0) return
        entries[key] = Entry(tag, rate, now, entries[key]?.nextMeteredAt ?: 0)
        trim()
    }
    @Synchronized fun deferMetered(key: String, until: Long) {
        entries[key] = (entries[key] ?: Entry()).copy(nextMeteredAt = until)
        trim()
    }
    @Synchronized fun forget(key: String) { entries.remove(key) }
    private fun trim() { while (entries.size > 8) entries.remove(entries.keys.first()) }
}

internal object BifrostUserTrafficLoad {
    fun rate(downlink: Long, uplink: Long, probeBodyBytes: Long): Double =
        (downlink.coerceAtLeast(0) - probeBodyBytes.coerceAtLeast(0)).coerceAtLeast(0).toDouble() + uplink.coerceAtLeast(0).toDouble()
    fun busy(downlink: Long, uplink: Long, probeBodyBytes: Long): Boolean =
        rate(downlink, uplink, probeBodyBytes) > BifrostQualityWorkPolicy.IDLE_RATE
}
