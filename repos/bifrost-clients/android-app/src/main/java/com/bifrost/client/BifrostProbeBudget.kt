package com.bifrost.client

/** Rolling payload reservations survive selector recreation. Failed or cancelled
 * probes remain charged, so retrying cannot manufacture a fresh allowance. */
internal class BifrostProbeBudget(
    private val read: (() -> List<Entry>)? = null,
    private val write: ((List<Entry>) -> Unit)? = null,
) {
    data class Entry(val at: Long, val bytes: Long, val metered: Boolean)
    private var entries = emptyList<Entry>()
    @Synchronized fun reserve(now: Long, bytes: Long, metered: Boolean, keepHealthReserve: Boolean): Boolean {
        entries = (read?.invoke() ?: entries).filter { now - it.at < WINDOW_MS }
        if (bytes <= 0) return false
        val reserve = if (keepHealthReserve) 256 * 1024L else 0L
        if (entries.sumOf { it.bytes } + bytes > WIFI_BYTES - reserve ||
            metered && entries.filter { it.metered }.sumOf { it.bytes } + bytes > MOBILE_BYTES - reserve) return false
        val next = entries + Entry(now, bytes, metered)
        // Persist before permitting a download. I/O failures deny the probe.
        try { write?.invoke(next) } catch (_: Exception) { return false }
        entries = next
        return true
    }
    @Synchronized fun retryDelay(now: Long): Long =
        entries.minOfOrNull { (it.at + WINDOW_MS - now).coerceAtLeast(1) } ?: WINDOW_MS
    companion object {
        // Performance policy parity with Windows. Foreground traffic still
        // cancels diagnostic measurements immediately.
        const val WINDOW_MS = 5 * 60_000L
        // Cellular keeps a separate hard cap while still allowing a large
        // provider sweep to make meaningful progress between foreground bursts.
        const val MOBILE_BYTES = 512L * 1024 * 1024
        const val WIFI_BYTES = 768L * 1024 * 1024
    }
}
