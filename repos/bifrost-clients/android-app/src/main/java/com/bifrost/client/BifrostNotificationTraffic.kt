package com.bifrost.client

import java.util.Locale

/** Small background snapshot; independent from visible charts and their allocations. */
internal data class BifrostTrafficRate(val down: Long, val up: Long, val at: Long) {
    fun fresh(now: Long): Boolean = at > 0L && now - at in 0..5_000L
}

internal class BifrostNotificationTraffic {
    @Volatile var latest = BifrostTrafficRate(0, 0, 0)
        private set
    fun accept(down: Long, up: Long, at: Long, available: Boolean) {
        latest = if (available) BifrostTrafficRate(down.coerceAtLeast(0), up.coerceAtLeast(0), at)
            else BifrostTrafficRate(0, 0, 0)
    }
    fun reset() { latest = BifrostTrafficRate(0, 0, 0) }
    fun text(now: Long): String {
        return lines(now).joinToString("\n")
    }
    fun lines(now: Long): List<String> {
        val sample = latest
        if (!sample.fresh(now)) return listOf("\u2191 --", "\u2193 --")
        return listOf("\u2191 " + format(sample.up), "\u2193 " + format(sample.down))
    }
    companion object {
        fun format(bytes: Long): String {
            val value = bytes.coerceAtLeast(0)
            return when {
                value < 1024 -> "$value B/s"
                value < 1024 * 1024 -> String.format(Locale.ROOT, "%.1f KB/s", value / 1024.0)
                else -> String.format(Locale.ROOT, "%.1f MB/s", value / (1024.0 * 1024.0))
            }
        }
    }
}
