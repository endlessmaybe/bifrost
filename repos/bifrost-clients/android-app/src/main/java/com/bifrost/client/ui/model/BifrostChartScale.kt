package com.bifrost.client.ui.model

import java.util.Locale
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.log10
import kotlin.math.pow

/** Shares the Windows chart's binary rate units and rounded vertical scale. */
internal object BifrostChartScale {
    fun maximum(values: List<Float>): Float {
        val peak = (values.filter { it.isFinite() }.maxOrNull() ?: 0f).coerceAtLeast(1024f).toDouble()
        val unit = if (peak >= 1024.0 * 1024) 1024.0 * 1024 else 1024.0
        val magnitude = 10.0.pow(floor(log10(peak / unit)))
        return (ceil(peak / unit / magnitude) * magnitude * unit).toFloat()
    }

    fun rate(bytesPerSecond: Float): String {
        var value = if (bytesPerSecond.isFinite()) bytesPerSecond.coerceAtLeast(0f).toDouble() else 0.0
        val units = arrayOf("B/s", "KB/s", "MB/s", "GB/s")
        var index = 0
        while (value >= 1024 && index < units.lastIndex) { value /= 1024; index++ }
        val number = String.format(Locale.ROOT, "%.1f", value).removeSuffix(".0")
        return "$number ${units[index]}"
    }
}
