package com.bifrost.client


/** Measurements are local end-to-end transfers, never advertised server scores. */
internal data class BifrostQualitySample(val at: Long, val ok: Boolean, val latencyMs: Double,
    val bytesPerSecond: Double, val stallMs: Double)

internal class BifrostNodeQuality {
    private val history = mutableMapOf<String, MutableList<BifrostQualitySample>>()

    fun record(tag: String, sample: BifrostQualitySample) {
        val entries = history.getOrPut(tag) { mutableListOf() }
        entries.removeAll { sample.at - it.at !in 0..HISTORY_MS }
        entries.add(sample)
        while (entries.size > 8) entries.removeAt(0)
    }

    fun score(tag: String, now: Long): Double? {
        // A successful URLTest is required, but its duration does not cap eligibility.
        val samples = history[tag].orEmpty().takeLast(2)
        if (samples.size != 2 || samples.any { !it.ok || now - it.at !in 0..120_000 ||
            !it.latencyMs.isFinite() || it.latencyMs <= 0 ||
            !it.bytesPerSecond.isFinite() || it.bytesPerSecond <= 0 }) return null
        return samples.minOf { it.bytesPerSecond }
    }

    fun reliableScore(tag: String, now: Long, requiredSamples: Int): Double? {
        require(requiredSamples in 2..8)
        val samples = history[tag].orEmpty().takeLast(requiredSamples)
        if (samples.size != requiredSamples || samples.any { !it.ok || now - it.at !in 0..360_000 ||
            !it.latencyMs.isFinite() || it.latencyMs <= 0 ||
            !it.bytesPerSecond.isFinite() || it.bytesPerSecond <= 0 }) return null
        val speeds = samples.map { it.bytesPerSecond }.sorted()
        val worst = speeds.first()
        val median = speeds[speeds.size / 2]
        val average = speeds.average()
        return worst * 0.60 + median * 0.25 + average * 0.15
    }

    fun confirmReliableWinner(incumbent: String, challenger: String, now: Long,
        requiredSamples: Int = BifrostQualityTransport.LONG_FORM_PASSES): String? {
        val challengerScore = reliableScore(challenger, now, requiredSamples) ?: return null
        val incumbentScore = reliableScore(incumbent, now, requiredSamples)
        return if (incumbentScore == null || challengerScore > incumbentScore * 1.03) challenger else null
    }

    fun choose(allowed: Set<String>, healthy: Set<String>, incumbent: String?, now: Long): String? {
        val scored = allowed.intersect(healthy).mapNotNull { tag -> score(tag, now)?.let { tag to it } }
        val best = scored.sortedWith(compareByDescending<Pair<String, Double>> { it.second }.thenBy { it.first }).firstOrNull() ?: return null
        val confirmation = history[best.first].orEmpty().takeLast(2)
        if (confirmation.size < 2 || confirmation.any { !it.ok || now - it.at !in 0..120_000 }) return null
        if (incumbent == null || incumbent !in healthy) return best.first
        val failed = history[incumbent].orEmpty().takeLast(2).let { it.size == 2 && it.all { sample -> !sample.ok && now - sample.at in 0..120_000 } }
        val current = score(incumbent, now) ?: if (failed) 0.0 else return null
        // Both media transfers from the challenger must beat the incumbent's
        // faster sample. That conservative comparison is already the noise
        // guard and avoids retaining a slower path behind an extra margin.
        val baseline = if (failed) 0.0 else history[incumbent].orEmpty().takeLast(2).maxOf { it.bytesPerSecond }
        if (best.first == incumbent || best.second <= baseline) return null
        return best.first
    }
    companion object {
        // Shared anti-flap band for native automatic selection.
        const val AUTO_SELECT_TOLERANCE_MS = 50
        // Android URLTest measures the entire HTTPS request, including TCP,
        // TLS and server response time. A 300 ms TCP-style gate excludes fast
        // payload paths before any throughput sample can be collected.
        // This is the native delay field's valid range, not a latency target.
        const val MAX_RUNTIME_LATENCY_MS = 65_535
        fun runtime() = BifrostNodeQuality()
        fun hasSustainedDrop(samples: List<BifrostQualitySample>, baseline: Double): Boolean =
            samples.size == 2 && (samples.all { !it.ok } || baseline.isFinite() && baseline > 0 &&
                samples.all { it.ok && it.bytesPerSecond.isFinite() && it.bytesPerSecond > 0 && it.bytesPerSecond < baseline * 0.5 })
        fun continueDownload(bytes: Int, bodySeconds: Double): Boolean = bytes < 512 * 1024 && (bytes < 128 * 1024 || bodySeconds < 0.25)
        fun bodyGoodput(bytes: Int, warmupBytes: Int, bodySeconds: Double): Double {
            if (bytes <= warmupBytes || warmupBytes < 0 || !bodySeconds.isFinite() || bodySeconds <= 0) return 0.0
            return (bytes - warmupBytes) / maxOf(0.001, bodySeconds)
        }
        fun finalists(rates: Map<String, Double>, healthy: Set<String>, incumbent: String): List<String> =
            (listOf(incumbent) + rates.filter { it.key in healthy && it.value.isFinite() && it.value > 0 }.entries
                .sortedWith(compareByDescending<Map.Entry<String, Double>> { it.value }.thenBy { it.key }).take(8).map { it.key }).distinct()
        /** Strongest observed challengers for the end-of-sweep capacity
         * championship.  The incumbent is deliberately excluded: callers
         * compare every returned challenger against the current winner again
         * using heavier multi-stream samples. */
        fun roundFinalists(
            rates: Map<String, Double>,
            allowed: Set<String>,
            healthy: Set<String>,
            incumbent: String,
            count: Int,
        ): List<String> = rates.asSequence()
            .filter { (tag, rate) ->
                tag != incumbent && tag in allowed && tag in healthy && rate.isFinite() && rate > 0
            }
            .sortedWith(compareByDescending<Map.Entry<String, Double>> { it.value }.thenBy { it.key })
            .take(count.coerceAtLeast(0))
            .map { it.key }
            .toList()
        const val HISTORY_MS = 60 * 60 * 1000L
        // Pairwise exploration plus at most two 4-stream x 512 KiB x two-pass
        // finalist comparisons. This is a fixture bound; the persistent
        // Android Wi-Fi/mobile rolling budgets remain authoritative.
        fun maximumRoundPayloadBytes(nodes: Int): Long =
            nodes * 3L * 1024 * 1024 + 192L * 1024 * 1024
        fun cohort(eligible: Collection<String>, visited: Set<String>, incumbent: String, cursor: String, count: Int): List<String> =
            eligible.filter { it != incumbent && it !in visited }.distinct()
                .sortedWith(compareBy<String> { if (it > cursor) 0 else 1 }.thenBy { it }).take(count)
    }
}
