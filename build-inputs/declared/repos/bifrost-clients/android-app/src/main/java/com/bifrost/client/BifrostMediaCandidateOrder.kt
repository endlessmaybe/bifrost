package com.bifrost.client

/** Try responsive, healthy alternatives first; retain exploration afterwards. */
internal object BifrostMediaCandidateOrder {
    private const val PREFERRED_SEED_COUNT = 2
    fun challenger(measurements: List<BifrostMeasuredCandidate>, healthy: Set<String>, visited: Set<String>,
        incumbent: String, cursor: String, preferred: List<String> = emptyList()): String? {
        val unvisited = healthy - visited - incumbent
        // The signed order is only a cold-start hint.  A full stale provider
        // ranking must not hide the fresh measurements from this network.
        preferred.asSequence()
            .filter { it != incumbent }
            .distinct()
            .take(PREFERRED_SEED_COUNT)
            .firstOrNull { it in unvisited }
            ?.let { return it }
        val responsive = measurements.filter { it.tag in unvisited && it.delay in 1..65_535 }
            .sortedWith(compareBy<BifrostMeasuredCandidate> { it.delay }.thenBy { it.tag })
        // Eight responsive candidates cover the first comparisons. Every
        // fourth comparison explores the remainder so latency is not a gate.
        if (visited.size % 4 != 3) responsive.firstOrNull()?.let { return it.tag }
        return BifrostNodeQuality.cohort(unvisited, emptySet(), incumbent, cursor, 1).firstOrNull()
    }
}
