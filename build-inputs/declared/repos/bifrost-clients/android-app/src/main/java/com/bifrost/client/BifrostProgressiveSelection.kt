package com.bifrost.client

import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OutboundGroupIterator
import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal data class BifrostMeasuredCandidate(val tag: String, val delay: Int, val measuredAt: Long)

internal object BifrostProgressiveSelection {
    fun best(allowed: Set<String>, candidates: List<BifrostMeasuredCandidate>, nowSeconds: Long): String? =
        candidates.asSequence().filter {
            it.tag in allowed && it.delay in 1..65535 && it.measuredAt > 0 &&
                nowSeconds - it.measuredAt in 0..(20 * 60)
        }.minWithOrNull(compareBy<BifrostMeasuredCandidate> { it.delay }.thenBy { it.tag })?.tag

    fun latencyWindow(
        allowed: Set<String>,
        candidates: List<BifrostMeasuredCandidate>,
        nowSeconds: Long,
    ): Set<String> {
        val fresh = candidates.filter {
            it.tag in allowed && it.delay in 1..65535 && it.measuredAt > 0 &&
                nowSeconds - it.measuredAt in 0..(20 * 60)
        }
        val floor = fresh.minOfOrNull { it.delay } ?: return emptySet()
        return fresh.filter { it.delay <= floor + BifrostNodeQuality.AUTO_SELECT_TOLERANCE_MS }
            .mapTo(linkedSetOf()) { it.tag }
    }

    /** Throughput qualification must not inherit URLTest's anti-flap RTT band.
     * A slightly higher-latency path can have much more sustained bandwidth;
     * require only a fresh successful native health result here. */
    fun throughputEligible(
        allowed: Set<String>,
        candidates: List<BifrostMeasuredCandidate>,
        nowSeconds: Long,
    ): Set<String> = candidates.asSequence().filter {
        it.tag in allowed && it.delay in 1..BifrostNodeQuality.MAX_RUNTIME_LATENCY_MS &&
            it.measuredAt > 0 && nowSeconds - it.measuredAt in 0..(20 * 60)
    }.mapTo(linkedSetOf()) { it.tag }

    fun stableBest(
        allowed: Set<String>,
        candidates: List<BifrostMeasuredCandidate>,
        nowSeconds: Long,
        current: String?,
    ): String? {
        val eligible = latencyWindow(allowed, candidates, nowSeconds)
        if (eligible.isEmpty()) return null
        if (current != null && current in eligible) return current
        return best(eligible, candidates, nowSeconds)
    }
}

/** Selects only leaves from the running, verified configuration. Native URLTest
 * probes continue in bounded cohorts; selection never reloads the core or TUN. */
internal class BifrostProgressiveSelector(
    config: String,
    private val selectOutbound: (String, String) -> Unit = { group, tag -> Libbox.newStandaloneCommandClient().selectOutbound(group, tag) },
    private val requestUrlTest: (String) -> Unit = { tag -> Libbox.newStandaloneCommandClient().urlTest(tag) },
    private val measureSample: ((Int) -> BifrostQualitySample)? = null,
    private val measureCapacitySample: ((Int, Int) -> BifrostQualitySample)? = null,
    private val measureLongSample: ((Int) -> BifrostQualitySample)? = null,
    private val clock: () -> Long = System::currentTimeMillis,
    private val pause: (Long) -> Unit = Thread::sleep,
    schedule: Boolean = true,
    // Throughput qualification is a connection responsibility, not a UI
    // visibility feature. Keeping it tied to the foreground app left a slow
    // latency winner in place whenever the user closed the Bifrost screen.
    private val automaticWorkAllowed: () -> Boolean = { true },
    private val recoveryWorkAllowed: () -> Boolean = { true },
    private val elapsedClock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val reportDiagnostic: (String) -> Unit = {},
    private val cancelSample: (() -> Unit)? = null,
    probeBudget: BifrostProbeBudget = BifrostProbeBudget(),
) : Closeable {
    private val lock = Any()
    @Volatile private var closed = false
    private val selected = mutableMapOf<String, String>()
    private var quality = BifrostNodeQuality.runtime()
    @Volatile private var network = ""
    private val transport = BifrostQualityTransport.fromConfig(JSONObject(config))
    private val profileFingerprint = JSONObject(config).getJSONArray("outbounds").let { outbounds ->
        val leaves = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
            .filter { it.optString("type") !in setOf("selector", "urltest") }.joinToString("\n")
        java.security.MessageDigest.getInstance("SHA-256").digest(leaves.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    private fun memoryKey(): String? = network.takeIf { it.isNotEmpty() }?.let { "$it/$profileFingerprint" }
    private fun remember(tag: String, now: Long) {
        val rate = quality.score(tag, now) ?: return
        memoryKey()?.let { BifrostQualityMemory.remember(it, tag, rate, now) }
    }
    fun takeProbeBodyBytes(): Long = transport?.takeReceivedBodyBytes() ?: 0L
    private var latest = emptyList<BifrostMeasuredCandidate>()
    private var lastDiagnostic = ""
    private var exploration = ""
    @Volatile internal var nextQualityAt = 0L
    private var confirmedCandidate: String? = null
    private var confirmedBytesPerSecond = 0.0
    private var lastQualityCheckAt = 0L
    @Volatile var busy = false
    @Volatile var userBytesPerSecond = 0.0
    @Volatile var metered = true
    @Volatile private var measuringRecovery = false
    fun updateUserTraffic(rate: Double) {
        workPolicy.observe(elapsedClock(), rate)
        userBytesPerSecond = rate
        busy = !rate.isFinite() || rate > BifrostQualityWorkPolicy.IDLE_RATE
        // Cancel the in-flight socket as soon as user traffic resumes, rather
        // than waiting up to six seconds for a diagnostic transfer to finish.
        if (!BifrostQualityWorkPolicy.canContinue(rate, measuringRecovery)) {
            transport?.cancelActive()
            cancelSample?.invoke()
        }
    }
    private val workPolicy = BifrostQualityWorkPolicy(probeBudget)
    private val failureRecovery = BifrostFailureRecovery()
    fun observeTransportFailure(message: String) { failureRecovery.observe(elapsedClock(), message) }
    private val visited = mutableSetOf<String>()
    private val roundObservedRates = mutableMapOf<String, Double>()
    private var initialQualityRounds = 0
    @Volatile private var roundCompleted = false
    internal val completedQualityRound: Boolean get() = roundCompleted
    private var pendingFinalization = false
    private var lastFullSweepAt = 0L
    private var incompleteAttempts = 0
    private var budgetPausedUntil = 0L
    private val recentlyLeft = mutableMapOf<String, Long>()
    private var measurementFloorSeconds = 0L
    private var networkGeneration = 0L
    fun networkChanged(fingerprint: String) = synchronized(lock) {
        if (closed || network == fingerprint) return@synchronized
        val changed = network.isNotEmpty()
        network = fingerprint
        networkGeneration++
        failureRecovery.networkChanged(elapsedClock())
        workPolicy.resetActivity()
        if (changed) {
            quality = BifrostNodeQuality.runtime(); latest = emptyList(); visited.clear(); roundObservedRates.clear()
            // Cached native RTTs belong to the old access network. Keep the
            // native connection alive while requiring fresh results to pick
            // the new network's candidate, including for the front selector.
            selected.clear()
            measurementFloorSeconds = clock() / 1000 + 1
            nextQualityAt = 0
            confirmedCandidate = null; confirmedBytesPerSecond = 0.0; lastQualityCheckAt = 0
            initialQualityRounds = 0
            roundCompleted = false; pendingFinalization = false; lastFullSweepAt = 0L
            incompleteAttempts = 0; recentlyLeft.clear()
            runCatching { worker.schedule({ refresh() }, 1200, TimeUnit.MILLISECONDS) }
        }

    }
    private val preferredOrder: Map<String, List<String>> = buildMap {
        val outbounds = JSONObject(config).getJSONArray("outbounds")
        for (index in 0 until outbounds.length()) {
            val group = outbounds.getJSONObject(index)
            val tag = group.optString("tag")
            if (tag !in setOf("proxy", "front-vmess") || group.optString("type") != "selector") continue
            val list = group.optJSONArray("outbounds") ?: continue
            val tags = (0 until list.length()).map { list.getString(it) }
            if ("$tag-auto" in tags) put(tag, tags.filter { it.startsWith("$tag-candidate-") })
        }
    }
    private val roots: Map<String, Set<String>> = preferredOrder.mapValues { it.value.toSet() }
    val automaticSelection: Boolean get() = roots["proxy"]?.isNotEmpty() == true
    private val worker = Executors.newSingleThreadScheduledExecutor { work ->
        Thread(work, "bifrost-progressive-selection").apply { isDaemon = true }
    }
    private val qualityWorker = Executors.newSingleThreadScheduledExecutor { Thread(it, "bifrost-quality").apply { isDaemon = true } }
    init {
        if (schedule) qualityWorker.scheduleWithFixedDelay({
            runCatching { optimize() }.onFailure {
                diagnostic("round=retry reason=operation-failed")
            }
        }, 350, 1_000, TimeUnit.MILLISECONDS)
    }
    fun accept(groups: OutboundGroupIterator) {
        while (groups.hasNext()) {
            val group = groups.next() ?: continue
            val root = roots.keys.firstOrNull { group.tag == "$it-auto" } ?: continue
            val measurements = mutableListOf<BifrostMeasuredCandidate>()
            val items = group.getItems()
            while (items.hasNext()) {
                val item = items.next() ?: continue
                measurements.add(BifrostMeasuredCandidate(item.tag, item.getURLTestDelay(), item.getURLTestTime()))
            }
            acceptMeasurements(root, measurements)
        }
    }
    internal fun acceptMeasurements(root: String, received: List<BifrostMeasuredCandidate>) {
        if (root !in roots) return
        val now = clock() / 1000
        synchronized(lock) {
                val measurements = received.filter { it.measuredAt >= measurementFloorSeconds }
                val diagnostic = "group=$root total=${measurements.size} positive=${measurements.count { it.delay in 1..65535 }} fresh=${measurements.count { now - it.measuredAt in 0..1200 }}"
                if (diagnostic != lastDiagnostic) {
                    lastDiagnostic = diagnostic
                    runCatching { android.util.Log.i("BifrostSelectionDiagnostic", diagnostic) }
                }
                if (root == "proxy") latest = measurements
                val current = selected[root]
                val healthyCandidates = BifrostProgressiveSelection.throughputEligible(roots.getValue(root), measurements, now)
                val remembered = if (root == "proxy") {
                    memoryKey()?.let { BifrostQualityMemory.read(it, clock()) }?.tag?.takeIf { it in healthyCandidates }
                } else null
                // Native latency reports are liveness evidence, not authority
                // to move an active connection to an unmeasured payload path.
                // The quality worker owns healthy proxy handovers.
                val best = if (root == "proxy" && current != null && current in healthyCandidates) current
                    else if (current == null && remembered != null) remembered
                    else BifrostProgressiveSelection.stableBest(roots.getValue(root), measurements, now, current)
                        ?: return@synchronized
                if (closed || current == best) return@synchronized
                val generation = networkGeneration
                runCatching { worker.execute {
                    synchronized(lock) {
                        if (!closed && networkGeneration == generation && selected[root] == current) runCatching {
                            // Pin the actual proxy leaf. Keeping proxy-auto
                            // selected lets URLTest change the real route
                            // while our quality worker still believes the
                            // previous leaf is the incumbent.
                            selectOutbound(root, if (root == "proxy") best else "$root-auto")
                            selected[root] = best
                            if (root == "proxy" && current == null && remembered != null) confirmedCandidate = best
                            runCatching { android.util.Log.i("BifrostSelectionDiagnostic", "group=$root selected=true") }
                        }
                    }
                } }
        }
    }
    private fun userRate(): Double = if (busy && userBytesPerSecond == 0.0) Double.NaN else userBytesPerSecond
    private fun canMeasure(roundNetwork: String, incumbent: String, recovery: Boolean): Boolean =
        !closed && !Thread.currentThread().isInterrupted && network == roundNetwork &&
            (if (recovery) recoveryWorkAllowed() else automaticWorkAllowed()) &&
            BifrostQualityWorkPolicy.canContinue(userRate(), recovery) &&
            synchronized(lock) { selected["proxy"] == incumbent }

    internal fun optimize() {
        val measure = measureSample ?: transport?.let { transfer -> { bytes: Int -> transfer.measure(bytes) } } ?: return
        val measureLong = measureLongSample ?: transport?.let { transfer -> { pass: Int -> transfer.measureLong(pass) } } ?: return
        if (closed || Thread.currentThread().isInterrupted) return
        val now = clock()
        val roundNetwork = network
        if (now < budgetPausedUntil) return
        val failedTraffic = failureRecovery.claim(elapsedClock(), userRate(), recoveryWorkAllowed())
        val recovery = if (failedTraffic) true else
            workPolicy.admit(elapsedClock(), userRate(), automaticWorkAllowed(), recoveryWorkAllowed()) ?: return
        if (recovery) diagnostic("round=recovery-requested reason=${if (failedTraffic) "repeated-transport-failure" else "slow-traffic"}")
        measuringRecovery = recovery
        // A completed sweep keeps its winner. Recheck it on the same two-minute
        // cadence as Windows and reopen full exploration at least hourly even
        // when it is still healthy, because edge capacity can drift without a
        // hard failure.
        if (now < nextQualityAt && !recovery) return
        transport?.allowAdaptiveDownload = false
        if (roundCompleted && !recovery) {
            val incumbent = synchronized(lock) { selected["proxy"] }
            val baseline = confirmedBytesPerSecond
            if (incumbent != null && incumbent == confirmedCandidate && baseline > 0) {
                if (!reserveProbe(2L * BifrostQualityTransport.STABLE_RECHECK_BYTES)) return
                val samples = mutableListOf<BifrostQualitySample>()
                repeat(2) {
                    if (!canMeasure(roundNetwork, incumbent, false)) return
                    synchronized(lock) {
                        if (!canMeasure(roundNetwork, incumbent, false)) return
                        selectOutbound(BifrostQualityTransport.GROUP, incumbent)
                    }
                    samples += measure(BifrostQualityTransport.STABLE_RECHECK_BYTES)
                    if (!canMeasure(roundNetwork, incumbent, false)) return
                }
                lastQualityCheckAt = clock()
                if (!BifrostNodeQuality.hasSustainedDrop(samples, baseline)) {
                    val fullSweepDue = lastFullSweepAt <= 0L ||
                        clock() - lastFullSweepAt >= BifrostMaintenancePolicy.FULL_SWEEP_INTERVAL_MS
                    if (!fullSweepDue) {
                        nextQualityAt = clock() + if (metered) BifrostMaintenancePolicy.METERED_QUALITY_INTERVAL_MS
                            else BifrostMaintenancePolicy.QUALITY_INTERVAL_MS
                        return
                    }
                    diagnostic("round=scheduled-full-sweep")
                } else {
                    diagnostic("round=recheck-drop")
                }
            }
            synchronized(lock) {
                visited.clear(); roundObservedRates.clear(); pendingFinalization = false; roundCompleted = false
            }
        }
        var started = false
        var completed = false
        var qualifiedCompletion = false
        var sampled = false
        var failedAttempt = false
        try {
            // If the pairwise sweep already covered the catalogue but the
            // heavier championship was deferred by foreground traffic or the
            // rolling byte budget, resume exactly there instead of rescanning
            // every candidate from the beginning.
            if (pendingFinalization) {
                if (recovery) return
                started = true; completed = true; sampled = true
                qualifiedCompletion = finalizeSweep(roundNetwork, measureLong)
                return
            }
            val snapshot = synchronized(lock) {
                val allowed = roots["proxy"] ?: return
                val incumbent = selected["proxy"] ?: return
                val nowSeconds = clock() / 1000
                val healthy = latest.filter {
                    it.tag in allowed &&
                        it.delay in 1..BifrostNodeQuality.MAX_RUNTIME_LATENCY_MS &&
                        nowSeconds - it.measuredAt in 0..1200
                }.map { it.tag }.toSet()
                if (healthy.size < minOf(2, allowed.size)) {
                    started = true; failedAttempt = true
                    runCatching { worker.execute { refresh() } }
                    return
                }
                if (healthy.all { it in visited }) visited.clear()
                val challenger = BifrostMediaCandidateOrder.challenger(latest, healthy, visited, incumbent, exploration,
                    preferredOrder["proxy"].orEmpty())
                Triple(allowed, incumbent, listOfNotNull(incumbent, challenger).distinct())
            }
            if (!reserveProbe(snapshot.third.size * 2L * BifrostQualityTransport.BYTES)) return
            started = true
            val incumbent = snapshot.second
            val measured = BifrostNodeQuality.runtime()
            fun measurePair(target: BifrostNodeQuality, tags: List<String>, bytes: Int): Boolean {
                for (tag in tags) repeat(2) {
                    if (!canMeasure(roundNetwork, incumbent, recovery)) return false
                    synchronized(lock) {
                        if (!canMeasure(roundNetwork, incumbent, recovery)) return false
                        selectOutbound(BifrostQualityTransport.GROUP, tag)
                    }
                    val result = measure(bytes)
                    if (!canMeasure(roundNetwork, incumbent, recovery)) return false
                    val delay = synchronized(lock) { latest.firstOrNull { it.tag == tag }?.delay ?: 0 }
                    target.record(tag, result.copy(latencyMs = delay.toDouble()))
                }
                return true
            }
            if (!measurePair(measured, snapshot.third, BifrostQualityTransport.BYTES)) return
            sampled = true
            fun healthy(): Set<String> {
                val nowSeconds = clock() / 1000
                return latest.filter {
                    it.tag in snapshot.first &&
                        it.delay in 1..BifrostNodeQuality.MAX_RUNTIME_LATENCY_MS &&
                        nowSeconds - it.measuredAt in 0..1200
                }.map { it.tag }.toSet()
            }
            fun promotionEligible() =
                BifrostProgressiveSelection.throughputEligible(snapshot.first, latest, clock() / 1000)
            var checked = measured
            var winner = synchronized(lock) { measured.choose(snapshot.third.toSet(), promotionEligible(), incumbent, clock()) }
            // Do not bounce back to an exit left within ten minutes unless the
            // current exit has repeatedly failed real transfers.
            if (winner != null && (recentlyLeft[winner] ?: 0L) > elapsedClock() && !(failedTraffic && measured.score(incumbent, clock()) == null)) winner = null
            if (winner != null) {
                val confirmation = BifrostNodeQuality.runtime()
                val candidates = listOf(incumbent, winner!!)
                val longBytes = candidates.size.toLong() * BifrostQualityTransport.LONG_FORM_PASSES *
                    BifrostQualityTransport.LONG_FORM_BYTES
                if (!reserveProbe(longBytes)) return
                for (pass in 0 until BifrostQualityTransport.LONG_FORM_PASSES) for (tag in candidates) {
                    if (!canMeasure(roundNetwork, incumbent, recovery)) return
                    synchronized(lock) {
                        if (!canMeasure(roundNetwork, incumbent, recovery)) return
                        selectOutbound(BifrostQualityTransport.GROUP, tag)
                    }
                    val result = measureLong(pass)
                    if (!canMeasure(roundNetwork, incumbent, recovery)) return
                    val delay = synchronized(lock) { latest.firstOrNull { it.tag == tag }?.delay ?: 0 }
                    confirmation.record(tag, result.copy(latencyMs = delay.toDouble()))
                }
                val confirmed = synchronized(lock) {
                    confirmation.confirmReliableWinner(incumbent, winner!!, clock())
                }
                if (confirmed != winner) {
                    winner = null
                    diagnostic("round=retained reason=long-form-unconfirmed")
                }
                checked = confirmation
            }
            synchronized(lock) {
                if (!canMeasure(roundNetwork, incumbent, recovery)) return
                winner?.let {
                    selectOutbound("proxy", it)
                    recentlyLeft[incumbent] = elapsedClock() + 10 * 60_000L
                    selected["proxy"] = it
                    diagnostic("round=promoted full-body-confirmed=true")
                }
                quality = checked
                val current = selected["proxy"] ?: return
                val rate = checked.score(current, clock())
                snapshot.third.distinct().forEach { tag ->
                    checked.score(tag, clock())?.takeIf { it.isFinite() && it > 0 }?.let { observed ->
                        val previous = roundObservedRates[tag]
                        if (previous == null || observed > previous) roundObservedRates[tag] = observed
                    }
                }
                if (rate != null && rate > 0) {
                    confirmedCandidate = current; confirmedBytesPerSecond = rate; lastQualityCheckAt = clock()
                }
                visited.addAll(snapshot.third)
                snapshot.third.lastOrNull { it != incumbent }?.let { exploration = it }
                completed = healthy().all { it in visited }
                pendingFinalization = completed && rate != null
                diagnostic("round=${if (pendingFinalization) "finalists-pending" else if (completed) "retry-unqualified" else "progress"} sampled=${visited.size} recovery=$recovery")
            }
            if (pendingFinalization && !recovery) qualifiedCompletion = finalizeSweep(roundNetwork, measureLong)
        } catch (error: Exception) {
            failedAttempt = true
            throw error
        } finally {
            if (started && !closed && network == roundNetwork) {
                if (sampled) {
                    initialQualityRounds++
                    if (completed && !qualifiedCompletion) incompleteAttempts++ else incompleteAttempts = 0
                }
                else if (failedAttempt) incompleteAttempts++
                val retryDelay = if (failedAttempt || completed && !qualifiedCompletion) {
                    val exponent = (incompleteAttempts - 1).coerceIn(0, 6)
                    (2_000L shl exponent).coerceAtMost(120_000L)
                } else 2_000L
                nextQualityAt = maxOf(budgetPausedUntil, clock() + when {
                    completed && roundCompleted -> if (metered) BifrostMaintenancePolicy.METERED_QUALITY_INTERVAL_MS
                        else BifrostMaintenancePolicy.QUALITY_INTERVAL_MS
                    !sampled -> retryDelay
                    else -> 2_000L
                })
            }
        }
    }

    private fun finalizeSweep(
        roundNetwork: String,
        measureLong: (Int) -> BifrostQualitySample,
    ): Boolean {
        val allowed = roots["proxy"] ?: return false
        var incumbent = synchronized(lock) { selected["proxy"] } ?: return false
        var confirmedRate = synchronized(lock) { roundObservedRates[incumbent] ?: confirmedBytesPerSecond }
        val healthyAtStart = synchronized(lock) {
            BifrostProgressiveSelection.throughputEligible(allowed, latest, clock() / 1000)
        }
        val finalists = synchronized(lock) {
            BifrostNodeQuality.roundFinalists(roundObservedRates.toMap(), allowed, healthyAtStart,
                incumbent, END_OF_SWEEP_FINALIST_COUNT)
        }
        for (challenger in finalists) {
            if (!canMeasure(roundNetwork, incumbent, false)) return false
            val healthy = synchronized(lock) {
                BifrostProgressiveSelection.throughputEligible(allowed, latest, clock() / 1000)
            }
            if (incumbent !in healthy || challenger !in healthy) {
                diagnostic("round=finalist-unavailable")
                continue
            }
            val tags = listOf(incumbent, challenger)
            val bytes = tags.size.toLong() * BifrostQualityTransport.LONG_FORM_PASSES *
                BifrostQualityTransport.LONG_FORM_BYTES
            if (!reserveProbe(bytes)) return false
            val confirmation = BifrostNodeQuality.runtime()
            for (pass in 0 until BifrostQualityTransport.LONG_FORM_PASSES) for (tag in tags) {
                if (!canMeasure(roundNetwork, incumbent, false)) return false
                synchronized(lock) {
                    if (!canMeasure(roundNetwork, incumbent, false)) return false
                    selectOutbound(BifrostQualityTransport.GROUP, tag)
                }
                val result = measureLong(pass)
                if (!canMeasure(roundNetwork, incumbent, false)) return false
                val delay = synchronized(lock) { latest.firstOrNull { it.tag == tag }?.delay ?: 0 }
                confirmation.record(tag, result.copy(latencyMs = delay.toDouble()))
            }
            synchronized(lock) {
                if (!canMeasure(roundNetwork, incumbent, false)) return false
                val eligible = BifrostProgressiveSelection.throughputEligible(allowed, latest, clock() / 1000)
                val winner = if (challenger in eligible) confirmation.confirmReliableWinner(incumbent, challenger, clock()) else null
                quality = confirmation
                if (winner == challenger) {
                    selectOutbound("proxy", challenger)
                    recentlyLeft[incumbent] = elapsedClock() + 10 * 60_000L
                    selected["proxy"] = challenger
                    incumbent = challenger
                    // Capacity samples decide the championship, but keep the
                    // ordinary single-stream round rate as the later drop
                    // baseline. Comparing a four-stream aggregate directly
                    // with the two-minute single-stream recheck would create a
                    // false "50% drop" and waste probe traffic every cycle.
                    confirmedRate = roundObservedRates[challenger] ?: confirmedRate
                    diagnostic("round=finalist-promoted long-form-passes=${BifrostQualityTransport.LONG_FORM_PASSES}")
                } else {
                    confirmedRate = roundObservedRates[incumbent] ?: confirmedRate
                    diagnostic("round=finalist-retained")
                }
            }
        }
        synchronized(lock) {
            if (network != roundNetwork || selected["proxy"] != incumbent ||
                !confirmedRate.isFinite() || confirmedRate <= 0) return false
            confirmedCandidate = incumbent
            confirmedBytesPerSecond = confirmedRate
            lastQualityCheckAt = clock()
            roundCompleted = true
            pendingFinalization = false
            lastFullSweepAt = clock()
            roundObservedRates.clear()
            remember(incumbent, clock())
        }
        diagnostic("round=completed long-form-reliability=true")
        return true
    }

    private companion object {
        const val END_OF_SWEEP_FINALIST_COUNT = 4
    }

    private fun reserveProbe(bytes: Long): Boolean {
        if (workPolicy.reserve(clock(), bytes, keepHealthReserve = true, metered = metered)) return true
        nextQualityAt = clock() + workPolicy.retryDelay(clock()).coerceAtLeast(5 * 60_000L)
        budgetPausedUntil = nextQualityAt
        diagnostic("round=paused reason=probe-budget")
        return false
    }

    private fun diagnostic(message: String) {
        runCatching { android.util.Log.i("BifrostSelectionDiagnostic", message) }
        runCatching { reportDiagnostic(message) }
    }
    fun refresh() {
        // Do not hold the measurement lock across native IPC: URLTest may
        // complete asynchronously while group callbacks deliver its results.
        if (!closed) roots.keys.forEach { root -> requestUrlTest("$root-auto") }
    }
    fun pauseQuality() { transport?.cancelActive() }
    override fun close() {
        // Cancel transfers and queued work before waiting for an in-flight
        // selector command. The next core cannot start before this fence exits.
        closed = true
        transport?.close(); qualityWorker.shutdownNow(); worker.shutdownNow()
        synchronized(lock) { Unit }
    }
}
