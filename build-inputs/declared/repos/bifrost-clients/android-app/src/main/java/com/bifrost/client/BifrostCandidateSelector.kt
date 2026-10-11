package com.bifrost.client

import android.content.Context
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import android.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.math.max
import kotlin.math.min

/**
 * Bounded, source-scoped candidate selection used by the real Android
 * connection path. It never crosses A/B, emits at most three bounded probes
 * in parallel and stores a two-hour/network-signature decision plus local
 * EWMA history in the encrypted UI store. TLS is handshaken whenever the
 * signed transport declares TLS (independent of port); WebSocket transports receive only a bounded
 * HTTP upgrade probe (never application payload).
 */
object BifrostCandidateSelector {
    private const val CACHE_VERSION = 3
    private const val CACHE_KEY = "probe_buckets_v3"
    private const val MAX_HISTORY_ENTRIES = 64
    private const val MAX_HISTORY_BYTES = 64 * 1024
    private const val MAX_HISTORY_LABEL_LENGTH = 256
    private val cacheGate = Any()
    private val retryCohorts = ConcurrentHashMap<String, Int>()
    const val REFRESH_INTERVAL_MS = 2 * 60 * 60 * 1000L
    const val MAX_PROBES = 3
    const val MAX_COHORTS_PER_ROUND = 3
    const val MAX_PROBE_BYTES = 4096
    /** Application-level request/response budget. Android's SSLSocket does
     * not expose TLS record counters, so this is deliberately not described
     * as a wire-byte limit. TLS work is separately bounded by at most one
     * handshake per candidate in this round, the socket timeout, and the
     * three-candidate concurrency cap. */
    const val MAX_APPLICATION_PROBE_BYTES = 12 * 1024
    // Bound one selection round even when the signed source has hundreds of
    // candidates. Failed rounds keep the rotating cursor, so later retries
    // continue through the catalogue instead of paying a multi-minute scan.
    const val MAX_TLS_HANDSHAKES_PER_ROUND = MAX_PROBES * MAX_COHORTS_PER_ROUND
    private const val BATCH_DEADLINE_MS = 6000L
    internal fun connectionBudgetMs(nodes: Int): Long = 12_000L +
        ((min(nodes.coerceIn(1, 300), MAX_TLS_HANDSHAKES_PER_ROUND) + MAX_PROBES - 1) / MAX_PROBES) * BATCH_DEADLINE_MS
    private const val EWMA_ALPHA = 0.2
    private const val INCUMBENT_HYSTERESIS_MS = 35.0
    private const val COOLDOWN_BASE_MS = 5 * 60 * 1000L
    private const val MAX_HEADER_BYTES = 4096
    private const val TIMEOUT_MS = 3000
    private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    private val random = SecureRandom()

    /** Signed schema probe metadata: ws_path belongs to source, while
     * host/SNI/TLS/network belong to transport. */
    internal data class ProbeDescriptor(
        val host: String,
        val sni: String,
        val path: String,
        val tls: Boolean,
        val network: String,
    )

    internal fun probeDescriptor(source: JSONObject, transport: JSONObject): ProbeDescriptor {
        val serverName = source.optString("server_name").trim()
        val transportSni = transport.optString("sni").trim()
        val host = transport.optString("host").trim().ifBlank { serverName.ifBlank { transportSni } }
        val sni = transportSni.ifBlank { serverName.ifBlank { host } }
        val rawPath = source.optString("ws_path").trim().ifBlank { "/" }
        val path = (if (rawPath.startsWith('/')) rawPath else "/$rawPath")
            .replace("\r", "").replace("\n", "")
        return ProbeDescriptor(
            host.replace("\r", "").replace("\n", ""),
            sni.replace("\r", "").replace("\n", ""),
            path,
            if (transport.has("tls")) transport.optBoolean("tls") else true,
            transport.optString("network", "tcp"),
        )
    }

    internal fun select(
        context: Context,
        content: String,
        sourceCode: String,
        requested: String? = null,
        nowMs: Long = System.currentTimeMillis(),
        cancellation: ProbeCancellation? = null,
        binding: BifrostProbeRoundKey? = null,
        commitIfCurrent: (((() -> Unit) -> Boolean))? = null,
    ): String {
        cancellation?.throwIfCancelled()
        val payload = JSONObject(content)
        val sources = payload.optJSONArray("sources")
        val source = (0 until (sources?.length() ?: 0))
            .mapNotNull { sources?.optJSONObject(it) }
            .firstOrNull { it.optString("code").equals(sourceCode, true) && it.optBoolean("configured", false) }
            ?: error("BF-SOURCE-NOT-READY")
        val candidates = source.optJSONArray("candidates") ?: error("BF-CANDIDATE-MISSING")
        val allowed = (0 until candidates.length()).mapNotNull { candidates.optJSONObject(it) }
            .filter {
                // The source object is authoritative.  Some signed control
                // packages carry no redundant source_code prefix in labels
                // (for example a-01), so do not reject a valid candidate
                // merely because its display label is opaque.
                val declaredSource = it.optString("source_code").trim()
                declaredSource.isBlank() || declaredSource.equals(sourceCode, true)
            }
        check(allowed.isNotEmpty()) { "BF-CANDIDATE-MISSING" }
        if (!requested.isNullOrBlank()) {
            return resolveCandidateLabel(allowed, requested)
        }

        val network = binding?.networkFingerprint ?: networkSignature(context)
        val bucketKey = binding?.cacheKey() ?: unboundBucketKey(content, sourceCode, network)
        val cacheSnapshot = synchronized(cacheGate) { readBucketCache(context) }
        val bucketsSnapshot = cacheSnapshot.optJSONObject("buckets") ?: JSONObject()
        val bucket = bucketsSnapshot.optJSONObject(bucketKey)?.takeIf { candidate ->
            binding == null || (
                candidate.optString("source").equals(binding.source, true) &&
                    candidate.optString("network") == binding.networkFingerprint &&
                    candidate.optLong("config_version", -1L) == binding.configVersion &&
                    candidate.optString("config_digest") == binding.configDigest &&
                    candidate.optString("candidate_fingerprint") == binding.candidateFingerprint &&
                    candidate.optString("transport_fingerprint") == binding.transportFingerprint &&
                    candidate.optLong("generation", -1L) == binding.generation
                )
        }
        val savedAt = bucket?.optLong("at", 0L) ?: 0L
        val saved = bucket?.optString("label", "").orEmpty()
        if (saved.isNotBlank() && nowMs - savedAt in 0 until REFRESH_INTERVAL_MS && allowed.any { it.optString("label").equals(saved, true) }) return saved

        val incumbentIsValid = saved.isNotBlank() && allowed.any { it.optString("label").equals(saved, true) }
        // Exploration position is not success evidence. Preserve it across
        // lifecycle generations so retries do not restart at three dead IPs.
        val explorationKey = binding?.copy(generation = 1L)?.cacheKey() ?: bucketKey
        val cohortStart = retryCohorts[explorationKey] ?: (bucket?.optInt("cohort", 0)?.coerceAtLeast(0) ?: 0)
        val batches = roundCohorts(allowed.map { it.optString("label") }, cohortStart, saved.takeIf { incumbentIsValid })
        val transport = source.optJSONObject("transport") ?: JSONObject()
        val descriptor = probeDescriptor(source, transport)
        val history = bucket?.optJSONObject("history")?.let { JSONObject(it.toString()) } ?: JSONObject()
        val physicalNetwork = context.getSystemService(android.net.ConnectivityManager::class.java)
            ?.let(BifrostUnderlyingNetwork::select) ?: error("BF-CANDIDATE-PROBE-FAILED")
        val probes = mutableListOf<Probe>()
        val cohort = mutableListOf<String>()
        for (batch in batches) {
            cancellation?.throwIfCancelled()
            cohort += batch
            val candidatesInBatch = batch.mapNotNull { label -> allowed.firstOrNull { it.optString("label").equals(label, true) } }
            probes += probeBounded(candidatesInBatch, network, descriptor, history, nowMs, cancellation, physicalNetwork)
            if (probes.any { it.metrics.success }) break
        }
        android.util.Log.i("BifrostConnectionDiagnostic", "transportProbe attempted=${cohort.size} successful=${probes.count { it.metrics.success }}")
        cancellation?.throwIfCancelled()
        probes.forEach { updateHistory(history, it.candidate.optString("label"), it.metrics, nowMs) }
        val boundedHistory = boundHistoryForCommit(history, cohort.toSet())
        val ranked = probes
            .sortedWith(compareBy<Probe> { !it.metrics.success }.thenBy { it.score }.thenBy { it.candidate.optString("label") })
        val best = ranked.firstOrNull()
        val incumbent = ranked.firstOrNull { it.candidate.optString("label").equals(saved, true) && it.metrics.success }
        val selected = if (best != null && incumbent != null && incumbent.score <= best.score + INCUMBENT_HYSTERESIS_MS) incumbent else best
        // If a captive/offline network prevents a probe, retain only the
        // previously measured incumbent for this source/network.  A backend
        // `healthy` or `score` bit is not a substitute for a local probe and
        // must never be presented as current-network evidence.
        val label = selected?.candidate?.optString("label")?.takeIf { selected.metrics.success }
            ?: saved.takeIf { saved.isNotBlank() && allowed.any { it.optString("label").equals(saved, true) } }
            ?: run {
                // Do not retry the same dead first three endpoints forever.
                // This cursor contains no success evidence and is bounded.
                cancellation?.throwIfCancelled()
                if (retryCohorts.size >= 64) retryCohorts.keys.firstOrNull()?.let(retryCohorts::remove)
                retryCohorts[explorationKey] = (cohortStart + max(1, cohort.size)) % allowed.size
                error("BF-CANDIDATE-PROBE-FAILED")
            }
        retryCohorts.remove(explorationKey)
        // Never mutate the object still referenced by the read cache before a
        // complete decision has been made.  This keeps an all-fail round from
        // accidentally advancing the last-good timestamp.
        val updatedBucket = bucket?.let { JSONObject(it.toString()) } ?: JSONObject()
        updatedBucket.put("source", sourceCode)
        updatedBucket.put("network", network)
        binding?.let {
            updatedBucket.put("config_version", it.configVersion)
            updatedBucket.put("config_digest", it.configDigest)
            updatedBucket.put("candidate_fingerprint", it.candidateFingerprint)
            updatedBucket.put("transport_fingerprint", it.transportFingerprint)
            updatedBucket.put("generation", it.generation)
        }
        updatedBucket.put("label", label)
        val succeeded = selected?.metrics?.success == true
        val previousSuccessAt = bucket?.optLong("at", 0L) ?: 0L
        updatedBucket.put("at", successTimestamp(previousSuccessAt, nowMs, succeeded))
        updatedBucket.put("last_attempt", nowMs)
        updatedBucket.put("last_used", nowMs)
        updatedBucket.put("cohort", ((cohortStart + max(1, cohort.size)) % allowed.size))
        updatedBucket.put("history", boundedHistory)
        // Only generation-bound rounds may write.  The second latch is inside
        // the serialized read/modify/write critical section, immediately
        // before the encrypted commit; A→B→A cancellation cannot leave a
        // stale bucket behind between the first check and put().
        if (binding != null && cancellation?.isCancelled() != true && commitIfCurrent != null) {
            if (!validBucket(updatedBucket)) return label
            // The coordinator holds its state/commit gate across this entire
            // cache RMW and encrypted write.  No Boolean predicate is sampled
            // before a competing source/config transition can invalidate it.
            commitIfCurrent.invoke {
                synchronized(cacheGate) {
                    val cache = readBucketCache(context)
                    val buckets = cache.optJSONObject("buckets") ?: JSONObject().also { cache.put("buckets", it) }
                    buckets.put(bucketKey, updatedBucket)
                    pruneBuckets(buckets)
                    cache.put("version", CACHE_VERSION)
                    cache.put("buckets", buckets)
                    BifrostSecureStore.put(context, CACHE_KEY, cache.toString())
                }
            }
        }
        return label
    }

    /** Stable label resolver shared by the selector and compiler contract
     * tests.  Control packages may expose id/code/label; the compiler must
     * accept whichever stable label the selector emits. */
    internal fun resolveCandidateLabel(candidates: List<JSONObject>, requested: String? = null): String {
        val match = candidates.firstOrNull { candidate ->
            requested.isNullOrBlank() || requested.equals(candidate.optString("label"), true) ||
                requested.equals(candidate.optString("id"), true) || requested.equals(candidate.optString("code"), true) ||
                requested.equals(candidate.optString("dial_address"), true)
        } ?: error("BF-CANDIDATE-SOURCE-MISMATCH")
        return match.optString("label").takeIf(String::isNotBlank)
            ?: match.optString("id").takeIf(String::isNotBlank)
            ?: match.optString("code").takeIf(String::isNotBlank)
            ?: error("BF-CANDIDATE-LABEL-MISSING")
    }

    /** Select a bounded rotating cohort, so a list larger than MAX_PROBES is
     * eventually sampled without issuing a burst of network traffic. */
    internal fun cohortLabels(labels: List<String>, start: Int, limit: Int = MAX_PROBES, incumbent: String? = null): List<String> {
        val clean = labels.filter(String::isNotBlank).distinct()
        if (clean.isEmpty() || limit <= 0) return emptyList()
        val offset = start.mod(clean.size)
        val selected = (0 until min(limit, clean.size)).map { clean[(offset + it) % clean.size] }.toMutableList()
        val validIncumbent = incumbent?.takeIf { value -> clean.any { it.equals(value, true) } }
        if (validIncumbent != null && selected.none { it.equals(validIncumbent, true) }) {
            if (selected.isEmpty()) selected += clean.first { it.equals(validIncumbent, true) }
            else selected[selected.lastIndex] = clean.first { it.equals(validIncumbent, true) }
        }
        return selected.distinct()
    }

    internal fun connectionCohorts(labels: List<String>, start: Int, incumbent: String? = null): List<List<String>> {
        val ordered = cohortLabels(labels, start, labels.size, incumbent)
        // Give a known incumbent the first batch without duplicating it.
        val first = incumbent?.let { saved -> ordered.firstOrNull { it.equals(saved, true) } }
        val queue = if (first == null) ordered else listOf(first) + ordered.filterNot { it.equals(first, true) }
        return queue.chunked(MAX_PROBES)
    }

    internal fun roundCohorts(labels: List<String>, start: Int, incumbent: String? = null): List<List<String>> =
        connectionCohorts(labels, start, incumbent).take(MAX_COHORTS_PER_ROUND)

    /** The `at` field is a last-success timestamp, never an attempt timestamp. */
    internal fun successTimestamp(previous: Long, now: Long, succeeded: Boolean): Long =
        if (succeeded) now else previous

    private data class ProbeMetrics(
        val success: Boolean,
        val rttMs: Double,
        val jitterMs: Double,
        val lossPercent: Double,
        val tlsSuccess: Boolean,
        val bytes: Int,
    )

    private data class Probe(val candidate: JSONObject, val metrics: ProbeMetrics, val score: Double)

    /** Execute a bounded number of transport probes concurrently and always
     * tear down the pool. A candidate consumes at most the signed byte budget;
     * no application payload is sent by this selector. */
    private fun probeBounded(candidates: List<JSONObject>, network: String, descriptor: ProbeDescriptor, history: JSONObject, nowMs: Long, cancellation: ProbeCancellation? = null, physicalNetwork: android.net.Network): List<Probe> {
        if (candidates.isEmpty()) return emptyList()
        val pool = Executors.newFixedThreadPool(min(MAX_PROBES, candidates.size))
        // Always own a round-local token.  A caller token is only a parent:
        // cancelling the caller closes this round, while successful cleanup
        // does not poison the controller's token for the next state update.
        val roundCancellation = ProbeCancellation()
        val parentRelay = cancellation?.onCancel { roundCancellation.cancel() }
        val budget = ProbeRoundBudget(MAX_APPLICATION_PROBE_BYTES) { roundCancellation.cancel() }
        return try {
            val completion = java.util.concurrent.ExecutorCompletionService<Probe>(pool)
            val futures = candidates.map { candidate ->
                val future = completion.submit {
                    roundCancellation.throwIfCancelled()
                    val metrics = measure(candidate, descriptor, budget, roundCancellation, physicalNetwork)
                    Probe(candidate, metrics, compositeScore(candidate, network, metrics, history.optJSONObject(candidate.optString("label")), nowMs))
                }
                val cancelHandle = Closeable { future.cancel(true) }
                roundCancellation.register(cancelHandle)
                future to cancelHandle
            }
            // Consume in completion order: a slow first candidate must not
            // discard a fast authenticated transport result from its siblings.
            val results = BifrostProbeCompletion.collect(completion, futures.size, BATCH_DEADLINE_MS) { cancellation?.throwIfCancelled() }
            results.filter { it.candidate.length() > 0 }
        } finally {
            roundCancellation.cancel()
            parentRelay?.close()
            pool.shutdownNow()
            runCatching { pool.awaitTermination(TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS) }
        }
    }

    private fun measure(candidate: JSONObject, descriptor: ProbeDescriptor, budget: ProbeRoundBudget, cancellation: ProbeCancellation? = null, physicalNetwork: android.net.Network): ProbeMetrics {
        val host = candidate.optString("dial_address").trim()
        val port = candidate.optInt("port", 443)
        if (host.isBlank() || port !in 1..65535) return ProbeMetrics(false, 9_999.0, 9_999.0, 100.0, false, 0)
        return runCatching {
            val tlsRequired = descriptor.tls
            val network = descriptor.network
            val samples = mutableListOf<Double>()
            var tlsSuccess = true
            var failures = 0
            var bytes = 0
            // Connection preflight needs one verified transport. Repeating a
            // second handshake here could discard a successful first sample
            // when the whole batch deadline expires. Stability is evaluated
            // separately after the actual VPN connection is established.
            repeat(1) {
                var stage = "bind"
                try {
                    cancellation?.throwIfCancelled()
                    val start = System.nanoTime()
                    val raw = Socket()
                    cancellation?.register(raw)
                    raw.use {
                        // While VPN is active, probing through the VPN would
                        // measure the incumbent instead of this candidate.
                        physicalNetwork.bindSocket(raw)
                        stage = "tcp"
                        raw.connect(InetSocketAddress(host, port), TIMEOUT_MS)
                        raw.soTimeout = TIMEOUT_MS
                        if (tlsRequired) {
                            stage = "tls"
                            // Dial the candidate address but use the signed
                            // source transport SNI/hostname for TLS verification.
                            val sni = descriptor.sni.ifBlank { host }
                            val secure = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                                .createSocket(raw, sni, port, true) as SSLSocket
                            cancellation?.register(secure)
                            secure.useClientMode = true
                            secure.soTimeout = TIMEOUT_MS
                            secure.sslParameters = secure.sslParameters.apply {
                                endpointIdentificationAlgorithm = "HTTPS"
                            }
                            secure.startHandshake()
                            try {
                                if (network.equals("ws", true) || network.equals("websocket", true)) {
                                    stage = "websocket"
                                    bytes += webSocketProbe(secure, descriptor, budget, cancellation)
                                }
                            } finally {
                                cancellation?.unregister(secure)
                                secure.close()
                            }
                        } else if (network.equals("ws", true) || network.equals("websocket", true)) {
                            stage = "websocket"
                            bytes += webSocketProbe(raw, descriptor, budget, cancellation)
                        }
                        samples += (System.nanoTime() - start) / 1_000_000.0
                    }
                    cancellation?.unregister(raw)
                } catch (error: Exception) {
                    if (cancellation?.isCancelled() == true) throw InterruptedException("BF-PROBE-CANCELLED")
                    // Never log endpoint addresses, signed paths, or exception messages.
                    android.util.Log.w("BifrostConnectionDiagnostic", "transportFailure stage=$stage type=${error.javaClass.simpleName}")
                    failures++
                    tlsSuccess = false
                }
            }
            if (samples.isEmpty()) return@runCatching ProbeMetrics(false, 9_999.0, 9_999.0, 100.0, false, bytes)
            val rtt = samples.average()
            val jitter = if (samples.size < 2) 0.0 else samples.zipWithNext().map { kotlin.math.abs(it.second - it.first) }.average()
            val loss = failures * 100.0
            ProbeMetrics(samples.isNotEmpty(), rtt, jitter, loss, samples.isNotEmpty(), bytes.coerceAtMost(MAX_PROBE_BYTES))
        }.getOrElse {
            // Preserve caller/budget cancellation instead of turning it into
            // a normal failed sample.  The owning round controller must be
            // able to discard this generation immediately.
            if (cancellation?.isCancelled() == true) throw InterruptedException("BF-PROBE-CANCELLED")
            ProbeMetrics(false, 9_999.0, 9_999.0, 100.0, false, 0)
        }
    }

    /** Prove a signed WebSocket transport with one bounded HTTP upgrade. */
    private fun webSocketProbe(socket: Socket, descriptor: ProbeDescriptor, budget: ProbeRoundBudget, cancellation: ProbeCancellation? = null): Int {
        val nonce = ByteArray(16).also(random::nextBytes)
        val key = Base64.encodeToString(nonce, Base64.NO_WRAP)
        val request = ("GET ${descriptor.path} HTTP/1.1\r\nHost: ${descriptor.host}\r\nUpgrade: websocket\r\n" +
            "Connection: Upgrade\r\nSec-WebSocket-Key: $key\r\n" +
            "Sec-WebSocket-Version: 13\r\n\r\n").toByteArray(StandardCharsets.US_ASCII)
        require(request.size <= MAX_PROBE_BYTES) { "BF-PROBE-BUDGET" }
        budget.consume(request.size)
        cancellation?.throwIfCancelled()
        socket.getOutputStream().apply { write(request); flush() }
        val response = ByteArrayOutputStream()
        val buffer = ByteArray(512)
        val input = socket.getInputStream()
        while (response.size() < min(MAX_PROBE_BYTES - request.size, MAX_HEADER_BYTES)) {
            cancellation?.throwIfCancelled()
            val requested = min(buffer.size, MAX_PROBE_BYTES - request.size - response.size())
            if (requested <= 0) break
            val granted = budget.reserve(requested)
            val read = input.read(buffer, 0, granted)
            budget.refund(granted - max(0, read))
            if (read <= 0) break
            response.write(buffer, 0, read)
            if (response.toString(StandardCharsets.US_ASCII.name()).contains("\r\n\r\n")) break
        }
        val headers = response.toString(StandardCharsets.US_ASCII.name())
        val status = Regex("^HTTP/1\\.[01] ([0-9]{3})\\b").find(headers)?.groupValues?.get(1) ?: "invalid"
        if (status != "101") android.util.Log.w("BifrostConnectionDiagnostic", "websocketStatus=$status")
        check(Regex("(?im)^HTTP/1\\.[01] 101\\b").containsMatchIn(headers)) { "BF-PROBE-WS-STATUS" }
        check(headerToken(headers, "Upgrade", "websocket")) { "BF-PROBE-WS-UPGRADE" }
        check(headerToken(headers, "Connection", "upgrade")) { "BF-PROBE-WS-CONNECTION" }
        val accept = Regex("(?im)^Sec-WebSocket-Accept:\\s*([^\\s]+)\\s*$").find(headers)?.groupValues?.get(1)
            ?: error("BF-PROBE-WS-ACCEPT")
        val expected = Base64.encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WS_GUID).toByteArray(StandardCharsets.US_ASCII)),
            Base64.NO_WRAP,
        )
        check(MessageDigest.isEqual(accept.toByteArray(StandardCharsets.US_ASCII), expected.toByteArray(StandardCharsets.US_ASCII))) { "BF-PROBE-WS-ACCEPT" }
        return request.size + response.size()
    }

    private fun headerToken(headers: String, name: String, token: String): Boolean {
        val value = Regex("(?im)^${Regex.escape(name)}:\\s*([^\\r\\n]*)$").find(headers)?.groupValues?.get(1) ?: return false
        return value.split(',').any { it.trim().equals(token, ignoreCase = true) }
    }

    private fun compositeScore(candidate: JSONObject, network: String, measured: ProbeMetrics? = null, local: JSONObject? = null, nowMs: Long = System.currentTimeMillis()): Double {
        val rtt = measured?.rttMs ?: candidate.optDouble("rtt_ms", 600.0)
        val jitter = measured?.jitterMs ?: candidate.optDouble("jitter_ms", 120.0)
        val loss = measured?.lossPercent ?: candidate.optDouble("loss_percent", 20.0)
        val tls = if (measured?.tlsSuccess ?: candidate.optBoolean("tls_success", true)) 0.0 else 500.0
        // Only local measurements represent this device's current network;
        // signed backend telemetry is deliberately not part of the score.
        val successPenalty = (1.0 - (local?.optDouble("success_ewma", if (measured?.success == true) 1.0 else 0.0) ?: 0.0)) * 160.0
        val cooldownPenalty = if ((local?.optLong("cooldown_until", 0L) ?: 0L) > nowMs) 10_000.0 else 0.0
        return max(0.0, rtt) + max(0.0, jitter) * 0.8 + max(0.0, loss) * 12 + tls + successPenalty + cooldownPenalty
    }

    private fun readBucketCache(context: Context): JSONObject = runCatching {
        parseProbeCache(BifrostSecureStore.get(context, CACHE_KEY, "{}"))
    }.getOrElse { JSONObject() }

    internal fun parseProbeCache(raw: String): JSONObject = runCatching {
        val parsed = JSONObject(raw)
        val buckets = parsed.optJSONObject("buckets") ?: return@runCatching JSONObject()
        val rootKeys = parsed.keys().asSequence().toSet()
        if (!strictLong(parsed.opt("version"), CACHE_VERSION.toLong(), CACHE_VERSION.toLong()) ||
            rootKeys != setOf("version", "buckets")) return@runCatching JSONObject()
        val valid = buckets.keys().asSequence().all { key -> validBucket(buckets.optJSONObject(key)) }
        if (!valid) JSONObject() else parsed
    }.getOrElse { JSONObject() }

    private fun validBucket(bucket: JSONObject?): Boolean {
        if (bucket == null) return false
        val keys = bucket.keys().asSequence().toSet()
        val expected = setOf(
            "source", "network", "config_version", "config_digest", "candidate_fingerprint",
            "transport_fingerprint", "generation", "label", "at", "last_attempt", "last_used",
            "cohort", "history",
        )
        if (keys != expected) return false
        val history = bucket.opt("history") as? JSONObject ?: return false
        return strictString(bucket, "source") &&
            strictString(bucket, "network") &&
            strictLong(bucket, "config_version", 1L, Long.MAX_VALUE) &&
            strictString(bucket, "config_digest", Regex("[0-9a-f]{64}")) &&
            strictString(bucket, "candidate_fingerprint", Regex("[0-9a-f]{64}")) &&
            strictString(bucket, "transport_fingerprint", Regex("[0-9a-f]{64}")) &&
            strictLong(bucket, "generation", 1L, Long.MAX_VALUE) &&
            strictString(bucket, "label", maxLength = MAX_HISTORY_LABEL_LENGTH) &&
            strictLong(bucket, "at", 0L, Long.MAX_VALUE) &&
            strictLong(bucket, "last_attempt", 0L, Long.MAX_VALUE) &&
            strictLong(bucket, "last_used", 0L, Long.MAX_VALUE) &&
            strictLong(bucket, "cohort", 0L, MAX_PROBES.toLong() * 1024L) &&
            validHistory(history)
    }

    private fun strictString(
        bucket: JSONObject,
        key: String,
        pattern: Regex? = null,
        maxLength: Int = 4096,
    ): Boolean {
        val value = bucket.opt(key) as? String ?: return false
        return value.isNotBlank() && value.length <= maxLength && (pattern == null || pattern.matches(value))
    }

    private fun validHistory(history: JSONObject): Boolean {
        if (history.length() > MAX_HISTORY_ENTRIES ||
            history.toString().toByteArray(StandardCharsets.UTF_8).size > MAX_HISTORY_BYTES) return false
        val expected = setOf(
            "success_ewma", "rtt_ewma", "jitter_ewma", "loss_ewma",
            "consecutive_failures", "cooldown_until",
        )
        return history.keys().asSequence().all { label ->
            label.isNotBlank() && label.length <= MAX_HISTORY_LABEL_LENGTH &&
                validHistoryEntry(history.optJSONObject(label), expected)
        }
    }

    private fun validHistoryEntry(entry: JSONObject?, expected: Set<String>): Boolean {
        if (entry == null || entry.keys().asSequence().toSet() != expected) return false
        return finiteNumber(entry.opt("success_ewma"), 0.0, 1.0) &&
            finiteNumber(entry.opt("rtt_ewma"), 0.0, 60_000.0) &&
            finiteNumber(entry.opt("jitter_ewma"), 0.0, 60_000.0) &&
            finiteNumber(entry.opt("loss_ewma"), 0.0, 100.0) &&
            strictLong(entry.opt("consecutive_failures"), 0L, 1_000_000L) &&
            strictLong(entry.opt("cooldown_until"), 0L, Long.MAX_VALUE)
    }

    private fun finiteNumber(value: Any?, minimum: Double, maximum: Double): Boolean {
        val number = value as? Number ?: return false
        val converted = number.toDouble()
        return converted.isFinite() && converted in minimum..maximum
    }

    private fun strictLong(bucket: JSONObject, key: String, minimum: Long, maximum: Long): Boolean {
        return strictLong(bucket.opt(key), minimum, maximum)
    }

    private fun strictLong(value: Any?, minimum: Long, maximum: Long): Boolean {
        if (value == null) return false
        // org.json represents integral JSON tokens as Int/Long. Reject
        // Double and numeric strings so 1.0/"1" cannot forge metadata.
        val number = when (value) {
            is Int -> value.toLong()
            is Long -> value
            else -> return false
        }
        return number in minimum..maximum
    }

    private fun unboundBucketKey(content: String, source: String, network: String): String {
        val root = JSONObject(content)
        val candidate = BifrostProbeFingerprints.input(
            BifrostConfigStore.Cached(
                core = "auto",
                content = content,
                version = root.optLong("config_version", 1L).coerceAtLeast(1L),
                digest = BifrostProbeFingerprints.sha256Hex(content),
            ),
            source,
            network,
        )
        return if (candidate != null) {
            BifrostProbeStableKey(
                candidate.source.trim().uppercase(),
                candidate.networkFingerprint,
                candidate.configVersion,
                candidate.configDigest,
                candidate.candidateFingerprint,
                candidate.transportFingerprint,
            ).withGeneration(1L).cacheKey()
        } else {
            BifrostProbeFingerprints.sha256Hex("${source.trim().lowercase()}\u0000$network\u0000${BifrostProbeFingerprints.sha256Hex(content)}")
        }
    }

    private fun pruneBuckets(buckets: JSONObject) {
        retainedBucketKeys(buckets).toSet().let { keep ->
            buckets.keys().asSequence().filterNot(keep::contains).toList().forEach(buckets::remove)
        }
    }

    private fun pruneHistory(history: JSONObject, preferredLabels: Set<String>) {
        // Remove exactly one entry at a time, checking both parser bounds
        // after every removal. Non-cohort labels are preferred victims; a
        // cohort label is removed only when retaining it would make the
        // self-produced object invalid. This also handles an all-preferred
        // 64+ entry or byte-pressure history deterministically.
        val order = history.keys().asSequence()
            .sortedWith(compareBy<String> { it in preferredLabels }.thenBy { it })
            .toMutableList()
        fun exceeds(): Boolean = history.length() > MAX_HISTORY_ENTRIES ||
            history.toString().toByteArray(StandardCharsets.UTF_8).size > MAX_HISTORY_BYTES
        while (exceeds() && order.isNotEmpty()) {
            history.remove(order.removeAt(0))
        }
        // A malformed/oversized label can still leave the object over the
        // byte budget after the initial key snapshot; continue in canonical
        // key order, never leaving an invalid writer value behind.
        while (exceeds()) {
            val next = history.keys().asSequence().sorted().firstOrNull() ?: break
            history.remove(next)
        }
    }

    internal fun boundHistoryForCommit(history: JSONObject, preferredLabels: Set<String>): JSONObject =
        JSONObject(history.toString()).also { pruneHistory(it, preferredLabels) }

    internal fun retainedBucketKeys(buckets: JSONObject, limit: Int = 8): List<String> =
        buckets.keys().asSequence()
            .sortedByDescending { buckets.optJSONObject(it)?.optLong("last_used", 0L) ?: 0L }
            .take(limit.coerceAtLeast(0))
            .toList()

    private fun updateHistory(history: JSONObject, label: String, metrics: ProbeMetrics, nowMs: Long) {
        if (label.isBlank() || label.length > MAX_HISTORY_LABEL_LENGTH) return
        val previous = history.optJSONObject(label) ?: JSONObject()
        val oldSuccess = previous.optDouble("success_ewma", if (metrics.success) 1.0 else 0.0)
        val oldRtt = previous.optDouble("rtt_ewma", metrics.rttMs)
        val oldJitter = previous.optDouble("jitter_ewma", metrics.jitterMs)
        val oldLoss = previous.optDouble("loss_ewma", metrics.lossPercent)
        val failures = if (metrics.success) 0 else previous.optInt("consecutive_failures", 0) + 1
        val cooldown = if (metrics.success) 0L else nowMs + COOLDOWN_BASE_MS * min(12, failures).toLong()
        previous.put("success_ewma", oldSuccess * (1 - EWMA_ALPHA) + (if (metrics.success) 1 else 0) * EWMA_ALPHA)
        previous.put("rtt_ewma", oldRtt * (1 - EWMA_ALPHA) + metrics.rttMs * EWMA_ALPHA)
        previous.put("jitter_ewma", oldJitter * (1 - EWMA_ALPHA) + metrics.jitterMs * EWMA_ALPHA)
        previous.put("loss_ewma", oldLoss * (1 - EWMA_ALPHA) + metrics.lossPercent * EWMA_ALPHA)
        previous.put("consecutive_failures", failures)
        previous.put("cooldown_until", cooldown)
        history.put(label, previous)
    }

    private fun networkSignature(context: Context): String = AndroidNetworkBucket.fingerprint(context)
}

internal object BifrostProbeCompletion {
    fun <T> collect(completion: java.util.concurrent.CompletionService<T>, count: Int, budgetMs: Long, checkCancellation: () -> Unit): List<T> {
        val results = mutableListOf<T>()
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMs)
        repeat(count) {
            checkCancellation()
            val remaining = deadline - System.nanoTime()
            if (remaining > 0) {
                val finished = completion.poll(remaining, TimeUnit.NANOSECONDS)
                if (finished != null) runCatching { finished.get() }.getOrNull()?.let(results::add)
            }
        }
        checkCancellation()
        return results
    }
}

/** Cancellation token which owns the sockets/futures of one probe round. */
class ProbeCancellation {
    private val cancelled = AtomicBoolean(false)
    private val resources = ConcurrentHashMap.newKeySet<Closeable>()
    private val gate = Any()
    private val callbacks = mutableSetOf<() -> Unit>()

    fun register(resource: Closeable) {
        var closeNow = false
        synchronized(gate) {
            if (cancelled.get()) closeNow = true
            else {
                resources += resource
                // Close the resource if cancellation raced the registration.
                if (cancelled.get() && resources.remove(resource)) closeNow = true
            }
        }
        if (closeNow) runCatching { resource.close() }
    }

    fun unregister(resource: Closeable) { resources -= resource }
    /** Register a parent-cancellation relay and return a handle which removes
     * it once the child round has finished. */
    fun onCancel(callback: () -> Unit): Closeable {
        var runNow = false
        synchronized(gate) {
            if (cancelled.get()) runNow = true else callbacks += callback
        }
        if (runNow) callback()
        return Closeable { synchronized(gate) { callbacks -= callback } }
    }
    fun isCancelled(): Boolean = cancelled.get()
    fun throwIfCancelled() { if (cancelled.get()) throw InterruptedException("BF-PROBE-CANCELLED") }
    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        val (snapshot, callbackSnapshot) = synchronized(gate) {
            resources.toList().also { resources.clear() } to callbacks.toList().also { callbacks.clear() }
        }
        snapshot.forEach { runCatching { it.close() } }
        callbackSnapshot.forEach { runCatching { it() } }
    }
}

/** Atomic application-byte budget shared by all candidates in one round. */
internal class ProbeRoundBudget(private val limit: Int, private val onExhausted: () -> Unit = {}) {
    private val used = AtomicInteger(0)
    val consumed: Int get() = used.get()
    val remaining: Int get() = (limit - used.get()).coerceAtLeast(0)

    fun reserve(requested: Int): Int {
        require(requested >= 0)
        while (true) {
            val current = used.get()
            val grant = min(requested, limit - current)
            if (grant <= 0) {
                onExhausted()
                throw IllegalStateException("BF-PROBE-BUDGET")
            }
            if (used.compareAndSet(current, current + grant)) return grant
        }
    }

    fun consume(requested: Int) {
        require(requested >= 0)
        while (true) {
            val current = used.get()
            if (limit - current < requested) {
                onExhausted()
                throw IllegalStateException("BF-PROBE-BUDGET")
            }
            if (used.compareAndSet(current, current + requested)) return
        }
    }

    fun refund(amount: Int) {
        if (amount > 0) used.addAndGet(-amount)
    }
}
