package com.bifrost.client

import android.content.Context
import org.json.JSONObject
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal data class BifrostProbeRoundInput(
    val content: String,
    val source: String,
    val networkFingerprint: String,
    val configVersion: Long,
    val configDigest: String,
    val candidateFingerprint: String,
    val transportFingerprint: String,
)

internal data class BifrostProbeRoundKey(
    val source: String,
    val networkFingerprint: String,
    val configVersion: Long,
    val configDigest: String,
    val candidateFingerprint: String,
    val transportFingerprint: String,
    val generation: Long,
) {
    init {
        require(source.isNotBlank() && !source.equals("auto", true)) { "BF-PROBE-SOURCE" }
        require(networkFingerprint.isNotBlank()) { "BF-PROBE-NETWORK" }
        require(configVersion > 0L) { "BF-PROBE-CONFIG-VERSION" }
        require(configDigest.matches(Regex("[0-9a-f]{64}"))) { "BF-PROBE-CONFIG-DIGEST" }
        require(candidateFingerprint.matches(Regex("[0-9a-f]{64}"))) { "BF-PROBE-CANDIDATES" }
        require(transportFingerprint.matches(Regex("[0-9a-f]{64}"))) { "BF-PROBE-TRANSPORT" }
        require(generation > 0L) { "BF-PROBE-GENERATION" }
    }

    fun cacheKey(): String = BifrostProbeFingerprints.sha256Hex(
        listOf(
            source.trim().lowercase(),
            networkFingerprint,
            configVersion.toString(),
            configDigest,
            candidateFingerprint,
            transportFingerprint,
            generation.toString(),
        ).joinToString("\u0000"),
    )

    internal fun stable(): BifrostProbeStableKey = BifrostProbeStableKey(
        source.trim().uppercase(),
        networkFingerprint,
        configVersion,
        configDigest,
        candidateFingerprint,
        transportFingerprint,
    )
}

internal data class BifrostProbeStableKey(
    val source: String,
    val networkFingerprint: String,
    val configVersion: Long,
    val configDigest: String,
    val candidateFingerprint: String,
    val transportFingerprint: String,
) {
    fun withGeneration(generation: Long) = BifrostProbeRoundKey(
        source,
        networkFingerprint,
        configVersion,
        configDigest,
        candidateFingerprint,
        transportFingerprint,
        generation,
    )
}

internal object BifrostProbeFingerprints {
    fun input(cached: BifrostConfigStore.Cached, sourceCode: String, networkFingerprint: String): BifrostProbeRoundInput? {
        val source = sourceCode.trim()
        if (source.isBlank() || source.equals("auto", true)) return null
        val root = JSONObject(cached.content)
        val sourceObject = findConfiguredSource(root, source) ?: return null
        return BifrostProbeRoundInput(
            content = cached.content,
            source = sourceObject.optString("code").trim(),
            networkFingerprint = networkFingerprint,
            configVersion = cached.version,
            configDigest = cached.digest,
            candidateFingerprint = candidateFingerprint(sourceObject),
            transportFingerprint = transportFingerprint(sourceObject),
        )
    }

    fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun findConfiguredSource(root: JSONObject, source: String): JSONObject? {
        val array = root.optJSONArray("sources") ?: return null
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            if (item.optString("code").equals(source, true) && item.optBoolean("configured", false)) return item
        }
        return null
    }

    private fun candidateFingerprint(source: JSONObject): String {
        val candidates = source.optJSONArray("candidates") ?: return sha256Hex("[]")
        val normalized = (0 until candidates.length())
            .mapNotNull { candidates.optJSONObject(it) }
            .map {
                listOf(
                    it.optString("label").trim(),
                    it.optString("id").trim(),
                    it.optString("code").trim(),
                    it.optString("dial_address").trim(),
                    it.optInt("port", 443).toString(),
                ).joinToString("\u0001")
            }
            .sorted()
            .joinToString("\u0002")
        return sha256Hex(normalized)
    }

    private fun transportFingerprint(source: JSONObject): String {
        val transport = source.optJSONObject("transport") ?: JSONObject()
        val normalized = listOf(
            source.optString("server_name").trim(),
            source.optString("ws_path").trim(),
            transport.optString("network", "tcp").trim(),
            transport.optString("host").trim(),
            transport.optString("sni").trim(),
            if (transport.has("tls")) transport.optBoolean("tls").toString() else "true",
        ).joinToString("\u0001")
        return sha256Hex(normalized)
    }
}

internal data class BifrostProbeCoordinatorResult(
    val source: String,
    val key: BifrostProbeRoundKey,
    val label: String?,
    val error: Throwable?,
    val delivery: BifrostProbeDeliveryAdmission? = null,
)

/** A load/configuration failure is admitted against its own demand epoch.
 * It must be invalidated exactly like a successful result when source,
 * network, or verified-config state changes before a consumer receives it. */
internal class BifrostProbeFailureAdmission internal constructor(
    val source: String,
    val epoch: Long,
    private val isCurrent: () -> Boolean = { true },
) {
    private val gate = Any()
    /** State-only retirement marker. Fence detach/replace may set it while
     * lifecycle.gate is held without taking admission.gate or running user
     * code; actual invalidate() remains outside lifecycle.gate. */
    @Volatile private var retired = false
    private var active = true
    private var dispatching = 0

    internal fun retire() { retired = true }

    fun invalidate() {
        synchronized(gate) {
            active = false
        }
    }

    internal fun isActiveForTest(): Boolean = synchronized(gate) { active }

    /** Admission is linearized under this gate, but the callback runs after
     * releasing it.  Lifecycle transitions detach under their own state gate
     * and invalidate after release, so neither lock is ever acquired while
     * holding the other (and a callback may safely re-enter lifecycle state). */
    fun deliver(callback: () -> Unit): Boolean {
        // This check is deliberately outside admission.gate.  It is the
        // consumer linearization point and may read lifecycle state without
        // creating an admission -> lifecycle lock order.  A transition that
        // wins first retires this consumer; a callback already admitted may
        // finish, but later consumers will fail this exact check.
        if (retired || !isCurrent()) return false
        synchronized(gate) {
            if (!active || retired) return false
            dispatching += 1
        }
        try {
            callback()
        } finally {
            synchronized(gate) { dispatching -= 1 }
        }
        return true
    }
}

/**
 * Delivery is admitted independently from lifecycle.gate. The admission
 * lock is the linearization point: a transition can invalidate an admission
 * before a callback starts, while a callback already holding it may finish.
 * No lifecycle/listener lock is held while user code runs.
 */
internal class BifrostProbeDeliveryAdmission internal constructor(
    internal val key: BifrostProbeRoundKey,
    private val isCurrent: () -> Boolean = { true },
) {
    private val gate = Any()
    @Volatile private var retired = false
    private var active = true

    internal fun retire() { retired = true }

    fun invalidate() {
        synchronized(gate) {
            active = false
        }
    }

    fun deliver(callback: () -> Unit): Boolean {
        // Linearize before entering the per-admission state gate.  The
        // predicate is evaluated outside that gate so callbacks/transitions
        // can never form an admission.gate -> lifecycle.gate cycle.
        if (retired || !isCurrent()) return false
        synchronized(gate) {
            if (!active || retired) return false
        }
        // Never hold the admission gate while invoking user/listener code;
        // callbacks may synchronously re-enter source/network lifecycle state.
        callback()
        return true
    }
}

/** State-only fence; its lock is never held while an admission callback runs. */
internal class BifrostProbeDeliveryFence {
    private val gate = Any()
    private var current: BifrostProbeDeliveryAdmission? = null

    fun replace(admission: BifrostProbeDeliveryAdmission): BifrostProbeDeliveryAdmission? = synchronized(gate) {
        val previous = current
        current = admission
        previous?.retire()
        previous
    }

    fun detach(): BifrostProbeDeliveryAdmission? = synchronized(gate) {
        val previous = current
        current = null
        previous?.retire()
        previous
    }
}

internal data class BifrostProbeConnectionBinding(
    val source: String,
    val networkFingerprint: String,
    val configVersion: Long,
    val configDigest: String,
    val candidateFingerprint: String,
    val transportFingerprint: String,
    val generation: Long,
) {
    fun matches(key: BifrostProbeRoundKey): Boolean =
        source.equals(key.source, true) &&
            networkFingerprint == key.networkFingerprint &&
            configVersion == key.configVersion &&
            configDigest == key.configDigest &&
            candidateFingerprint == key.candidateFingerprint &&
            transportFingerprint == key.transportFingerprint &&
            generation == key.generation

    companion object {
        fun from(input: BifrostProbeRoundInput, generation: Long) = BifrostProbeConnectionBinding(
            input.source.trim().uppercase(),
            input.networkFingerprint,
            input.configVersion,
            input.configDigest,
            input.candidateFingerprint,
            input.transportFingerprint,
            generation,
        )
    }
}

/** Immutable receipt handed from the verified selector to the connection
 * transaction.  A label alone is not sufficient: every binding field must
 * still match immediately before permission and service handoff. */
internal data class BifrostCandidateSelectionReceipt(
    val label: String,
    val binding: BifrostProbeConnectionBinding,
) {
    init { require(label.isNotBlank() && label.length <= 256) { "BF-CANDIDATE-LABEL" } }

    fun matches(input: BifrostProbeRoundInput, generation: Long): Boolean =
        binding == BifrostProbeConnectionBinding.from(input, generation)
}

/** Exact-once, cancellable handoff for a connection's shared probe result. */
internal class BifrostConnectionProbeRequest(
    private val callback: (Result<BifrostCandidateSelectionReceipt>) -> Unit,
    private val expectedBinding: BifrostProbeConnectionBinding? = null,
) : Closeable {
    private val gate = Any()
    private var completed = false
    private var lease: Closeable? = null

    internal fun expectedBindingForValidation(): BifrostProbeConnectionBinding? = expectedBinding

    fun attach(candidateLease: Closeable) {
        val closeNow = synchronized(gate) {
            if (completed) true else {
                lease = candidateLease
                false
            }
        }
        if (closeNow) runCatching { candidateLease.close() }
    }

    fun complete(result: Result<BifrostCandidateSelectionReceipt>) {
        val ownedLease = synchronized(gate) {
            if (completed) return
            completed = true
            lease.also { lease = null }
        }
        runCatching { callback(result) }
        runCatching { ownedLease?.close() }
    }

    fun completeFromProbe(result: BifrostProbeCoordinatorResult): Boolean {
        if (expectedBinding != null && !expectedBinding.matches(result.key)) return false
        val selected = result.label?.let {
            Result.success(BifrostCandidateSelectionReceipt(it, BifrostProbeConnectionBinding(
                result.key.source,
                result.key.networkFingerprint,
                result.key.configVersion,
                result.key.configDigest,
                result.key.candidateFingerprint,
                result.key.transportFingerprint,
                result.key.generation,
            )))
        }
            ?: Result.failure(result.error ?: IllegalStateException("BF-CANDIDATE-PROBE-FAILED"))
        complete(selected)
        return true
    }

    override fun close() {
        val ownedLease = synchronized(gate) {
            if (completed) return
            completed = true
            lease.also { lease = null }
        }
        runCatching { ownedLease?.close() }
    }
}

internal interface BifrostProbeScheduler : Closeable {
    fun schedule(delayMs: Long, task: () -> Unit): Closeable
}

internal class ExecutorProbeScheduler(
    private val executor: ScheduledExecutorService,
) : BifrostProbeScheduler {
    override fun schedule(delayMs: Long, task: () -> Unit): Closeable {
        val future = executor.schedule(task, delayMs.coerceAtLeast(0L), TimeUnit.MILLISECONDS)
        // Transport cancellation is owned by ProbeCancellation. Interrupting
        // a running scheduler task also interrupts unrelated Keystore/file
        // reads when a new connection lease joins the existing round.
        return Closeable { future.cancel(false) }
    }

    override fun close() {
        executor.shutdownNow()
    }
}

internal class BifrostProbeLifecycleCoordinator(
    private val scheduler: BifrostProbeScheduler,
    private val debounceMs: Long = 1_500L,
    private val cadenceMs: Long = BifrostCandidateSelector.REFRESH_INTERVAL_MS,
    private val load: (source: String) -> BifrostProbeRoundInput?,
    private val probe: (input: BifrostProbeRoundInput, key: BifrostProbeRoundKey, cancellation: ProbeCancellation, isCurrent: () -> Boolean) -> String,
    private val publish: (BifrostProbeCoordinatorResult) -> Unit,
    private val unavailable: (source: String, error: Throwable) -> Unit = { _, _ -> },
    private val unavailableAdmitted: ((source: String, error: Throwable, admission: BifrostProbeFailureAdmission) -> Unit)? = null,
    private val beforePublish: (() -> Unit)? = null,
) : Closeable {
    private val gate = Any()
    private val leases = mutableSetOf<String>()
    private var source: String = ""
    private var closed = false
    private var scheduled: Closeable? = null
    private var cadence: Closeable? = null
    private var activeCancellation: ProbeCancellation? = null
    private var activeKey: BifrostProbeRoundKey? = null
    private var stableKey: BifrostProbeStableKey? = null
    private var generation = 0L
    private var failureEpoch = 0L
    private val deliveryFence = BifrostProbeDeliveryFence()
    private val failureFence = BifrostProbeFailureFence()
    private data class ActiveRound(
        val key: BifrostProbeRoundKey,
        val cancellation: ProbeCancellation,
        val delivery: BifrostProbeDeliveryAdmission,
    )

    fun acquireLease(owner: String, requestedSource: String? = null): Closeable {
        synchronized(gate) {
            if (closed) return Closeable { }
            leases += owner
            if (requestedSource != null) {
                source = requestedSource.takeIf(::validSource)?.trim()?.uppercase().orEmpty()
            } else if (leases.size == 1) {
                // A new visible lease with no persisted source must not reuse
                // the previous Activity/Service source after all demand was
                // released.
                source = ""
            }
            scheduleLocked(0L)
        }
        return Closeable { releaseLease(owner) }
    }

    fun updateSource(requestedSource: String) {
        val invalidated = synchronized(gate) {
            source = requestedSource.takeIf(::validSource)?.trim()?.uppercase().orEmpty()
            failureEpoch += 1
            generation += 1
            activeCancellation?.cancel()
            activeKey = null
            scheduleLocked(0L)
            Fences(deliveryFence.detach(), failureFence.detach())
        }
        invalidated.invalidate()
    }

    fun refreshNow(requestedSource: String? = null, forceTransition: Boolean = true) {
        val invalidated = synchronized(gate) {
            val previousSource = source
            requestedSource?.takeIf(::validSource)?.let { source = it.trim().uppercase() }
            if (!forceTransition && previousSource == source) {
                // Joining a completed or scheduled round must preserve the
                // generation captured by connection preflight. executeRound
                // advances it itself if the verified inputs actually changed.
                if (activeKey == null) scheduleLocked(0L)
                return@synchronized Fences(null, null)
            }
            val sameActiveRound = !forceTransition && activeKey != null &&
                activeKey?.source == source && activeCancellation?.isCancelled() == false
            if (sameActiveRound) return@synchronized Fences(null, null)
            failureEpoch += 1
            generation += 1
            activeCancellation?.cancel()
            activeCancellation = null
            activeKey = null
            scheduleLocked(0L)
            Fences(deliveryFence.detach(), failureFence.detach())
        }
        invalidated.invalidate()
    }

    fun networkChanged() {
        val invalidated = synchronized(gate) {
            activeCancellation?.cancel()
            failureEpoch += 1
            generation += 1
            activeKey = null
            // A cadence tick must not bypass the 1500ms quiet window.
            cadence?.close()
            cadence = null
            scheduleLocked(debounceMs)
            Fences(deliveryFence.detach(), failureFence.detach())
        }
        invalidated.invalidate()
    }

    fun isCurrent(key: BifrostProbeRoundKey): Boolean = synchronized(gate) { isCurrentLocked(key, null) }

    /** Owns the state gate for the complete cache RMW/encrypted commit. */
    fun commitIfCurrent(
        key: BifrostProbeRoundKey,
        expectedCancellation: ProbeCancellation,
        commit: () -> Unit,
    ): Boolean = synchronized(gate) {
        if (!isCurrentLocked(key, expectedCancellation)) false else {
            commit()
            true
        }
    }

    private fun isCurrentLocked(key: BifrostProbeRoundKey, expectedCancellation: ProbeCancellation?): Boolean =
        !closed && activeKey == key && stableKey == key.stable() && source == key.source &&
            activeCancellation?.let { current ->
                (expectedCancellation == null || current === expectedCancellation) && !current.isCancelled()
            } == true

    fun hasDemand(): Boolean = synchronized(gate) { leases.isNotEmpty() }

    fun captureConnectionGeneration(input: BifrostProbeRoundInput): Long = synchronized(gate) {
        val stable = BifrostProbeStableKey(
            input.source.trim().uppercase(),
            input.networkFingerprint,
            input.configVersion,
            input.configDigest,
            input.candidateFingerprint,
            input.transportFingerprint,
        )
        if (stableKey == stable) generation else generation + 1L
    }

    private fun releaseLease(owner: String) {
        val invalidated = synchronized(gate) {
            leases -= owner
            if (leases.isEmpty()) {
                scheduled?.close()
                scheduled = null
                cadence?.close()
                cadence = null
                activeCancellation?.cancel()
                activeCancellation = null
                activeKey = null
                failureEpoch += 1
                generation += 1
                Fences(deliveryFence.detach(), failureFence.detach())
            } else Fences(null, null)
        }
        invalidated.invalidate()
    }

    private fun scheduleLocked(delayMs: Long) {
        scheduled?.close()
        scheduled = null
        if (closed || leases.isEmpty() || !validSource(source)) return
        scheduled = scheduler.schedule(delayMs) { executeRound() }
    }

    private fun scheduleCadenceLocked() {
        cadence?.close()
        cadence = null
        if (closed || leases.isEmpty() || !validSource(source)) return
        cadence = scheduler.schedule(cadenceMs) { executeRound() }
    }

    private fun executeRound() {
        val requestedSource = synchronized(gate) {
            if (closed || leases.isEmpty() || !validSource(source)) return
            source
        }
        val loaded = runCatching { load(requestedSource) }
        val input = loaded.getOrNull()
        if (input == null) {
            var shouldNotify = false
            val invalidated = synchronized(gate) {
                if (closed || leases.isEmpty() || source != requestedSource) FailureDecision(null, null, null)
                else {
                    scheduleCadenceLocked()
                    shouldNotify = true
                    val epoch = ++failureEpoch
            val admission = BifrostProbeFailureAdmission(requestedSource, epoch) {
                synchronized(gate) { !closed && source == requestedSource && failureEpoch == epoch }
            }
                    FailureDecision(deliveryFence.detach(), failureFence.replace(admission), admission)
                }
            }
            invalidated.invalidate()
            // A connection demand must not wait for the two-hour cadence when
            // the verified config disappears between preflight and execution.
            // Notify outside the lifecycle gate so the listener fence remains
            // the only callback/close synchronization boundary.
            if (shouldNotify) {
                val error = loaded.exceptionOrNull() ?: IllegalStateException("BF-CONFIG-CACHE-MISSING")
                unavailable(requestedSource, error)
                invalidated.current?.let { unavailableAdmitted?.invoke(requestedSource, error, it) }
            }
            return
        }
        if (!input.source.equals(requestedSource, true)) {
            var shouldNotify = false
            val invalidated = synchronized(gate) {
                if (closed || leases.isEmpty() || source != requestedSource) FailureDecision(null, null, null)
                else {
                    scheduleCadenceLocked()
                    shouldNotify = true
                    val epoch = ++failureEpoch
                    val admission = BifrostProbeFailureAdmission(requestedSource, epoch) {
                        synchronized(gate) { !closed && source == requestedSource && failureEpoch == epoch }
                    }
                    FailureDecision(deliveryFence.detach(), failureFence.replace(admission), admission)
                }
            }
            invalidated.invalidate()
            if (shouldNotify) {
                val error = IllegalStateException("BF-SOURCE-NOT-READY")
                unavailable(requestedSource, error)
                invalidated.current?.let { unavailableAdmitted?.invoke(requestedSource, error, it) }
            }
            return
        }
        var supersededDelivery: BifrostProbeDeliveryAdmission? = null
        var supersededFailure: BifrostProbeFailureAdmission? = null
        val round = synchronized(gate) {
            if (closed || leases.isEmpty() || source != requestedSource) return
            val nextStable = BifrostProbeStableKey(
                input.source.trim().uppercase(),
                input.networkFingerprint,
                input.configVersion,
                input.configDigest,
                input.candidateFingerprint,
                input.transportFingerprint,
            )
            if (stableKey != nextStable) {
                generation += 1
                stableKey = nextStable
                activeCancellation?.cancel()
                activeKey = null
            }
            val nextKey = nextStable.withGeneration(generation)
            if (activeKey == nextKey) return
            val cancellation = ProbeCancellation()
            activeCancellation = cancellation
            activeKey = nextKey
            val delivery = BifrostProbeDeliveryAdmission(nextKey) {
                synchronized(gate) {
                    !closed && source == nextKey.source && generation == nextKey.generation && stableKey == nextKey.stable()
                }
            }
            supersededDelivery = deliveryFence.replace(delivery)
            supersededFailure = failureFence.detach()
            ActiveRound(nextKey, cancellation, delivery)
        }
        supersededDelivery?.invalidate()
        supersededFailure?.invalidate()
        val key = round.key
        val cancellation = round.cancellation
        val result = runCatching { probe(input, key, cancellation) { synchronized(gate) { isCurrentLocked(key, cancellation) } } }
        val publishResult = synchronized(gate) {
            val current = !closed && activeKey == key && activeCancellation === cancellation && stableKey == key.stable() &&
                source == key.source && !cancellation.isCancelled()
            if (activeKey == key && activeCancellation === cancellation) {
                activeKey = null
                activeCancellation = null
            }
            if (current) BifrostProbeCoordinatorResult(
                key.source,
                key,
                result.getOrNull(),
                result.exceptionOrNull(),
                round.delivery,
            ) else null
        }
        // Publication is deliberately outside the lifecycle gate.  Listener
        // registration/close fencing below provides the no-late-callback
        // guarantee without creating a lifecycle-gate/listener-gate cycle.
        if (publishResult == null) round.delivery.invalidate()
        beforePublish?.invoke()
        if (publishResult != null) publish(publishResult)
        // A superseded round must not replace a live 1500ms debounce (or an
        // immediate source refresh) with its own cadence task.
        if (publishResult != null) {
            synchronized(gate) { scheduleCadenceLocked() }
        }
    }

    override fun close() {
        val invalidated = synchronized(gate) {
            closed = true
            scheduled?.close()
            cadence?.close()
            activeCancellation?.cancel()
            scheduled = null
            cadence = null
            activeCancellation = null
            activeKey = null
            failureEpoch += 1
            leases.clear()
            Fences(deliveryFence.detach(), failureFence.detach())
        }
        invalidated.invalidate()
        scheduler.close()
    }

    private fun validSource(value: String): Boolean =
        value.isNotBlank() && !value.equals("auto", true)
}

private class BifrostProbeFailureFence {
    private val gate = Any()
    private var current: BifrostProbeFailureAdmission? = null

    fun replace(admission: BifrostProbeFailureAdmission): BifrostProbeFailureAdmission? = synchronized(gate) {
        val previous = current
        current = admission
        previous?.retire()
        previous
    }

    fun detach(): BifrostProbeFailureAdmission? = synchronized(gate) {
        val previous = current
        current = null
        previous?.retire()
        previous
    }

}

private data class Fences(
    val delivery: BifrostProbeDeliveryAdmission?,
    val failure: BifrostProbeFailureAdmission?,
) {
    fun invalidate() {
        delivery?.invalidate()
        failure?.invalidate()
    }
}

private data class FailureDecision(
    val delivery: BifrostProbeDeliveryAdmission?,
    val previous: BifrostProbeFailureAdmission?,
    val current: BifrostProbeFailureAdmission?,
) {
    fun invalidate() {
        delivery?.invalidate()
        previous?.invalidate()
    }
}

/** Production listener fence. It is deliberately independent from both
 * lifecycle.gate and listenerGate, so close never forms a lock cycle. */
internal class BifrostProbeListenerRegistration(
    private val listener: (BifrostProbeCoordinatorResult) -> Unit,
    private val failure: (source: String, error: Throwable) -> Unit = { _, _ -> },
) : Closeable {
    private val gate = Any()
    private var active = true
    private var dispatching = 0
    private val dispatchThreads = mutableMapOf<Thread, Int>()

    fun dispatch(result: BifrostProbeCoordinatorResult) {
        dispatchInternal { listener(result) }
    }

    fun dispatchFailure(source: String, error: Throwable) {
        dispatchInternal { failure(source, error) }
    }

    private fun dispatchInternal(callback: () -> Unit) {
        synchronized(gate) {
            if (!active) return
            dispatching += 1
            val thread = Thread.currentThread()
            dispatchThreads[thread] = (dispatchThreads[thread] ?: 0) + 1
        }
        try {
            runCatching { callback() }
        } finally {
            synchronized(gate) {
                dispatching -= 1
                val thread = Thread.currentThread()
                val depth = (dispatchThreads[thread] ?: 1) - 1
                if (depth <= 0) dispatchThreads.remove(thread) else dispatchThreads[thread] = depth
                if (dispatching == 0) (gate as java.lang.Object).notifyAll()
            }
        }
    }

    override fun close() {
        synchronized(gate) {
            active = false
            if (dispatchThreads.containsKey(Thread.currentThread())) return
            var interrupted = false
            while (dispatching > 0) {
                try { (gate as java.lang.Object).wait() } catch (_: InterruptedException) { interrupted = true }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}

/**
 * Owns the process-wide Android network callback independently from listener
 * and lifecycle locks.  Installation is single-flight: concurrent leases
 * wait for the one installation result, while a final release during an
 * installation causes the just-created callback to be closed before it can
 * become observable.  All close operations happen outside the state lock.
 */
internal class BifrostNetworkObserverOwner(
    private val observe: ((() -> Unit) -> Closeable?),
) : Closeable {
    private val gate = Any()
    private var observer: Closeable? = null
    private var demand = 0
    private var installing = false
    private var closed = false
    private var dispatching = 0
    private val dispatchThreads = mutableMapOf<Thread, Int>()

    fun acquire(onChanged: () -> Unit): Closeable {
        var counted = false
        while (true) {
            var install = false
            synchronized(gate) {
                if (closed) throw IllegalStateException("BF-NETWORK-OBSERVER-CLOSED")
                if (!counted) {
                    demand += 1
                    counted = true
                }
                if (observer != null) return lease()
                if (!installing) {
                    installing = true
                    install = true
                } else {
                    try { (gate as java.lang.Object).wait() }
                    catch (error: InterruptedException) {
                        demand = (demand - 1).coerceAtLeast(0)
                        (gate as java.lang.Object).notifyAll()
                        Thread.currentThread().interrupt()
                        throw error
                    }
                }
            }
            if (!install) continue
            val created = try {
                observe { dispatch(onChanged) } ?: error("BF-NETWORK-OBSERVER-UNAVAILABLE")
            } catch (error: Throwable) {
                synchronized(gate) {
                    installing = false
                    demand = (demand - 1).coerceAtLeast(0)
                    (gate as java.lang.Object).notifyAll()
                }
                throw error
            }
            var keep = false
            synchronized(gate) {
                installing = false
                if (!closed && demand > 0 && observer == null) {
                    observer = created
                    keep = true
                }
                (gate as java.lang.Object).notifyAll()
            }
            if (!keep) {
                runCatching { created.close() }
                synchronized(gate) {
                    if (closed) {
                        demand = (demand - 1).coerceAtLeast(0)
                        throw IllegalStateException("BF-NETWORK-OBSERVER-CLOSED")
                    }
                }
            }
            return lease()
        }
    }

    internal fun demandCountForTest(): Int = synchronized(gate) { demand }
    internal fun hasObserverForTest(): Boolean = synchronized(gate) { observer != null }

    private fun dispatch(onChanged: () -> Unit) {
        synchronized(gate) {
            if (closed || demand == 0) return
            dispatching += 1
            val thread = Thread.currentThread()
            dispatchThreads[thread] = (dispatchThreads[thread] ?: 0) + 1
        }
        try { onChanged() } finally {
            synchronized(gate) {
                dispatching -= 1
                val thread = Thread.currentThread()
                val depth = (dispatchThreads[thread] ?: 1) - 1
                if (depth <= 0) dispatchThreads.remove(thread) else dispatchThreads[thread] = depth
                (gate as java.lang.Object).notifyAll()
            }
        }
    }

    private fun lease(): Closeable {
        val released = AtomicBoolean(false)
        return Closeable { if (released.compareAndSet(false, true)) release() }
    }

    private fun release() {
        var toClose: Closeable? = null
        synchronized(gate) {
            if (demand <= 0) return
            demand -= 1
            if (demand == 0 && !installing) {
                toClose = observer
                observer = null
            }
            (gate as java.lang.Object).notifyAll()
        }
        runCatching { toClose?.close() }
    }

    override fun close() {
        var toClose: Closeable? = null
        synchronized(gate) {
            if (closed) return
            closed = true
            demand = 0
            if (!installing) {
                toClose = observer
                observer = null
            }
            if (!dispatchThreads.containsKey(Thread.currentThread())) {
                var interrupted = false
                while (dispatching > 0) {
                    try { (gate as java.lang.Object).wait() }
                    catch (_: InterruptedException) { interrupted = true }
                }
                if (interrupted) Thread.currentThread().interrupt()
            }
            (gate as java.lang.Object).notifyAll()
        }
        runCatching { toClose?.close() }
    }
}

internal class BifrostCandidateProbeCoordinator(context: Context) : Closeable {
    private val appContext = context.applicationContext
    private val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "bifrost-candidate-probe").apply { isDaemon = true }
    }
    private val listeners = mutableSetOf<BifrostProbeListenerRegistration>()
    private val listenerGate = Any()
    private val connectionLeaseIds = AtomicLong(0L)
    @Volatile private var closed = false
    private val observerOwner = BifrostNetworkObserverOwner { callback ->
        AndroidNetworkBucket.observe(appContext, callback)
    }
    private lateinit var lifecycle: BifrostProbeLifecycleCoordinator

    init {
        lifecycle = BifrostProbeLifecycleCoordinator(
            scheduler = ExecutorProbeScheduler(executor),
            load = { source ->
                val cached = BifrostConfigStore.load(appContext)
                if (cached == null) null else BifrostProbeFingerprints.input(
                    cached,
                    source,
                    AndroidNetworkBucket.fingerprint(appContext),
                )
            },
            probe = { input, key, cancellation, isCurrent ->
                BifrostCandidateSelector.select(
                    appContext,
                    input.content,
                    input.source,
                    cancellation = cancellation,
                    binding = key,
                    commitIfCurrent = { commit -> lifecycle.commitIfCurrent(key, cancellation, commit) },
                )
            },
            publish = { result ->
                // Snapshot registration ownership, then admit each consumer
                // independently.  A first callback may synchronously change
                // source/network/config; that transition invalidates the
                // admission before the next registration is invoked.
                val snapshot = synchronized(listenerGate) { listeners.toList() }
                snapshot.forEach { registration ->
                    result.delivery?.deliver { registration.dispatch(result) }
                        ?: registration.dispatch(result)
                }
            },
            unavailable = { _, _ -> },
            unavailableAdmitted = { source, error, admission ->
                val snapshot = synchronized(listenerGate) { listeners.toList() }
                snapshot.forEach { registration ->
                    admission.deliver { registration.dispatchFailure(source, error) }
                }
            },
        )
    }

    fun acquireLease(
        owner: String,
        source: String?,
        listener: (BifrostProbeCoordinatorResult) -> Unit,
        failure: (source: String, error: Throwable) -> Unit = { _, _ -> },
    ): Closeable {
        if (closed) return Closeable { }
        val registration = BifrostProbeListenerRegistration(listener, failure)
        synchronized(listenerGate) {
            if (closed) return Closeable { }
            listeners += registration
        }
        val observerLease = try {
            observerOwner.acquire {
                // Invalidation is synchronous with the event and is never
                // queued behind the single-thread probe executor.
                if (!closed) lifecycle.networkChanged()
            }
        } catch (error: Throwable) {
            removeRegistration(registration)
            throw error
        }
        val lease = try {
            // No listenerGate is held while the lifecycle gate is acquired.
            // The wrapper-owned count below is the sole observer lifetime
            // authority, so release never queries lifecycle state under it.
            lifecycle.acquireLease(owner, source)
        } catch (error: Throwable) {
            observerLease.close()
            removeRegistration(registration)
            throw error
        }
        if (closed) {
            lease.close()
            observerLease.close()
            removeRegistration(registration)
            return Closeable { }
        }
        val released = AtomicBoolean(false)
        return Closeable {
            if (!released.compareAndSet(false, true)) return@Closeable
            lease.close()
            registration.close()
            observerLease.close()
            removeRegistration(registration)
        }
    }

    private fun removeRegistration(registration: BifrostProbeListenerRegistration) {
        synchronized(listenerGate) { listeners.remove(registration) }
    }

    fun updateSource(source: String) {
        lifecycle.updateSource(source)
    }

    fun refreshNow(source: String? = null, forceTransition: Boolean = true) {
        lifecycle.refreshNow(source, forceTransition)
    }

    internal fun captureConnectionGeneration(input: BifrostProbeRoundInput): Long =
        lifecycle.captureConnectionGeneration(input)

    fun selectForConnection(source: String, requested: String?, callback: (Result<BifrostCandidateSelectionReceipt>) -> Unit): BifrostConnectionProbeRequest {
        if (closed) {
            return BifrostConnectionProbeRequest(callback).also {
                it.complete(Result.failure(IllegalStateException("BF-PROBE-CLOSED")))
            }
        }
        val normalized = source.trim().uppercase()
        if (!requested.isNullOrBlank()) {
            // Explicit candidate labels are a pure signed-source resolution;
            // they never create a second probe round or cache bucket, but the
            // preflight binding is still re-read before accepting the label.
            val preflightInput = runCatching {
                val cached = BifrostConfigStore.load(appContext) ?: error("BF-CONFIG-CACHE-MISSING")
                BifrostProbeFingerprints.input(cached, normalized, AndroidNetworkBucket.fingerprint(appContext))
                    ?: error("BF-SOURCE-NOT-READY")
            }
            val request = BifrostConnectionProbeRequest(
                callback,
                preflightInput.getOrNull()?.let { input ->
                    BifrostProbeConnectionBinding.from(input, lifecycle.captureConnectionGeneration(input))
                },
            )
            val preflight = preflightInput
            if (preflight.isFailure) {
                request.complete(Result.failure(preflight.exceptionOrNull() ?: IllegalStateException("BF-SOURCE-NOT-READY")))
                return request
            }
            // Signed seed resolution runs on the caller's IO context. It must
            // not wait behind the shared executor's background network probes.
            request.complete(runCatching {
                if (closed) error("BF-PROBE-CLOSED")
                val cached = BifrostConfigStore.load(appContext) ?: error("BF-CONFIG-CACHE-MISSING")
                val latestInput = BifrostProbeFingerprints.input(
                    cached,
                    normalized,
                    AndroidNetworkBucket.fingerprint(appContext),
                ) ?: error("BF-SOURCE-NOT-READY")
                val expected = requestBinding(request)
                val latestGeneration = lifecycle.captureConnectionGeneration(latestInput)
                if (latestInput != preflight.getOrThrow() ||
                    latestInput.networkFingerprint != AndroidNetworkBucket.fingerprint(appContext)) {
                    error("BF-PROBE-BINDING-CHANGED")
                }
                val label = BifrostCandidateSelector.select(appContext, cached.content, normalized, requested = requested)
                val binding = BifrostProbeConnectionBinding.from(latestInput, latestGeneration)
                if (expected != null && expected != binding) error("BF-PROBE-BINDING-CHANGED")
                BifrostCandidateSelectionReceipt(label, binding)
            })
            return request
        }

        // A connection is an ephemeral lease on the same lifecycle owner,
        // not a private selector/executor.  Existing Activity/Service leases
        // therefore coalesce on the same immutable round key; if none exists
        // this lease supplies demand until the shared result arrives.
        val ready = runCatching {
            val cached = BifrostConfigStore.load(appContext) ?: error("BF-CONFIG-CACHE-MISSING")
            BifrostProbeFingerprints.input(cached, normalized, AndroidNetworkBucket.fingerprint(appContext))
                ?: error("BF-SOURCE-NOT-READY")
        }
        if (ready.isFailure) {
            return BifrostConnectionProbeRequest(callback).also {
                it.complete(Result.failure(ready.exceptionOrNull() ?: IllegalStateException("BF-SOURCE-NOT-READY")))
            }
        }
        val readyInput = ready.getOrThrow()
        if (closed) {
            return BifrostConnectionProbeRequest(callback).also {
                it.complete(Result.failure(IllegalStateException("BF-PROBE-CLOSED")))
            }
        }
        val expectedBinding = BifrostProbeConnectionBinding.from(
            readyInput,
            lifecycle.captureConnectionGeneration(readyInput),
        )
        val request = BifrostConnectionProbeRequest(callback, expectedBinding)
        val owner = "connection:${connectionLeaseIds.incrementAndGet()}"
        val listener: (BifrostProbeCoordinatorResult) -> Unit = { result ->
            if (result.source.equals(normalized, true)) {
                request.completeFromProbe(result)
            }
        }
        val lease = acquireLease(
            owner,
            normalized,
            listener,
            failure = { failedSource, error ->
                if (failedSource.equals(normalized, true)) request.complete(Result.failure(error))
            },
        )
        // The scheduler seam may dispatch inline before acquireLease returns;
        // attach() closes that just-created lease in the callback-before-handle
        // case instead of leaking demand/listeners.
        request.attach(lease)
        // A connection demand joins an already-running identical round; it
        // must not retire that round merely because it arrived concurrently.
        refreshNow(normalized, forceTransition = false)
        return request
    }

    private fun requestBinding(request: BifrostConnectionProbeRequest): BifrostProbeConnectionBinding? = request.expectedBindingForValidation()

    override fun close() {
        if (closed) return
        closed = true
        val registrations: List<BifrostProbeListenerRegistration>
        synchronized(listenerGate) {
            registrations = listeners.toList()
            listeners.clear()
        }
        observerOwner.close()
        lifecycle.close()
        registrations.forEach { it.close() }
    }

    /** Per-lease dispatch fence. close() waits for an in-flight callback, but
     * recognizes self-close from a callback so an ephemeral request cannot
     * deadlock itself. */
}
