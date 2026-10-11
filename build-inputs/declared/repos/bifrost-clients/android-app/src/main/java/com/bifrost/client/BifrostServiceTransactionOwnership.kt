package com.bifrost.client

/** Complete service correlation token.  Bindings are part of ownership. */
internal data class BifrostServiceTransactionToken(
    val transactionId: String,
    val generation: String,
    val digest: String,
    val bindings: String,
)

internal enum class BifrostServiceOwnershipPhase {
    IDLE,
    PENDING,
    COMMITTED,
    BLOCKED_FAILED,
    UNPROTECTED_FAILED,
    DISCONNECTING,
}

internal enum class BifrostServiceRuntimeAction { NONE, STARTING, READY, BLOCK, DISCONNECT, ABORT }
internal enum class BifrostServiceForegroundAction { PRESERVE, CONNECTED, BLOCKED, STOP_REMOVE }

internal data class BifrostServiceLifecycleDecision(
    val accepted: Boolean,
    val runtimeAction: BifrostServiceRuntimeAction,
    val foregroundAction: BifrostServiceForegroundAction,
    val stopSelf: Boolean,
    val ackToken: BifrostServiceTransactionToken?,
    val phase: BifrostServiceOwnershipPhase,
)

/**
 * Pure service ownership/lifecycle state machine.  It is called by the real
 * onStartCommand path and has no Android/runtime side effects.  Once the
 * Bifrost-owned fence is established, a failed core moves to BLOCKED_FAILED;
 * only a complete matching token can release that boundary.
 */
internal class BifrostServiceTransactionOwnership {
    private var pending: BifrostServiceTransactionToken? = null
    private var committed: BifrostServiceTransactionToken? = null
    private var blocked: BifrostServiceTransactionToken? = null
    private var unprotected: BifrostServiceTransactionToken? = null
    private var disconnecting: BifrostServiceTransactionToken? = null
    private var disconnectingOriginalPhase: BifrostServiceOwnershipPhase? = null
    private var fenceEstablished = false
    private var lastDecision = BifrostServiceLifecycleDecision(
        accepted = false,
        runtimeAction = BifrostServiceRuntimeAction.NONE,
        foregroundAction = BifrostServiceForegroundAction.PRESERVE,
        stopSelf = false,
        ackToken = null,
        phase = BifrostServiceOwnershipPhase.IDLE,
    )

    @Synchronized
    fun decision(): BifrostServiceLifecycleDecision = lastDecision

    private fun decide(
        accepted: Boolean,
        runtimeAction: BifrostServiceRuntimeAction,
        foregroundAction: BifrostServiceForegroundAction,
        stopSelf: Boolean,
        ackToken: BifrostServiceTransactionToken?,
    ) {
        lastDecision = BifrostServiceLifecycleDecision(
            accepted, runtimeAction, foregroundAction, stopSelf, ackToken, phase(),
        )
    }

    @Synchronized
    fun phase(): BifrostServiceOwnershipPhase = when {
        disconnecting != null -> BifrostServiceOwnershipPhase.DISCONNECTING
        blocked != null -> BifrostServiceOwnershipPhase.BLOCKED_FAILED
        unprotected != null -> BifrostServiceOwnershipPhase.UNPROTECTED_FAILED
        committed != null -> BifrostServiceOwnershipPhase.COMMITTED
        pending != null -> BifrostServiceOwnershipPhase.PENDING
        else -> BifrostServiceOwnershipPhase.IDLE
    }

    @Synchronized
    fun hasOwner(): Boolean = pending != null || committed != null || blocked != null || unprotected != null || disconnecting != null

    @Synchronized
    fun pendingToken(): BifrostServiceTransactionToken? = pending

    @Synchronized
    fun committedToken(): BifrostServiceTransactionToken? = committed

    @Synchronized
    fun blockedToken(): BifrostServiceTransactionToken? = blocked

    @Synchronized
    fun unprotectedToken(): BifrostServiceTransactionToken? = unprotected

    @Synchronized
    fun disconnectingToken(): BifrostServiceTransactionToken? = disconnecting

    @Synchronized
    fun runtimeFenceEstablished(token: BifrostServiceTransactionToken): Boolean =
        (pending == token || committed == token || blocked == token) && fenceEstablished

    /** True when the exact owner has crossed the runtime boundary, including
     * a committed or already-blocked owner.  Catch paths use this instead of
     * inferring the phase from a nullable pending field. */
    @Synchronized
    fun fenceEstablishedFor(token: BifrostServiceTransactionToken): Boolean =
        (pending == token || committed == token || blocked == token) && fenceEstablished

    @Synchronized
    fun begin(token: BifrostServiceTransactionToken): Boolean {
        if (hasOwner()) {
            decide(false, BifrostServiceRuntimeAction.NONE, BifrostServiceForegroundAction.PRESERVE, false, token)
            return false
        }
        pending = token
        fenceEstablished = false
        decide(true, BifrostServiceRuntimeAction.STARTING, BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    /** Rehydrate a live Service owner after Service recreation.  The registry
     * is the authority; this method never mints a token or snapshot. */
    @Synchronized
    fun adoptExisting(token: BifrostServiceTransactionToken, ownerPhase: BifrostServiceOwnershipPhase): Boolean {
        if (hasOwner()) return false
        when (ownerPhase) {
            BifrostServiceOwnershipPhase.PENDING -> pending = token
            BifrostServiceOwnershipPhase.COMMITTED -> committed = token
            BifrostServiceOwnershipPhase.BLOCKED_FAILED -> blocked = token
            BifrostServiceOwnershipPhase.UNPROTECTED_FAILED -> unprotected = token
            else -> return false
        }
        fenceEstablished = true
        decide(true, BifrostServiceRuntimeAction.NONE, BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    @Synchronized
    fun markFenceEstablished(token: BifrostServiceTransactionToken): Boolean {
        if (pending != token) return false
        fenceEstablished = true
        decide(true, BifrostServiceRuntimeAction.STARTING, BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    @Synchronized
    fun ready(token: BifrostServiceTransactionToken): Boolean {
        if (pending != token || !fenceEstablished) return false
        pending = null
        committed = token
        fenceEstablished = true
        decide(true, BifrostServiceRuntimeAction.READY, BifrostServiceForegroundAction.CONNECTED, false, token)
        return true
    }

    /**
     * A failure after the COMMITTED transition is still recoverable.  Retain
     * the exact fenced owner as BLOCKED_FAILED so a later exact disconnect can
     * release it; never leave an owner in a phase the catch path cannot reach.
     */
    @Synchronized
    fun failAfterCommit(token: BifrostServiceTransactionToken): Boolean {
        if (committed != token || !fenceEstablished) return false
        committed = null
        blocked = token
        decide(true, BifrostServiceRuntimeAction.BLOCK, BifrostServiceForegroundAction.BLOCKED, false, token)
        return true
    }

    /** Keep a committed owner addressable when blocking itself failed.  The
     * caller must not report BLOCKED; move it to an explicit unprotected phase
     * so an exact retry/disconnect remains available. */
    @Synchronized
    fun retainCommittedUnprotected(token: BifrostServiceTransactionToken): Boolean {
        if (committed != token || !fenceEstablished) return false
        committed = null
        unprotected = token
        fenceEstablished = false
        decide(false, BifrostServiceRuntimeAction.ABORT, BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    /** Failure before the fence exists: no retained owner and no sticky service. */
    @Synchronized
    fun failBeforeFence(token: BifrostServiceTransactionToken): Boolean {
        if (pending != token || fenceEstablished) return false
        pending = null
        fenceEstablished = false
        decide(true, BifrostServiceRuntimeAction.ABORT, BifrostServiceForegroundAction.STOP_REMOVE, true, token)
        return true
    }

    /** Failure after fencing: retain the exact token for explicit disconnect. */
    @Synchronized
    fun failAfterFence(token: BifrostServiceTransactionToken): Boolean {
        if (pending != token || !fenceEstablished) return false
        pending = null
        blocked = token
        fenceEstablished = true
        decide(true, BifrostServiceRuntimeAction.BLOCK, BifrostServiceForegroundAction.BLOCKED, false, token)
        return true
    }

    /** Fence/core failure itself was not established.  A confirmed native
     * teardown may return IDLE; otherwise retain an explicit unprotected owner. */
    @Synchronized
    fun failFenceUnavailable(token: BifrostServiceTransactionToken): Boolean {
        return failFenceUnavailable(token, teardownConfirmed = false)
    }

    /** A failed re-block with unconfirmed native stop is an explicit
     * unprotected owner, never IDLE and never BLOCKED. */
    @Synchronized
    fun failFenceUnavailable(token: BifrostServiceTransactionToken, teardownConfirmed: Boolean): Boolean {
        if (pending != token || !fenceEstablished) return false
        pending = null
        committed = null
        blocked = null
        if (teardownConfirmed) {
            unprotected = null
            fenceEstablished = false
            decide(true, BifrostServiceRuntimeAction.ABORT, BifrostServiceForegroundAction.STOP_REMOVE, true, token)
        } else {
            unprotected = token
            fenceEstablished = false
            decide(true, BifrostServiceRuntimeAction.ABORT, BifrostServiceForegroundAction.PRESERVE, false, token)
        }
        return true
    }

    /** Begin an exact disconnect without discarding ownership.  Runtime/core
     * teardown must prove success before completeDisconnect() clears it. */
    @Synchronized
    fun beginDisconnect(token: BifrostServiceTransactionToken): Boolean {
        // A duplicate command must not start a second runtime teardown while
        // the first exact command is still in flight.
        if (disconnecting == token) return false
        if (pending != token && committed != token && blocked != token && unprotected != token) {
            decide(false, BifrostServiceRuntimeAction.NONE,
                if (hasOwner()) BifrostServiceForegroundAction.PRESERVE else BifrostServiceForegroundAction.STOP_REMOVE,
                !hasOwner(), token)
            return false
        }
        disconnecting = token
        disconnectingOriginalPhase = when {
            pending == token -> BifrostServiceOwnershipPhase.PENDING
            committed == token -> BifrostServiceOwnershipPhase.COMMITTED
            unprotected == token -> BifrostServiceOwnershipPhase.UNPROTECTED_FAILED
            else -> BifrostServiceOwnershipPhase.BLOCKED_FAILED
        }
        decide(true, BifrostServiceRuntimeAction.DISCONNECT, BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    /** Compatibility name retained only as a safe begin operation.  It never
     * claims IDLE and therefore cannot demonstrate the former ownership-loss
     * ordering bug. */
    @Synchronized
    fun disconnectExact(token: BifrostServiceTransactionToken): Boolean = beginDisconnect(token)

    @Synchronized
    fun completeDisconnect(token: BifrostServiceTransactionToken): Boolean {
        if (disconnecting != token) return false
        disconnecting = null
        disconnectingOriginalPhase = null
        pending = null
        committed = null
        blocked = null
        unprotected = null
        fenceEstablished = false
        decide(true, BifrostServiceRuntimeAction.DISCONNECT, BifrostServiceForegroundAction.STOP_REMOVE, true, token)
        return true
    }

    /** Finalize registry proof and ownership under one production decision.
     * If registry proof fails, the disconnecting owner remains available for
     * the exact retry path. */
    @Synchronized
    fun completeDisconnectWithRelease(
        token: BifrostServiceTransactionToken,
        release: () -> BifrostServiceReleaseReceipt?,
    ): BifrostServiceReleaseReceipt? {
        if (disconnecting != token) return null
        val receipt = release() ?: return null
        disconnecting = null
        disconnectingOriginalPhase = null
        pending = null
        committed = null
        blocked = null
        unprotected = null
        fenceEstablished = false
        decide(true, BifrostServiceRuntimeAction.DISCONNECT, BifrostServiceForegroundAction.STOP_REMOVE, true, token)
        return receipt
    }

    /** A failed teardown retains the exact owner.  BLOCKED_FAILED is allowed
     * only when the current runtime outcome proves a physical block; a false
     * outcome is retained as explicit UNPROTECTED_FAILED for exact retry. */
    @Synchronized
    fun failDisconnect(token: BifrostServiceTransactionToken, boundaryBlocked: Boolean = false): Boolean {
        if (disconnecting != token) return false
        disconnecting = null
        disconnectingOriginalPhase = null
        if (boundaryBlocked) {
            pending = null
            committed = null
            blocked = token
            unprotected = null
            fenceEstablished = true
            decide(true, BifrostServiceRuntimeAction.BLOCK, BifrostServiceForegroundAction.BLOCKED, false, token)
        } else {
            // A failed disconnect is authoritative only for the *current*
            // runtime outcome.  Historical BLOCKED_FAILED state is not
            // physical evidence: when boundaryBlocked is false every exact
            // retry owner is explicitly unprotected, including a formerly
            // blocked or still-pending owner.  This prevents a stale BLOCKED
            // label from surviving a false physical result.
            pending = null
            committed = null
            blocked = null
            unprotected = token
            fenceEstablished = false
            decide(true, BifrostServiceRuntimeAction.ABORT, BifrostServiceForegroundAction.PRESERVE, false, token)
        }
        return true
    }

    /** Exact owner cleanup for an independently verified missing Root runtime.
     * Unlike a normal disconnect there is no boundary left to release, so no
     * release receipt is minted and the old token can never be reused. */
    @Synchronized
    fun abandonMissingRuntime(token: BifrostServiceTransactionToken): Boolean {
        if (pending != token && committed != token && blocked != token &&
            unprotected != token && disconnecting != token) return false
        pending = null
        committed = null
        blocked = null
        unprotected = null
        disconnecting = null
        disconnectingOriginalPhase = null
        fenceEstablished = false
        decide(true, BifrostServiceRuntimeAction.ABORT,
            BifrostServiceForegroundAction.PRESERVE, false, token)
        return true
    }

    @Synchronized
    @JvmSynthetic
    fun clear() {
        pending = null
        committed = null
        blocked = null
        unprotected = null
        disconnecting = null
        disconnectingOriginalPhase = null
        fenceEstablished = false
        decide(false, BifrostServiceRuntimeAction.NONE, BifrostServiceForegroundAction.PRESERVE, false, null)
    }
}

/** Complete immutable metadata handed from Service to a recreated Activity. */
internal data class BifrostServiceConnectionDescription(
    val core: String,
    val mode: String,
    val source: String,
    val country: String,
    val frontSource: String,
    val candidate: String?,
    val connectionType: String = BifrostConnectionType.DIRECT_VMESH.wireValue,
)

/** Same-process status handoff used when an Activity is recreated. */
internal data class BifrostServiceOwnershipSnapshot(
    val phase: BifrostServiceOwnershipPhase,
    val token: BifrostServiceTransactionToken,
    val snapshot: BifrostApplicationPolicySnapshot,
    val description: BifrostServiceConnectionDescription,
)

/** Monotonic Service-owned proof that the exact owner was released. */
internal data class BifrostServiceReleaseReceipt(
    val token: BifrostServiceTransactionToken,
    val epoch: Long,
)

internal data class BifrostServiceRegistryStatus(
    val owner: BifrostServiceOwnershipSnapshot?,
    val release: BifrostServiceReleaseReceipt?,
    val globalOwner: BifrostServiceOwnershipSnapshot?,
)

internal object BifrostServiceOwnershipRegistry {
    @Volatile private var current: BifrostServiceOwnershipSnapshot? = null
    @Volatile private var lastReleased: BifrostServiceReleaseReceipt? = null
    /** Exact Activity handoffs, keyed by the complete token.  A global
     * zero-argument lookup is deliberately not an authority surface. */
    private val disconnectRequests = LinkedHashMap<String, BifrostServiceTransactionToken>()
    private var releaseEpoch = 0L
    private val consumedReleaseEpochs = LinkedHashMap<String, Long>()
    private val retired = LinkedHashMap<String, Long>()
    // A bounded Bloom history prevents an evicted retired entry from being
    // resurrected by a delayed duplicate token.  False positives fail closed.
    private val retiredBloom = java.util.BitSet(4096)
    private val pendingReleases = LinkedHashMap<String, BifrostServiceReleaseReceipt>()
    private const val MAX_RETIRED = 64
    private const val MAX_PENDING_RELEASES = 8

    @Synchronized
    fun publish(
        phase: BifrostServiceOwnershipPhase,
        token: BifrostServiceTransactionToken,
        snapshot: BifrostApplicationPolicySnapshot,
        description: BifrostServiceConnectionDescription,
    ) {
        BifrostApplicationPolicySnapshot.verify(snapshot)
        require(token.generation == snapshot.generation && token.digest == snapshot.digest) {
            "BF-CONNECTION-TOKEN"
        }
        val boundPackages = runCatching { BifrostApplicationPackageBindings.decode(token.bindings) }
            .getOrElse { throw IllegalArgumentException("BF-APP-PACKAGE-INVALID") }
        require(boundPackages.map { it.packageName } == snapshot.identities) {
            "BF-APP-PACKAGE-INVALID"
        }
        require(BifrostServiceConnectionMetadata.complete(description, BifrostServiceConnectionMetadata.REQUIRED_FIELDS)) {
            "BF-CONNECTION-DESCRIPTION"
        }
        val key = tokenKey(token)
        check(!retired.containsKey(key) && !retiredBloomContains(key)) { "BF-CONNECTION-RELEASED" }
        val existing = current
        if (existing != null) {
            check(existing.token == token) { "BF-CONNECTION-ACTIVE" }
        }
        current = BifrostServiceOwnershipSnapshot(phase, token, snapshot, description)
    }

    @Synchronized
    fun current(): BifrostServiceOwnershipSnapshot? = current

    @Synchronized
    fun isRetired(token: BifrostServiceTransactionToken): Boolean {
        val key = tokenKey(token)
        return retired.containsKey(key) || retiredBloomContains(key)
    }

    @Synchronized
    fun requestDisconnect(token: BifrostServiceTransactionToken) {
        val key = tokenKey(token)
        disconnectRequests[key] = token
        while (disconnectRequests.size > MAX_PENDING_RELEASES) {
            disconnectRequests.remove(disconnectRequests.entries.first().key)
        }
    }

    @Synchronized
    fun isDisconnectRequested(token: BifrostServiceTransactionToken): Boolean =
        disconnectRequests[tokenKey(token)] == token

    /** Compatibility query intentionally returns no token.  Recovery must use
     * a token retained by the exact Activity handoff, never global discovery. */
    @Synchronized
    fun requestedDisconnect(): BifrostServiceTransactionToken? = null

    @Synchronized
    fun requestedDisconnectFor(token: BifrostServiceTransactionToken): BifrostServiceTransactionToken? =
        disconnectRequests[tokenKey(token)]?.takeIf { it == token }

    @Synchronized
    fun clearDisconnect(token: BifrostServiceTransactionToken) {
        disconnectRequests.remove(tokenKey(token), token)
    }

    /** Java-visible compatibility/query surface: it can never issue a new
     * receipt.  Issuance is confined to the coordinator-only exact method. */
    @Synchronized
    fun noteReleased(token: BifrostServiceTransactionToken): BifrostServiceReleaseReceipt? =
        lastReleased?.takeIf { it.token == token }

    /** Coordinator-only receipt finalization after a proven DISCONNECTING
     * transition.  @JvmSynthetic prevents same-package Java callers from
     * treating this as a release capability. */
    @Synchronized
    @JvmSynthetic
    internal fun noteReleasedExact(token: BifrostServiceTransactionToken): BifrostServiceReleaseReceipt? {
        if (current == null) return lastReleased?.takeIf { it.token == token }
        val existing = current ?: return null
        if (existing.token != token) return null
        if (existing.phase != BifrostServiceOwnershipPhase.DISCONNECTING) return null
        releaseEpoch++
        val receipt = BifrostServiceReleaseReceipt(token, releaseEpoch)
        lastReleased = receipt
        pendingReleases[tokenKey(token)] = receipt
        while (pendingReleases.size > MAX_PENDING_RELEASES) {
            val evictedKey = pendingReleases.entries.first().key
            pendingReleases.remove(evictedKey)
            // An evicted receipt must not leave an orphaned Activity request
            // that can be rediscovered forever.
            disconnectRequests.remove(evictedKey)
        }
        val key = tokenKey(token)
        retired[key] = releaseEpoch
        retiredBloomMark(key)
        while (retired.size > MAX_RETIRED) retired.remove(retired.entries.first().key)
        current = null
        return receipt
    }

    /** Duplicate disconnects for the exact already-released owner are an
     * authoritative idle result; a different live owner is never treated as
     * idle. */
    @Synchronized
    fun authoritativeIdle(token: BifrostServiceTransactionToken): Boolean =
        current == null && lastReleased?.token == token

    @Synchronized
    fun releaseReceipt(token: BifrostServiceTransactionToken): BifrostServiceReleaseReceipt? =
        pendingReleases[tokenKey(token)]
            ?: lastReleased?.takeIf { it.token == token }

    /** Exact request-bound discovery.  The caller must already possess the
     * complete token from its own Activity handoff. */
    @Synchronized
    fun releaseDiscovery(token: BifrostServiceTransactionToken): BifrostServiceReleaseReceipt? {
        val key = tokenKey(token)
        return pendingReleases[key]?.takeIf { disconnectRequests[key] == token }
    }

    @Synchronized
    fun releaseDiscoveryToken(token: BifrostServiceTransactionToken): BifrostServiceTransactionToken? =
        releaseDiscovery(token)?.token

    /** Compatibility no-op: there is no zero-authority receipt enumeration. */
    @Synchronized
    fun releaseDiscovery(): BifrostServiceReleaseReceipt? = null

    /** Compatibility no-op: there is no zero-authority token enumeration. */
    @Synchronized
    fun releaseDiscoveryToken(): BifrostServiceTransactionToken? = null

    /** Atomically consume the exact receipt epoch.  The receipt remains
     * readable for a recreated Activity/status query; consumption is monotonic
     * and cannot be forged from a null-owner observation. */
    @Synchronized
    fun consumeReleaseReceipt(token: BifrostServiceTransactionToken, epoch: Long): Boolean {
        val key = tokenKey(token)
        // Only an exact pending receipt may be consumed.  In particular, do
        // not use lastReleased or a global epoch high-water mark: independent
        // handoffs may be consumed in either order.
        val receipt = pendingReleases[key] ?: return false
        if (receipt.epoch != epoch || consumedReleaseEpochs.containsKey(key)) return false
        pendingReleases.remove(key)
        consumedReleaseEpochs[key] = epoch
        while (consumedReleaseEpochs.size > MAX_RETIRED) {
            consumedReleaseEpochs.remove(consumedReleaseEpochs.entries.first().key)
        }
        disconnectRequests.remove(key, token)
        return true
    }

    @Synchronized
    fun status(token: BifrostServiceTransactionToken): BifrostServiceRegistryStatus =
        BifrostServiceRegistryStatus(current?.takeIf { it.token == token }, releaseReceipt(token), current)

    private fun tokenKey(token: BifrostServiceTransactionToken): String =
        listOf(token.transactionId, token.generation, token.digest, token.bindings).joinToString("\u0000")

    @Synchronized
    /** Compatibility no-op: release clients cannot erase owner/epoch state. */
    fun reset() = Unit

    private fun resetState() {
        current = null
        lastReleased = null
        disconnectRequests.clear()
        releaseEpoch = 0L
        consumedReleaseEpochs.clear()
        retired.clear()
        pendingReleases.clear()
        retiredBloom.clear()
    }

    @Synchronized
    fun clear() = Unit

    /** Java-visible compatibility surface; it cannot erase ownership. */
    @Synchronized
    fun clearExact(token: BifrostServiceTransactionToken) = Unit

    @Synchronized
    @JvmSynthetic
    internal fun clearExactInternal(token: BifrostServiceTransactionToken) {
        if (current?.token == token) current = null
    }

    /** Root process death is not a successful disconnect, so it must not
     * create a release receipt.  It is nevertheless authoritative proof that
     * the process-local token can never own a live remote runtime again. */
    @Synchronized
    @JvmSynthetic
    internal fun retireMissingRuntimeInternal(token: BifrostServiceTransactionToken): Boolean {
        if (current?.token != token) return false
        val key = tokenKey(token)
        releaseEpoch++
        retired[key] = releaseEpoch
        retiredBloomMark(key)
        while (retired.size > MAX_RETIRED) retired.remove(retired.entries.first().key)
        current = null
        disconnectRequests.remove(key)
        pendingReleases.remove(key)
        return true
    }

    private fun retiredBloomContains(key: String): Boolean {
        val first = Math.floorMod(key.hashCode(), 4096)
        val second = Math.floorMod(key.hashCode() xor 0x5bd1e995.toInt(), 4096)
        return retiredBloom[first] && retiredBloom[second]
    }

    private fun retiredBloomMark(key: String) {
        retiredBloom.set(Math.floorMod(key.hashCode(), 4096))
        retiredBloom.set(Math.floorMod(key.hashCode() xor 0x5bd1e995.toInt(), 4096))
    }
}
