package com.bifrost.client

/**
 * Pure transaction state machine used by the Activity acknowledgement path.
 * A token is the only authority for a pending connection; committed state is
 * deliberately not cancellable through this gate.  This keeps late,
 * duplicate, out-of-order and cross-generation callbacks harmless.
 */
internal data class BifrostConnectionTransactionToken(
    val transactionId: String,
    val generation: String,
    val digest: String,
    val bindings: String,
)

internal enum class BifrostConnectionTransactionPhase {
    IDLE,
    STARTING,
    READY_PENDING_COMMIT,
    COMMITTED,
    BLOCKED_FAILED,
    DISCONNECTING,
    FAILED,
    CANCELLED,
}

internal sealed class BifrostConnectionAckDecision {
    data object Ignored : BifrostConnectionAckDecision()
    data class Failed(
        val code: String,
        val compensate: Boolean,
        val blocked: Boolean = false,
        val token: BifrostConnectionTransactionToken? = null,
    ) : BifrostConnectionAckDecision()
    data class Ready(val token: BifrostConnectionTransactionToken) : BifrostConnectionAckDecision()
}

internal class BifrostConnectionTransactionGate {
    private var active: BifrostConnectionTransactionToken? = null
    private var committed: BifrostConnectionTransactionToken? = null
    private var blocked: BifrostConnectionTransactionToken? = null
    private var disconnecting: BifrostConnectionTransactionToken? = null
    private var currentPhase: BifrostConnectionTransactionPhase = BifrostConnectionTransactionPhase.IDLE
    private var successCount = 0
    private var serviceDispatched: BifrostConnectionTransactionToken? = null

    @Synchronized
    fun begin(token: BifrostConnectionTransactionToken): Boolean {
        if (active != null || committed != null || blocked != null || disconnecting != null) return false
        active = token
        serviceDispatched = null
        currentPhase = BifrostConnectionTransactionPhase.STARTING
        return true
    }

    @Synchronized
    fun phase(): BifrostConnectionTransactionPhase =
        if (disconnecting != null) BifrostConnectionTransactionPhase.DISCONNECTING else currentPhase

    @Synchronized
    fun committedToken(): BifrostConnectionTransactionToken? = committed

    @Synchronized
    fun successCount(): Int = successCount

    @Synchronized
    fun isActive(token: BifrostConnectionTransactionToken): Boolean = active == token

    @Synchronized
    fun canRefreshPreparation(token: BifrostConnectionTransactionToken): Boolean =
        active == token && serviceDispatched == null && disconnecting == null &&
            currentPhase == BifrostConnectionTransactionPhase.STARTING

    /** Called immediately before handing the Intent to Android. Once handed
     * off, only the exact Service release handshake can prove teardown. */
    @Synchronized
    fun markServiceDispatched(token: BifrostConnectionTransactionToken): Boolean {
        if (active != token || currentPhase != BifrostConnectionTransactionPhase.STARTING) return false
        serviceDispatched = token
        return true
    }

    /** Cancellation during local probing/permission preparation needs no
     * Service receipt: this exact transaction has never been dispatched. */
    @Synchronized
    fun cancelBeforeServiceDispatch(token: BifrostConnectionTransactionToken): Boolean {
        if (active != token || serviceDispatched != null ||
            currentPhase != BifrostConnectionTransactionPhase.STARTING) return false
        return cancelExact(token)
    }

    @Synchronized
    fun blockedToken(): BifrostConnectionTransactionToken? = blocked

    /** Rehydrate only from the live same-process Service ownership registry. */
    @Synchronized
    fun adoptBlocked(token: BifrostConnectionTransactionToken): Boolean {
        if (!hasLiveOwner(token, BifrostServiceOwnershipPhase.BLOCKED_FAILED) ||
            active != null || committed != null || blocked != null || disconnecting != null) return false
        blocked = token
        currentPhase = BifrostConnectionTransactionPhase.BLOCKED_FAILED
        return true
    }

    @Synchronized
    fun adoptCommitted(token: BifrostConnectionTransactionToken): Boolean {
        if (!hasLiveOwner(token, BifrostServiceOwnershipPhase.COMMITTED) ||
            active != null || committed != null || blocked != null || disconnecting != null) return false
        committed = token
        currentPhase = BifrostConnectionTransactionPhase.COMMITTED
        return true
    }

    @Synchronized
    fun adoptStarting(token: BifrostConnectionTransactionToken): Boolean {
        if (!hasLiveOwner(token, BifrostServiceOwnershipPhase.PENDING) ||
            active != null || committed != null || blocked != null || disconnecting != null) return false
        active = token
        serviceDispatched = token
        currentPhase = BifrostConnectionTransactionPhase.STARTING
        return true
    }

    /**
     * Accept only an acknowledgement for the active transaction while it is
     * still starting.  Both success and failure acknowledgements carry the
     * complete token.  A same-id field mismatch is ignored without changing
     * the active transaction; this is important when a late failure from an
     * older service request collides with a newer request reusing an id.
     */
    @Synchronized
    fun acknowledge(
        transactionId: String,
        ready: Boolean,
        digest: String?,
        generation: String?,
        bindings: String?,
        failureCode: String,
        blockedFailure: Boolean = false,
    ): BifrostConnectionAckDecision {
        val expected = active ?: return BifrostConnectionAckDecision.Ignored
        if (expected.transactionId != transactionId || currentPhase != BifrostConnectionTransactionPhase.STARTING) {
            return BifrostConnectionAckDecision.Ignored
        }
        if (!ready) {
            if (digest != expected.digest || generation != expected.generation || bindings != expected.bindings) {
                return BifrostConnectionAckDecision.Ignored
            }
            active = null
            return if (blockedFailure) {
                blocked = expected
                currentPhase = BifrostConnectionTransactionPhase.BLOCKED_FAILED
                BifrostConnectionAckDecision.Failed(safeCode(failureCode), compensate = false, blocked = true, token = expected)
            } else {
                currentPhase = BifrostConnectionTransactionPhase.FAILED
                BifrostConnectionAckDecision.Failed(safeCode(failureCode), compensate = false, blocked = false, token = expected)
            }
        }
        if (digest != expected.digest || generation != expected.generation || bindings != expected.bindings) {
            return BifrostConnectionAckDecision.Ignored
        }
        currentPhase = BifrostConnectionTransactionPhase.READY_PENDING_COMMIT
        return BifrostConnectionAckDecision.Ready(expected)
    }

    @Synchronized
    fun fail(token: BifrostConnectionTransactionToken): Boolean {
        if (active != token) return false
        active = null
        currentPhase = BifrostConnectionTransactionPhase.FAILED
        BifrostApplicationPolicySnapshotRegistry.remove(token.transactionId)
        return true
    }

    /**
     * Start an exact disconnect handshake.  Local state is deliberately kept
     * in DISCONNECTING until the Service returns an authoritative idle result;
     * this prevents a new connection from racing an old VPN owner.
     */
    @Synchronized
    fun beginDisconnectExact(token: BifrostConnectionTransactionToken): Boolean {
        if (disconnecting == token) return true
        if (active != token && committed != token && blocked != token) return false
        active = null
        committed = null
        blocked = null
        disconnecting = token
        currentPhase = BifrostConnectionTransactionPhase.DISCONNECTING
        // Android may have accepted the start Intent while its Service worker
        // has not read the snapshot yet. Keep that exact handoff alive until
        // the worker can acknowledge teardown; deleting it here strands both
        // sides in DISCONNECTING with no Service owner to issue a receipt.
        return true
    }

    /** Complete the disconnect handshake only for its complete token. */
    @Synchronized
    fun releaseDisconnectExact(token: BifrostConnectionTransactionToken): Boolean {
        if (disconnecting != token) return false
        disconnecting = null
        currentPhase = BifrostConnectionTransactionPhase.IDLE
        BifrostApplicationPolicySnapshotRegistry.remove(token.transactionId)
        return true
    }

    /** Complete a release discovered after Activity recreation.  No local
     * owner may exist; the Service receipt has already supplied the exact
     * token/epoch proof, so this cannot consume a newer transaction. */
    @Synchronized
    @JvmSynthetic
    fun completeDiscoveredRelease(token: BifrostConnectionTransactionToken): Boolean {
        if (active != null || committed != null || blocked != null || disconnecting != null) return false
        currentPhase = BifrostConnectionTransactionPhase.IDLE
        BifrostApplicationPolicySnapshotRegistry.remove(token.transactionId)
        return true
    }

    @Synchronized
    fun disconnectingToken(): BifrostConnectionTransactionToken? = disconnecting

    @Synchronized
    fun cancelExact(token: BifrostConnectionTransactionToken): Boolean {
        if (active != token) return false
        active = null
        currentPhase = BifrostConnectionTransactionPhase.CANCELLED
        BifrostApplicationPolicySnapshotRegistry.remove(token.transactionId)
        return true
    }

    /** Complete exactly once after the caller has atomically persisted state. */
    @Synchronized
    fun commit(token: BifrostConnectionTransactionToken): Boolean {
        if (active != token || currentPhase != BifrostConnectionTransactionPhase.READY_PENDING_COMMIT) {
            return false
        }
        active = null
        blocked = null
        committed = token
        currentPhase = BifrostConnectionTransactionPhase.COMMITTED
        successCount++
        return true
    }

    private fun safeCode(value: String): String =
        value.takeIf { Regex("BF-[A-Z0-9-]{1,61}").matches(it) } ?: "BF-SERVICE-ACK"

    private fun hasLiveOwner(
        token: BifrostConnectionTransactionToken,
        phase: BifrostServiceOwnershipPhase,
    ): Boolean {
        val live = BifrostServiceOwnershipRegistry.current() ?: return false
        return live.phase == phase &&
            live.token.transactionId == token.transactionId &&
            live.token.generation == token.generation &&
            live.token.digest == token.digest &&
            live.token.bindings == token.bindings
    }
}
