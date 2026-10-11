package com.bifrost.client

/**
 * Production Service command ordering shared by BifrostVpnService and JVM
 * tests.  A disconnect is a two-phase operation: beginDisconnect retains the
 * exact owner, the injected runtime proves teardown, then the registry records
 * a release receipt and ownership is completed.  No caller can manufacture an
 * IDLE result from a missing owner.
 */
internal data class BifrostServiceDisconnectResult(
    val accepted: Boolean,
    val released: Boolean,
    val blocked: Boolean,
    val idle: Boolean,
    val cleanupOwnService: Boolean,
    val code: String,
    val token: BifrostServiceTransactionToken,
    val receipt: BifrostServiceReleaseReceipt?,
)

internal data class BifrostServiceStatusResult(
    val token: BifrostServiceTransactionToken,
    /** Global owner, exposed for the Service-instance cleanup decision. */
    val live: BifrostServiceOwnershipSnapshot?,
    val exactLive: BifrostServiceOwnershipSnapshot?,
    val receipt: BifrostServiceReleaseReceipt?,
    val exact: Boolean,
    val globalOwner: BifrostServiceOwnershipSnapshot?,
    val cleanupOwnService: Boolean,
)

internal object BifrostServiceConnectionMetadata {
    const val CORE = "core"
    const val MODE = "mode"
    const val SOURCE = "source"
    const val COUNTRY = "country"
    const val FRONT_SOURCE = "front_source"
    const val CANDIDATE = "candidate"
    const val CONNECTION_TYPE = "connection_type"
    val REQUIRED_FIELDS = setOf(CORE, MODE, SOURCE, COUNTRY, FRONT_SOURCE, CANDIDATE, CONNECTION_TYPE)

    fun complete(description: BifrostServiceConnectionDescription?, present: Set<String>): Boolean {
        if (description == null || !present.containsAll(REQUIRED_FIELDS)) return false
        return description.core.isNotBlank() && description.mode.isNotBlank() &&
            description.source.isNotBlank() && description.country.isNotBlank() &&
            description.frontSource.isNotBlank() && !description.candidate.isNullOrBlank() &&
            runCatching { BifrostConnectionType.parse(description.connectionType) }.isSuccess
    }

    fun matches(expected: BifrostServiceConnectionDescription?, actual: BifrostServiceConnectionDescription?): Boolean =
        expected != null && actual != null && expected == actual
}

internal data class BifrostServiceFailureResult(
    val retained: Boolean,
    val blocked: Boolean,
    val unprotected: Boolean,
    val phase: BifrostServiceOwnershipPhase,
)

/** Production catch-path decision used by BifrostVpnService and JVM tests. */
internal class BifrostServiceFailureCoordinator(
    private val ownership: BifrostServiceTransactionOwnership,
) {
    @Synchronized
    fun apply(token: BifrostServiceTransactionToken?, outcome: BifrostRuntimeCoreFailureOutcome): BifrostServiceFailureResult {
        if (token == null) return BifrostServiceFailureResult(false, false, false, ownership.phase())
        // A concurrent watchdog/disconnect may already have moved the exact
        // owner into a terminal retained phase.  Never downgrade that proof or
        // let a late connect catch clear it.
        if (ownership.blockedToken() == token) {
            return BifrostServiceFailureResult(true, true, false, BifrostServiceOwnershipPhase.BLOCKED_FAILED)
        }
        if (ownership.unprotectedToken() == token) {
            return BifrostServiceFailureResult(true, false, true, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED)
        }
        if (ownership.disconnectingToken() == token) {
            return BifrostServiceFailureResult(true, false, false, BifrostServiceOwnershipPhase.DISCONNECTING)
        }
        val fenced = ownership.fenceEstablishedFor(token)
        if (!fenced) {
            ownership.failBeforeFence(token)
            return BifrostServiceFailureResult(false, false, false, ownership.phase())
        }
        val retained = when (ownership.phase()) {
            BifrostServiceOwnershipPhase.COMMITTED -> {
                if (outcome.blocked) ownership.failAfterCommit(token)
                else ownership.retainCommittedUnprotected(token)
            }
            else -> if (outcome.blocked) ownership.failAfterFence(token)
            else ownership.failFenceUnavailable(token, outcome.teardownConfirmed)
        }
        val phase = ownership.phase()
        return BifrostServiceFailureResult(
            retained,
            retained && phase == BifrostServiceOwnershipPhase.BLOCKED_FAILED,
            retained && phase == BifrostServiceOwnershipPhase.UNPROTECTED_FAILED,
            phase,
        )
    }
}

/** The real service supplies BifrostRuntimeCoordinator.disconnect here. */
internal class BifrostServiceCommandCoordinator(
    private val ownership: BifrostServiceTransactionOwnership,
    private val runtimeDisconnect: () -> BifrostRuntimeDisconnectOutcome,
) {
    @Synchronized
    fun disconnect(token: BifrostServiceTransactionToken): BifrostServiceDisconnectResult {
        return disconnect(token, {}, {})
    }

    @Synchronized
    fun disconnect(
        token: BifrostServiceTransactionToken,
        onAcknowledgement: (BifrostServiceDisconnectResult) -> Unit,
        onCleanup: () -> Unit,
    ): BifrostServiceDisconnectResult {
        val result = disconnectInternal(token)
        // Acknowledgement is always attempted before foreground/self cleanup.
        // ResultReceiver failures are deliberately isolated: the exact
        // release receipt remains recoverable through ACTION_STATUS.
        runCatching { onAcknowledgement(result) }
        // A delayed duplicate receipt may coexist with a newer live owner.
        // Cleanup is therefore an exact coordinator decision, rechecked at the
        // side-effect boundary; never stop the shared Service for that owner.
        if (result.released && result.cleanupOwnService &&
            BifrostServiceOwnershipRegistry.current() == null && !ownership.hasOwner()) {
            runCatching { onCleanup() }
        }
        return result
    }

    private fun disconnectInternal(token: BifrostServiceTransactionToken): BifrostServiceDisconnectResult {
        val existingReceipt = BifrostServiceOwnershipRegistry.releaseReceipt(token)
        if (existingReceipt != null) {
            return BifrostServiceDisconnectResult(
                accepted = true,
                released = true,
                blocked = false,
                idle = true,
                cleanupOwnService = BifrostServiceOwnershipRegistry.current() == null && !ownership.hasOwner(),
                code = "BF-CONNECTION-DISCONNECTED",
                token = token,
                receipt = existingReceipt,
            )
        }
        if (!ownership.beginDisconnect(token)) {
            return BifrostServiceDisconnectResult(
                accepted = false,
                released = false,
                blocked = ownership.phase() == BifrostServiceOwnershipPhase.BLOCKED_FAILED,
                idle = false,
                cleanupOwnService = false,
                code = "BF-CONNECTION-TOKEN",
                token = token,
                receipt = null,
            )
        }
        BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == token }?.let { live ->
            runCatching {
                BifrostServiceOwnershipRegistry.publish(
                    BifrostServiceOwnershipPhase.DISCONNECTING,
                    token,
                    live.snapshot,
                    live.description,
                )
            }
        }
        val outcome = runCatching { runtimeDisconnect() }.getOrElse {
            // A throwable carries no physical boundary proof. Historical
            // ownership/fence markers must never be relabeled BLOCKED.
            BifrostRuntimeDisconnectOutcome(false, false, "BF-RUNTIME-DISCONNECT")
        }
        if (!outcome.success) {
            val retained = ownership.failDisconnect(token, outcome.blocked)
            val blocked = retained && ownership.phase() == BifrostServiceOwnershipPhase.BLOCKED_FAILED
            if (blocked) {
                BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == token }?.let { live ->
                    runCatching {
                        BifrostServiceOwnershipRegistry.publish(
                            BifrostServiceOwnershipPhase.BLOCKED_FAILED,
                            token,
                            live.snapshot,
                            live.description,
                        )
                    }
                }
            } else {
                BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == token }?.let { live ->
                    val restoredPhase = ownership.phase().takeIf {
                        it == BifrostServiceOwnershipPhase.COMMITTED ||
                            it == BifrostServiceOwnershipPhase.PENDING ||
                            it == BifrostServiceOwnershipPhase.UNPROTECTED_FAILED
                    }
                    if (restoredPhase != null) runCatching {
                        BifrostServiceOwnershipRegistry.publish(restoredPhase, token, live.snapshot, live.description)
                    }
                }
            }
            if (!blocked && !ownership.hasOwner()) BifrostServiceOwnershipRegistry.clearExactInternal(token)
            return BifrostServiceDisconnectResult(
                accepted = retained,
                released = false,
                blocked = blocked,
                idle = false,
                cleanupOwnService = false,
                code = outcome.code,
                token = token,
                receipt = null,
            )
        }
        val receipt = ownership.completeDisconnectWithRelease(token) {
            BifrostServiceOwnershipRegistry.noteReleasedExact(token)
        }
        if (receipt == null) {
            // The runtime succeeded but exact registry/ownership proof did not
            // complete.  Retain a fenced owner whenever possible; never emit
            // a false IDLE acknowledgement.
            ownership.failDisconnect(token, boundaryBlocked = false)
            return BifrostServiceDisconnectResult(
                accepted = false,
                released = false,
                blocked = ownership.phase() == BifrostServiceOwnershipPhase.BLOCKED_FAILED,
                idle = false,
                cleanupOwnService = false,
                code = "BF-CONNECTION-RELEASE-PROOF",
                token = token,
                receipt = null,
            )
        }
        return BifrostServiceDisconnectResult(
            accepted = true,
            released = true,
            blocked = false,
            idle = true,
            cleanupOwnService = BifrostServiceOwnershipRegistry.current() == null && !ownership.hasOwner(),
            code = "BF-CONNECTION-DISCONNECTED",
            token = token,
            receipt = receipt,
        )
    }

    @Synchronized
    fun status(token: BifrostServiceTransactionToken): BifrostServiceStatusResult {
        val status = BifrostServiceOwnershipRegistry.status(token)
        val exact = status.owner != null || status.release != null
        return BifrostServiceStatusResult(
            token,
            status.globalOwner,
            status.owner,
            status.release,
            exact,
            status.globalOwner,
            cleanupOwnService = status.globalOwner == null && !ownership.hasOwner(),
        )
    }
}
