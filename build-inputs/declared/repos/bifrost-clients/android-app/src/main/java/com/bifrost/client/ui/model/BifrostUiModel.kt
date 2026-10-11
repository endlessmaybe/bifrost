package com.bifrost.client.ui.model

import com.bifrost.client.BifrostConnectionRouteContract
import com.bifrost.client.BifrostConnectionRouteSelection
import com.bifrost.client.BifrostRouteMode

/** Explicit presentation states; a colour is never the sole state signal. */
enum class BifrostConnectionState { IDLE, PREPARING, CONNECTED, PROTECTED, RECONNECTING, BLOCKED, ERROR }

/** Typed signal from the verified local runtime boundary.  Display strings
 * never participate in state authorization. */
enum class BifrostRuntimeSignal { IDLE, PREPARING, CONNECTED, PROTECTED, RECONNECTING, BLOCKED, ERROR }

data class BifrostRuntimeEvidence(
    val serviceAccepted: Boolean = false,
    val readbackVerified: Boolean = false,
    val transactionId: String? = null,
    val digest: String? = null,
    val generation: String? = null,
    val bindings: String? = null,
    val signal: BifrostRuntimeSignal = BifrostRuntimeSignal.IDLE,
)

data class BifrostUiMetrics(
    val download: String = "—",
    val upload: String = "—",
    val sessionTraffic: String = "—",
    val duration: String = "—",
    val samples: List<Float> = emptyList(),
    val uploadSamples: List<Float> = emptyList(),
)

data class BifrostPresentationState(
    val state: BifrostConnectionState,
    val statusText: String,
    val source: String = "—",
    val route: String = "—",
    val country: String = "—",
    val core: String = BifrostUiText.auto,
    val metrics: BifrostUiMetrics = BifrostUiMetrics(),
    val isTestState: Boolean = false,
) {
    val isProtected: Boolean get() = state == BifrostConnectionState.PROTECTED
    val isConnected: Boolean get() = isProtected || state == BifrostConnectionState.CONNECTED
    val hasSamples: Boolean get() = metrics.samples.isNotEmpty()

    companion object {
        fun idle(status: String = BifrostUiText.notConnected) = BifrostPresentationState(
            BifrostConnectionState.IDLE,
            status,
        )

        fun testProtected() = BifrostPresentationState(
            BifrostConnectionState.PROTECTED,
            BifrostUiText.connected,
            source = "A",
            route = "A-03",
            country = BifrostUiText.auto,
            core = "${BifrostUiText.auto} · sing-box",
            metrics = BifrostUiMetrics("18.6 MB/s", "4.2 MB/s", "3.42 GB", "01:42:18", listOf(12f, 18f, 15f, 22f, 20f, 26f, 24f, 28f)),
            isTestState = true,
        )
    }
}

/**
 * The single immutable Compose state for the Android client. Transient
 * credentials are held only in this in-memory state while the screen is
 * alive; they are never placed in saved state or persisted by the reducer.
 */
data class BifrostUiState(
    val page: String = "home",
    val mode: String = "smart",
    val core: String = "auto",
    val source: String = "",
    val country: String = "auto",
    val frontSource: String = "auto",
    val candidateMode: String = "auto",
    val candidateLabel: String = "",
    val appPolicy: String = "allow",
    val appPolicyEnabled: Boolean = false,
    val baseUrl: String = "",
    val invite: String = "",
    val publicId: String = "",
    val recovery: String = "",
    val pairing: String = "",
    val includeText: String = "",
    val excludeText: String = "",
    val showRecovery: Boolean = false,
    val showPairing: Boolean = false,
    val showAdvancedFront: Boolean = false,
)

sealed interface BifrostUiEvent {
    data class Page(val value: String) : BifrostUiEvent
    data class Mode(val value: String) : BifrostUiEvent
    data class Core(val value: String) : BifrostUiEvent
    data class Source(val value: String) : BifrostUiEvent
    data class Country(val value: String) : BifrostUiEvent
    data class FrontSource(val value: String) : BifrostUiEvent
    data class CandidateMode(val value: String) : BifrostUiEvent
    data class CandidateLabel(val value: String) : BifrostUiEvent
    data class AppPolicy(val value: String) : BifrostUiEvent
    data class AppPolicyEnabled(val value: Boolean) : BifrostUiEvent
    data class BaseUrl(val value: String) : BifrostUiEvent
    data class Invite(val value: String) : BifrostUiEvent
    data class PublicId(val value: String) : BifrostUiEvent
    data class Recovery(val value: String) : BifrostUiEvent
    data class Pairing(val value: String) : BifrostUiEvent
    data class Include(val value: String) : BifrostUiEvent
    data class Exclude(val value: String) : BifrostUiEvent
    data class ShowRecovery(val value: Boolean) : BifrostUiEvent
    data class ShowPairing(val value: Boolean) : BifrostUiEvent
    data class ShowAdvancedFront(val value: Boolean) : BifrostUiEvent
}

object BifrostUiStateReducer {
    fun reduce(state: BifrostUiState, event: BifrostUiEvent): BifrostUiState = when (event) {
        is BifrostUiEvent.Page -> state.copy(page = event.value)
        is BifrostUiEvent.Mode -> state.copy(
            mode = event.value,
            appPolicyEnabled = state.appPolicyEnabled && event.value == "smart",
            showAdvancedFront = if (event.value == "smartgate") state.showAdvancedFront else false,
            candidateMode = if (event.value == "global") "manual" else "auto",
            candidateLabel = if (event.value == "global") state.candidateLabel else "",
            country = if (event.value == "smartgate") state.country else "auto",
            frontSource = if (event.value == "smartgate") state.frontSource else "auto",
        )
        is BifrostUiEvent.Core -> state.copy(core = event.value)
        is BifrostUiEvent.Source -> state.copy(source = event.value)
        is BifrostUiEvent.Country -> state.copy(country = if (state.mode == "smartgate") event.value else "auto")
        is BifrostUiEvent.FrontSource -> state.copy(frontSource = if (state.mode == "smartgate") event.value else "auto")
        is BifrostUiEvent.CandidateMode -> if (state.mode == "smartgate") state.copy(candidateMode = "auto", candidateLabel = "") else {
            val candidateMode = event.value.takeIf { it == "auto" || it == "manual" } ?: "auto"
            state.copy(
                mode = if (candidateMode == "auto") "smart" else "global",
                appPolicyEnabled = state.appPolicyEnabled && candidateMode == "auto",
                candidateMode = candidateMode,
                candidateLabel = if (candidateMode == "manual") state.candidateLabel else "",
                country = "auto",
                frontSource = "auto",
                showAdvancedFront = false,
            )
        }
        is BifrostUiEvent.CandidateLabel -> state.copy(candidateLabel = event.value)
        is BifrostUiEvent.AppPolicy -> when (event.value) {
            "exclude" -> state.copy(appPolicy = "exclude", includeText = "")
            else -> state.copy(appPolicy = "allow", excludeText = "")
        }
        is BifrostUiEvent.AppPolicyEnabled -> state.copy(appPolicyEnabled = event.value && state.mode == "smart")
        is BifrostUiEvent.BaseUrl -> state.copy(baseUrl = event.value)
        is BifrostUiEvent.Invite -> state.copy(invite = event.value)
        is BifrostUiEvent.PublicId -> state.copy(publicId = event.value)
        is BifrostUiEvent.Recovery -> state.copy(recovery = event.value)
        is BifrostUiEvent.Pairing -> state.copy(pairing = event.value)
        is BifrostUiEvent.Include -> state.copy(includeText = event.value)
        is BifrostUiEvent.Exclude -> state.copy(excludeText = event.value)
        is BifrostUiEvent.ShowRecovery -> state.copy(showRecovery = event.value)
        is BifrostUiEvent.ShowPairing -> state.copy(showPairing = event.value)
        is BifrostUiEvent.ShowAdvancedFront -> state.copy(showAdvancedFront = event.value)
    }
}

object BifrostUiReducer {
    /**
     * A protected presentation is an ownership proof, not a status string.
     * The expected identity is supplied by the Activity's current committed
     * transaction; every field must match the Service readback evidence.
     * Defaults intentionally remain null so an arbitrary test/status caller
     * cannot manufacture a protected state.
     */
    fun fromRuntimeSignal(
        signal: BifrostRuntimeSignal,
        evidence: BifrostRuntimeEvidence,
        expectedTransactionId: String? = null,
        expectedDigest: String? = null,
        expectedGeneration: String? = null,
        expectedBindings: String? = null,
        displayText: String? = null,
    ): BifrostPresentationState {
        val exactOwnership = !expectedTransactionId.isNullOrBlank() &&
            !expectedDigest.isNullOrBlank() &&
            !expectedGeneration.isNullOrBlank() &&
            !expectedBindings.isNullOrBlank() &&
            evidence.transactionId == expectedTransactionId &&
            evidence.digest == expectedDigest &&
            evidence.generation == expectedGeneration &&
            evidence.bindings == expectedBindings
        val state = if (signal in setOf(BifrostRuntimeSignal.PROTECTED, BifrostRuntimeSignal.CONNECTED) &&
            !(evidence.serviceAccepted && evidence.readbackVerified && exactOwnership)) {
            BifrostConnectionState.ERROR
        } else {
            when (signal) {
                BifrostRuntimeSignal.PREPARING -> BifrostConnectionState.PREPARING
                BifrostRuntimeSignal.PROTECTED -> BifrostConnectionState.PROTECTED
                BifrostRuntimeSignal.CONNECTED -> BifrostConnectionState.CONNECTED
                BifrostRuntimeSignal.RECONNECTING -> BifrostConnectionState.RECONNECTING
                BifrostRuntimeSignal.BLOCKED -> BifrostConnectionState.BLOCKED
                BifrostRuntimeSignal.ERROR -> BifrostConnectionState.ERROR
                BifrostRuntimeSignal.IDLE -> BifrostConnectionState.IDLE
            }
        }
        return BifrostPresentationState(state, when (state) {
            BifrostConnectionState.PREPARING -> BifrostUiText.preparing
            BifrostConnectionState.RECONNECTING -> BifrostUiText.reconnecting
            BifrostConnectionState.BLOCKED -> BifrostUiText.blocked
            BifrostConnectionState.ERROR -> BifrostUiText.temporarilyUnavailable
            BifrostConnectionState.PROTECTED, BifrostConnectionState.CONNECTED -> BifrostUiText.connected
            else -> BifrostUiText.notConnected
        })
    }

    /** Compatibility wrapper: status is display-only and is never parsed. */
    fun fromServiceStatus(
        status: String,
        evidence: BifrostRuntimeEvidence,
        expectedTransactionId: String? = null,
        expectedDigest: String? = null,
        expectedGeneration: String? = null,
        expectedBindings: String? = null,
    ): BifrostPresentationState = fromRuntimeSignal(
        evidence.signal,
        evidence,
        expectedTransactionId,
        expectedDigest,
        expectedGeneration,
        expectedBindings,
        status,
    )

}

object BifrostUiContract {
    val navigation = listOf(BifrostUiText.home, BifrostUiText.nodes, BifrostUiText.activity, BifrostUiText.settings)
    val modes = listOf("smart" to BifrostUiText.smart, "global" to BifrostUiText.global, "smartgate" to BifrostUiText.smartGate)
}

object BifrostUiActions {
    fun canStop(state: BifrostConnectionState): Boolean = state in setOf(
        BifrostConnectionState.PROTECTED, BifrostConnectionState.CONNECTED, BifrostConnectionState.PREPARING,
        BifrostConnectionState.RECONNECTING, BifrostConnectionState.BLOCKED,
    )
}

/**
 * Typed bridge from the three home presentation modes plus the independent
 * routing-page switch to the existing Service contract.  SmartGate remains a
 * presentation choice (wire mode smart); enabling application routing is the
 * only operation that selects the existing per-app contract and carries its
 * validated list.
 */
data class BifrostRoutingSelection(
    val wireMode: String,
    val policyMode: String,
    val include: List<String>,
    val exclude: List<String>,
)

object BifrostRoutingContract {
    fun select(
        selection: BifrostConnectionRouteSelection,
        policyMode: String,
        include: List<String>,
        exclude: List<String>,
    ): BifrostRoutingSelection {
        require(policyMode == "allow" || policyMode == "exclude")
        return if (selection.routeMode == BifrostRouteMode.PER_APP) {
            BifrostRoutingSelection("per-app", policyMode, include, exclude)
        } else {
            BifrostRoutingSelection(selection.routeMode.wireValue, "none", emptyList(), emptyList())
        }
    }

    fun select(
        uiMode: String,
        appPolicyEnabled: Boolean,
        policyMode: String,
        include: List<String>,
        exclude: List<String>,
    ): BifrostRoutingSelection {
        return select(
            BifrostConnectionRouteContract.fromUiMode(uiMode, appPolicyEnabled),
            policyMode,
            include,
            exclude,
        )
    }
}
