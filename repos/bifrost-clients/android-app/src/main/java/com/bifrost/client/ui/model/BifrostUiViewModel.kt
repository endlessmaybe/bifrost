package com.bifrost.client.ui.model

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Lifecycle owner for the single immutable A-screen state. */
class BifrostUiViewModel : ViewModel() {
    private val _state = MutableStateFlow(BifrostUiState())
    val state: StateFlow<BifrostUiState> = _state.asStateFlow()
    private var initialized = false

    fun initialize(initial: BifrostUiState) {
        if (!initialized) {
            _state.value = initial
            initialized = true
        }
    }

    fun dispatch(event: BifrostUiEvent) {
        _state.value = BifrostUiStateReducer.reduce(_state.value, event)
    }

    fun reconcileAuthorities(
        sources: List<String>,
        countries: List<String>,
        frontSources: List<String>,
        candidateLabels: List<String> = emptyList(),
    ) {
        val current = _state.value
        val nextSource = if (current.source.isBlank()) "" else
            sources.firstOrNull { it.equals(current.source, ignoreCase = true) }.orEmpty()
        val nextCountry = if (current.country.isBlank()) "auto" else
            countries.firstOrNull { it.equals(current.country, ignoreCase = true) } ?: "auto"
        val nextFront = if (current.frontSource.isBlank()) "auto" else
            frontSources.firstOrNull { it.equals(current.frontSource, ignoreCase = true) } ?: "auto"
        val candidateStillValid = current.candidateMode != "manual" || candidateLabels.any { it == current.candidateLabel }
        if (nextSource != current.source || nextCountry != current.country || nextFront != current.frontSource || !candidateStillValid) {
            _state.value = current.copy(
                source = nextSource,
                country = nextCountry,
                frontSource = nextFront,
                candidateMode = if (candidateStillValid) current.candidateMode else "auto",
                candidateLabel = if (candidateStillValid) current.candidateLabel else "",
            )
        }
    }
}
