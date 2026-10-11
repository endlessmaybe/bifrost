package com.bifrost.client

/** Immutable shell state controlled by the currently verified source authority. */
internal data class BifrostSourceAuthorityState(
    val hasConfig: Boolean,
    val sources: List<String>,
    val frontSources: List<String>,
    val selectedSource: String,
    val selectedCandidate: String?,
)

internal data class BifrostSourceAuthorityApplyResult(
    val state: BifrostSourceAuthorityState,
    val accepted: Boolean,
    val persistenceOk: Boolean,
)

/**
 * Production state seam for authority revocation and source selection. It
 * owns no Android UI and performs no I/O itself; persistence and owner update
 * are injected so failure/rollback paths are executable in unit tests.
 */
internal class BifrostSourceAuthorityController(
    private val persistSource: (String) -> Boolean,
    private val updateOwner: (String) -> Unit,
) {
    fun apply(
        current: BifrostSourceAuthorityState,
        authority: BifrostSourceAuthority?,
        requestedSource: String? = null,
        persistSelection: Boolean = false,
    ): BifrostSourceAuthorityApplyResult {
        val sources = authority?.sources.orEmpty()
        val frontSources = authority?.frontSources ?: listOf("auto")
        val requested = requestedSource ?: current.selectedSource
        val canonical = authority?.accept(requested)
        if (canonical.isNullOrBlank()) {
            val persistenceOk = persistSource("")
            updateOwner("")
            return BifrostSourceAuthorityApplyResult(
                BifrostSourceAuthorityState(
                    hasConfig = authority != null,
                    sources = sources,
                    frontSources = frontSources,
                    selectedSource = "",
                    selectedCandidate = null,
                ),
                accepted = false,
                persistenceOk = persistenceOk,
            )
        }
        if (persistSelection && !persistSource(canonical)) {
            val currentStillValid = authority.accept(current.selectedSource) != null
            if (currentStillValid) {
                return BifrostSourceAuthorityApplyResult(
                    current.copy(hasConfig = true, sources = sources, frontSources = frontSources),
                    accepted = false,
                    persistenceOk = false,
                )
            }
            persistSource("")
            updateOwner("")
            return BifrostSourceAuthorityApplyResult(
                BifrostSourceAuthorityState(true, sources, frontSources, "", null),
                accepted = false,
                persistenceOk = false,
            )
        }
        val changed = !current.selectedSource.equals(canonical, true)
        if (changed) updateOwner(canonical)
        return BifrostSourceAuthorityApplyResult(
            BifrostSourceAuthorityState(
                hasConfig = true,
                sources = sources,
                frontSources = frontSources,
                selectedSource = canonical,
                selectedCandidate = current.selectedCandidate.takeUnless { changed },
            ),
            accepted = true,
            persistenceOk = true,
        )
    }
}
