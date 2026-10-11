package com.bifrost.client

import org.json.JSONObject
import com.bifrost.client.ui.model.BifrostUiText

/** The two independent protocol axes.  Presentation labels are never sent
 * as route values: SmartGate is a connection type, while route mode remains
 * smart/global/per-app. */
enum class BifrostConnectionType(val wireValue: String) {
    DIRECT_VMESH("direct-vmess"),
    SMARTGATE("smartgate");

    companion object {
        fun parse(value: String?): BifrostConnectionType =
            entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("BF-CONNECTION-TYPE")
    }
}

enum class BifrostRouteMode(val wireValue: String) {
    SMART("smart"),
    GLOBAL("global"),
    PER_APP("per-app");

    companion object {
        fun parse(value: String?): BifrostRouteMode =
            entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException("BF-ROUTE-MODE")
    }
}

data class BifrostConnectionRouteSelection(
    val connectionType: BifrostConnectionType,
    val routeMode: BifrostRouteMode,
) {
    init {
        require(connectionType != BifrostConnectionType.SMARTGATE || routeMode != BifrostRouteMode.GLOBAL) {
            "BF-SMARTGATE-ROUTE"
        }
    }
}

object BifrostConnectionRouteContract {
    fun fromUiMode(uiMode: String, appPolicyEnabled: Boolean): BifrostConnectionRouteSelection {
        val type = when (uiMode) {
            "smartgate" -> BifrostConnectionType.SMARTGATE
            "smart", "global" -> BifrostConnectionType.DIRECT_VMESH
            else -> error("BF-CONNECTION-TYPE")
        }
        val route = if (appPolicyEnabled) BifrostRouteMode.PER_APP else when (uiMode) {
            "global" -> BifrostRouteMode.GLOBAL
            else -> BifrostRouteMode.SMART
        }
        return BifrostConnectionRouteSelection(type, route)
    }

    fun parse(connectionType: String?, routeMode: String?): BifrostConnectionRouteSelection =
        BifrostConnectionRouteSelection(
            BifrostConnectionType.parse(connectionType),
            BifrostRouteMode.parse(routeMode),
        )

    fun validate(connectionType: String?, routeMode: String?): BifrostConnectionRouteSelection =
        parse(connectionType, routeMode)

    fun presentationMode(selection: BifrostConnectionRouteSelection): String =
        if (selection.connectionType == BifrostConnectionType.SMARTGATE) "smartgate"
        else if (selection.routeMode == BifrostRouteMode.GLOBAL) "global" else "smart"
}

/** Protocol values are deliberately separate from localized display text. */
enum class BifrostCandidateMode(val wireValue: String) {
    AUTO("auto"),
    MANUAL("manual");

    companion object {
        fun parse(value: String?): BifrostCandidateMode =
            entries.firstOrNull { it.wireValue == value?.trim()?.lowercase() } ?: AUTO
    }
}

data class BifrostCandidateOption(
    val label: String,
    val displayName: String,
)

data class BifrostCoreOption(
    val code: String,
    val displayName: String,
)

data class BifrostNodeSelection(
    val mode: BifrostCandidateMode = BifrostCandidateMode.AUTO,
    val manualLabel: String? = null,
    val core: String = "auto",
)

/**
 * Derives only safe UI labels from the latest signature-verified config. No
 * address, port, UUID, host, SNI, path, credential, or raw package object is
 * returned to Compose. The caller must supply a BifrostConfigStore.Cached
 * value (or equivalent verified content), never an arbitrary response body.
 */
object BifrostCandidateSelectionContract {
    val coreOptions = listOf(
        BifrostCoreOption("auto", BifrostUiText.coreAuto),
        BifrostCoreOption("sing-box", BifrostUiText.coreSingBox),
        BifrostCoreOption("xray", BifrostUiText.coreXray),
    )

    fun candidateOptions(content: String, sourceCode: String): List<BifrostCandidateOption> {
        val source = findSource(JSONObject(content), sourceCode) ?: return emptyList()
        val candidates = source.optJSONArray("candidates") ?: return emptyList()
        return (0 until candidates.length()).mapNotNull { index ->
            val item = candidates.optJSONObject(index) ?: return@mapNotNull null
            val label = item.optString("label").trim().takeIf(::safeLabel) ?: return@mapNotNull null
            val display = sequenceOf(
                item.optString("display_name").trim(),
                item.optString("name").trim(),
                label,
            ).firstOrNull(::safeDisplay).orEmpty()
            BifrostCandidateOption(label, display)
        }.distinctBy { it.label }
    }

    fun countryOptions(content: String): List<Pair<String, String>> {
        val countries = JSONObject(content).optJSONArray("countries") ?: return listOf("auto" to BifrostUiText.auto)
        return listOf("auto" to BifrostUiText.auto) + (0 until countries.length()).mapNotNull { index ->
            val item = countries.optJSONObject(index) ?: return@mapNotNull null
            val code = item.optString("code").trim().takeIf(::safeCode) ?: return@mapNotNull null
            val display = sequenceOf(item.optString("name_zh"), item.optString("display_name"), item.optString("name"), code)
                .map(String::trim).firstOrNull(::safeDisplay) ?: code
            code to display
        }.distinctBy { it.first }
    }

    fun visibleCandidateChooser(uiMode: String, country: String): Boolean =
        uiMode != "smartgate" && country.isNotBlank()

    fun validate(
        content: String,
        sourceCode: String,
        uiMode: String,
        country: String,
        selection: BifrostNodeSelection,
    ): BifrostNodeSelection {
        require(uiMode in setOf("smart", "global", "smartgate")) { "BF-UI-MODE" }
        require(findSource(JSONObject(content), sourceCode) != null) { "BF-SOURCE-NOT-READY" }
        require(selection.core in coreOptions.map { it.code }) { "BF-CONFIG-CORE" }
        if (selection.mode == BifrostCandidateMode.MANUAL) {
            require(visibleCandidateChooser(uiMode, country)) { "BF-CANDIDATE-MODE" }
            val allowed = candidateOptions(content, sourceCode).map { it.label }
            require(selection.manualLabel in allowed) { "BF-CANDIDATE-NOT-READY" }
        }
        return selection.copy(manualLabel = selection.manualLabel?.takeIf { selection.mode == BifrostCandidateMode.MANUAL })
    }

    private fun findSource(root: JSONObject, sourceCode: String): JSONObject? {
        val sources = root.optJSONArray("sources") ?: return null
        return (0 until sources.length()).asSequence()
            .mapNotNull { sources.optJSONObject(it) }
            .firstOrNull {
                it.optBoolean("configured", false) && it.optString("code").equals(sourceCode.trim(), true)
            }
    }

    private fun safeCode(value: String): Boolean =
        value.isNotBlank() && value.length <= 64 && value.matches(Regex("[A-Za-z0-9._-]+"))

    private fun safeLabel(value: String): Boolean =
        safeDisplay(value) && !value.any { it == '/' || it == ':' || it == '@' || it == '\\' }

    private fun safeDisplay(value: String): Boolean =
        value.isNotBlank() && value.length <= 128 && value.none { it == '\u0000' || it.isISOControl() }
}
