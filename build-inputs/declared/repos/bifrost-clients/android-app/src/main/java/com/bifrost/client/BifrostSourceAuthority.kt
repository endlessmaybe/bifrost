package com.bifrost.client

import org.json.JSONObject

/**
 * The only source choices exposed by the Android shell.  The caller must
 * obtain content from BifrostConfigStore.load(), which is already signature
 * and generation verified; this value object never invents fallback sources.
 */
internal data class BifrostSourceAuthority(
    val sources: List<String>,
    val frontSources: List<String>,
) {
    fun accept(requested: String): String? = sources.firstOrNull { it.equals(requested.trim(), true) }

    companion object {
        fun empty(): BifrostSourceAuthority = BifrostSourceAuthority(emptyList(), listOf("auto"))

        fun fromVerifiedConfig(content: String): BifrostSourceAuthority {
            val root = JSONObject(content)
            val sourceArray = root.optJSONArray("sources")
            val configured = if (sourceArray == null) emptyList() else
                (0 until sourceArray.length())
                    .mapNotNull { index ->
                        val source = sourceArray.optJSONObject(index) ?: return@mapNotNull null
                        if (source.opt("configured") != true) return@mapNotNull null
                        (source.opt("code") as? String)?.trim()?.takeIf(String::isNotBlank)
                    }
                    .distinct()
            return BifrostSourceAuthority(configured, listOf("auto") + configured)
        }
    }
}
