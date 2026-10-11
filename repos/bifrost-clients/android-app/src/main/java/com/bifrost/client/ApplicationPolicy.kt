package com.bifrost.client

/**
 * Stable Kotlin facade for the final JVM snapshot value.  The value type and
 * every construction/parsing path live in Java so the compiled API has a
 * private constructor, no Kotlin marker constructor, and cannot be
 * implemented by same-package adversary code.
 */
internal object BifrostApplicationPolicy {
    fun normalize(
        routeMode: String,
        policyMode: String,
        include: Iterable<String>,
        exclude: Iterable<String>,
    ): BifrostApplicationPolicySnapshot = BifrostApplicationPolicySnapshot.fromSelection(
        routeMode,
        policyMode,
        include,
        exclude,
    )

    fun verify(snapshot: BifrostApplicationPolicySnapshot): BifrostApplicationPolicySnapshot =
        BifrostApplicationPolicySnapshot.verify(snapshot)

    fun parseUiList(text: String): List<String> {
        if (text.isEmpty()) return emptyList()
        val normalised = text.replace("\r\n", "\n").replace('\r', '\n')
        val parts = normalised.split(',', ';', '\n')
        if (parts.any { it.trim().isEmpty() }) throw IllegalArgumentException("BF-APP-ID")
        return BifrostApplicationPolicySnapshot.normalizeIdentities(parts.map(String::trim))
    }
}
