package com.bifrost.client

import android.content.Context
import java.util.UUID

/** A user request to keep Root connected, never an account or routing capability. */
internal object BifrostRootConnectionIntent {
    private fun store(context: Context) = context.getSharedPreferences("bifrost-features", Context.MODE_PRIVATE)
    @Synchronized fun current(context: Context): String? =
        if (!BifrostFeaturePreferences.rootMode(context)) null else store(context)
            .getString("root_connection_request", null)?.takeIf { it.matches(Regex("[0-9a-f]{32}")) }
    @Synchronized fun begin(context: Context): String = UUID.randomUUID().toString().replace("-", "").also {
        check(store(context).edit().putString("root_connection_request", it).commit()) { "BF-RELEASE-STATE" }
    }
    @Synchronized fun matches(context: Context, epoch: String): Boolean = current(context) == epoch
    @Synchronized fun stop(context: Context) {
        check(store(context).edit().remove("root_connection_request").commit()) { "BF-RELEASE-STATE" }
    }
    @Synchronized fun stopExact(context: Context, epoch: String) {
        if (current(context) == epoch) stop(context)
    }
    fun retryable(error: Throwable): Boolean = BifrostUiErrorMapper.code(error) !in setOf(
        "BF-ROOT-PERMISSION", "BF-ROOT-UNSUPPORTED", "BF-ROOT-OTHER-VPN", "BF-NOT-ENROLLED",
        "BF-AUTH-003", "BF-CONNECTION-RELEASED", "BF-VPN-PERMISSION",
    )
}
