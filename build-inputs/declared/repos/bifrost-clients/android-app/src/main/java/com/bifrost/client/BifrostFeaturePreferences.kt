package com.bifrost.client

import android.content.Context

/** Only non-sensitive presentation/maintenance choices belong in this store. */
internal object BifrostFeaturePreferences {
    internal val transitionGate = Any()
    val changing: Boolean get() = BifrostApplicationPolicySnapshotRegistry.configurationChanging()
    private fun store(context: Context) = context.getSharedPreferences("bifrost-features", Context.MODE_PRIVATE)
    fun automaticUpdates(context: Context) = store(context).getBoolean("automatic_updates", true)
    fun setAutomaticUpdates(context: Context, enabled: Boolean) {
        check(store(context).edit().putBoolean("automatic_updates", enabled).commit()) { "BF-RELEASE-STATE" }
    }
    fun hotspotMode(context: Context) = store(context).getString("hotspot_mode", "smart")
        ?.takeIf { it in setOf("smart", "direct") } ?: "smart"
    fun setHotspotMode(context: Context, mode: String) {
        check(mode in setOf("smart", "direct")) { "BF-ROOT-POLICY" }
        synchronized(transitionGate) {
            check(!changing && !BifrostUpdateInstallGate.pending) { "BF-CONNECTION-IN-FLIGHT" }
            val epoch = BifrostRootConnectionIntent.current(context)
            // Apply and read back the live kernel rule before persisting UI state.
            if (epoch != null) BifrostRootIpc.call(context, "hotspot", epoch,
                org.json.JSONObject().put("mode", mode))
            try {
                check(store(context).edit().putString("hotspot_mode", mode).commit()) { "BF-RELEASE-STATE" }
            } catch (error: Exception) {
                if (epoch != null) runCatching { BifrostRootIpc.call(context, "hotspot", epoch,
                    org.json.JSONObject().put("mode", hotspotMode(context))) }
                throw error
            }
        }
    }
    fun rootMode(context: Context) = store(context).getBoolean("root_mode", false)
    fun setRootMode(context: Context, enabled: Boolean) {
        val owner = synchronized(transitionGate) {
            check(BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED &&
                BifrostServiceOwnershipRegistry.current() == null && !BifrostUpdateInstallGate.pending) {
                "BF-CONNECTION-IN-FLIGHT"
            }
            BifrostApplicationPolicySnapshotRegistry.beginConfigurationChange()
                ?: error("BF-CONNECTION-IN-FLIGHT")
        }
        try {
            if (enabled) BifrostRootTunnel.probe(context)
            if (!enabled) BifrostRootConnectionIntent.stop(context)
            check(store(context).edit().putBoolean("root_mode", enabled).commit()) { "BF-RELEASE-STATE" }
            BifrostDiagnostics.record(context, if (enabled) "root-mode-enabled" else "root-mode-disabled")
        } finally {
            synchronized(transitionGate) { BifrostApplicationPolicySnapshotRegistry.endConfigurationChange(owner) }
        }
    }
}
