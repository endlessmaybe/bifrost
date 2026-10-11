package com.bifrost.client

/** Same lifecycle contract for the app-owned VPN and the independent Root core. */
interface BifrostCoreRuntime {
    fun prepareXray(config: String, applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>? = null): Int
    fun start(configContent: String, requestedCore: String,
        applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>? = null,
        candidateLabels: Map<String, String> = emptyMap(), cancelled: () -> Boolean = { false }): Boolean
    fun applicationPolicyReadback(expectedApplicationBindings: List<BifrostApplicationPackageBinding>? = null): BifrostApplicationPolicySnapshot
    fun stop()
    fun isReady(): Boolean
    fun isDataPlaneHealthy(): Boolean
    fun refreshOutboundHealth()
}

internal interface BifrostRootBoundary {
    fun configure(snapshot: BifrostApplicationPolicySnapshot)
    fun block(): Boolean
    fun releaseFence()
    fun alive(): Boolean
    fun close()
}
