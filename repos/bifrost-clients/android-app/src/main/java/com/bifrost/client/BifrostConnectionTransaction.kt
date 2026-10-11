package com.bifrost.client

import java.io.IOException

/** The immutable package selected by the UI and verified by the package store. */
internal data class BifrostCompiledConnection(
    val config: String,
    val requestedCore: String,
    val applicationPolicy: BifrostApplicationPolicySnapshot,
    val expectedBindings: List<BifrostApplicationPackageBinding>?,
    val candidateLabels: Map<String, String> = emptyMap(),
    val cancelled: () -> Boolean = { false },
)

/** Narrow port used by the production service and by deterministic JVM seams. */
internal interface BifrostConnectionCorePort {
    @Throws(IOException::class)
    fun start(connection: BifrostCompiledConnection)

    @Throws(IOException::class)
    fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?): BifrostApplicationPolicySnapshot
}

/**
 * Single production connection transaction.  BifrostVpnService and lifecycle
 * fixtures both enter here; adapters are the only code allowed to touch the
 * core/TUN implementation.  A failed start never releases the fail-closed
 * boundary and cannot silently direct-connect.
 */
internal class BifrostConnectionTransaction(
    private val runtime: BifrostRuntimeCoordinator,
    private val core: BifrostConnectionCorePort,
) {
    @Throws(IOException::class)
    fun connect(connection: BifrostCompiledConnection): BifrostApplicationPolicySnapshot {
        if (connection.cancelled()) throw IOException("BF-CONNECTION-RELEASED")
        if (!runtime.starting()) throw IOException("BF-BLACKHOLE-UNAVAILABLE")
        try {
            core.start(connection)
            if (connection.cancelled()) throw IOException("BF-CONNECTION-RELEASED")
            val readback = core.readback(connection.expectedBindings)
            if (readback.canonicalJson != connection.applicationPolicy.canonicalJson ||
                readback.digest != connection.applicationPolicy.digest ||
                readback.generation != connection.applicationPolicy.generation) {
                throw IOException("BF-APP-POLICY-READBACK")
            }
            if (!runtime.coreReady()) throw IOException("BF-CORE-READY-WITHOUT-FENCE")
            return readback
        } catch (error: Exception) {
            // The owning service failure coordinator performs the final stop;
            // keeping the runtime in STARTING/HEALTHY here preserves the
            // evidence needed to install the blackhole before teardown.
            throw if (error is IOException) error else IOException("BF-CORE-START", error)
        }
    }
}

/** Adapter that binds the real Android core to the shared transaction. */
internal class ProductionBifrostCorePort(private val delegate: BifrostCoreRuntime) : BifrostConnectionCorePort {
    override fun start(connection: BifrostCompiledConnection) {
        delegate.start(
            connection.config,
            connection.requestedCore,
            connection.applicationPolicy,
            connection.expectedBindings,
            connection.candidateLabels,
            connection.cancelled,
        )
    }

    override fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?): BifrostApplicationPolicySnapshot =
        delegate.applicationPolicyReadback(expectedBindings)
}
