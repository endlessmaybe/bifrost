package com.bifrost.client

import android.content.Context
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.StringIterator
import java.io.IOException
import java.util.concurrent.TimeUnit
import org.json.JSONObject

/** Owns the official libbox TUN bridge and optional in-process Xray transport. */
class BifrostCoreAdapter internal constructor(
    private val context: Context,
    private val vpn: BifrostVpnService?,
    private val root: BifrostRootTunnel? = null,
    private val initialize: () -> Unit = { (context.applicationContext as BifrostApplication).ensureLibboxInitialized() },
    private val onStopped: () -> Unit = { vpn?.onCoreServiceStop(); Unit },
) : CommandServerHandler, BifrostCoreRuntime {
    private var commandServer: CommandServer? = null
    private var networkWakeLock: android.os.PowerManager.WakeLock? = null
    private val trafficObserver = BifrostTrafficObserver()
    private var platform: BifrostLibboxPlatform? = null
    private var xray: BifrostXrayTransport? = null
    private var preparedPolicy: BifrostApplicationPolicySnapshot? = null
    @Volatile private var dataPlaneHealth: BifrostDataPlaneHealth? = null
    private var activeRuntimeConfig: String? = null
    private var activeCandidateLabels: Map<String, String> = emptyMap()
    @Volatile private var serviceFailed = false

    /** Start the gomobile Xray transport before compiling the shared bridge. */
    @Synchronized
    @Throws(IOException::class)
    override fun prepareXray(
        config: String,
        applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>?,
    ): Int {
        val verifiedPolicy = BifrostApplicationPolicy.verify(applicationPolicy)
        initialize()
        if (xray?.isReady() == true) {
            val existing = preparedPolicy ?: throw IOException("BF-APP-POLICY-MISSING")
            check(existing.digest == verifiedPolicy.digest && existing.generation == verifiedPolicy.generation) {
                "BF-APP-POLICY-SNAPSHOT"
            }
            platform?.applicationPolicyReadback(expectedApplicationBindings)
                ?: throw IOException("BF-APP-POLICY-READBACK")
            return xray!!.port()
        }
        val bridge = platform ?: BifrostLibboxPlatform(context, vpn, root).also { platform = it }
        bridge.activate()
        bridge.configureApplicationPolicy(verifiedPolicy, expectedApplicationBindings)
        runCatching { Libbox.setXraySocketProtector(bridge) }
            .getOrElse { throw IOException("BF-XRAY-SOCKET-PROTECTOR", it) }
        check(Libbox.xrayProtectProbe()) { "BF-XRAY-PROTECT-PROBE" }
        val transport = xray ?: BifrostXrayTransport().also { xray = it }
        return transport.start(config).also { preparedPolicy = verifiedPolicy }
    }

    @Synchronized
    @Throws(IOException::class)
    fun prepareXray(config: String): Int = throw IOException("BF-APP-POLICY-MISSING")

    @Synchronized
    @Throws(IOException::class)
    override fun start(
        configContent: String,
        requestedCore: String,
        applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>?,
        candidateLabels: Map<String, String>,
        cancelled: () -> Boolean,
    ): Boolean {
        checkStartupCancellation(cancelled)
        val verifiedPolicy = BifrostApplicationPolicy.verify(applicationPolicy)
        initialize()
        if (isReady()) {
            val readback = platform?.applicationPolicyReadback(expectedApplicationBindings)
                ?: throw IOException("BF-APP-POLICY-READBACK")
            check(readback.digest == verifiedPolicy.digest && readback.generation == verifiedPolicy.generation) {
                "BF-APP-POLICY-READBACK"
            }
            preparedPolicy = verifiedPolicy
            runCatching { startTrafficObserver(activeRuntimeConfig ?: configContent) }.onFailure { trafficObserver.stop() }
            return true
        }
        val core = requestedCore.lowercase()
        require(core == "auto" || core == "sing-box" || core == "xray") { "BF-CORE-UNSUPPORTED-ANDROID" }
        if (core == "xray") check(xray?.isReady() == true) { "BF-XRAY-TRANSPORT-NOT-READY" }
        val parsed = runCatching { JSONObject(configContent) }.getOrElse { throw IOException("BF-CONFIG-JSON", it) }
        if (!containsTunInbound(parsed)) throw IOException("BF-TUN-CONFIG-MISSING")
        if (root != null) {
            BifrostRootDnsRouting.configure(parsed, listOf("com.tailscale.ipn"))
            BifrostHotspotRouting.configure(parsed)
            // Root owns a kernel TUN, so its TCP flows can use the system
            // stack. Keep gVisor for UDP, including DNS and QUIC.
            val inbounds = parsed.getJSONArray("inbounds")
            for (index in 0 until inbounds.length()) {
                val inbound = inbounds.getJSONObject(index)
                if (inbound.optString("type") == "tun") inbound.put("stack", "mixed")
            }
        }
        val health = BifrostDataPlaneHealth().also { dataPlaneHealth = it; it.configure(parsed) }
        BifrostQualityTransport.configure(parsed)
        val runtimeConfig = parsed.toString()
        activeRuntimeConfig = runtimeConfig
        activeCandidateLabels = candidateLabels.toMap()

        val bridge = platform ?: BifrostLibboxPlatform(context, vpn, root).also { platform = it }
        bridge.activate()
        bridge.configureApplicationPolicy(verifiedPolicy, expectedApplicationBindings)
        if (core == "xray") {
            runCatching { Libbox.setXraySocketProtector(bridge) }
                .getOrElse { throw IOException("BF-XRAY-SOCKET-PROTECTOR", it) }
            check(Libbox.xrayProtectProbe()) { "BF-XRAY-PROTECT-PROBE" }
        }
        val server = runCatching { Libbox.newCommandServer(this, bridge) }.getOrElse { throw IOException("BF-LIBBOX-SERVER", it) }
        commandServer = server
        serviceFailed = false
        var startStage = "server"
        try {
            server.start()
            startStage = "config"
            Libbox.checkConfig(runtimeConfig)
            startStage = "service"
            server.startOrReloadService(runtimeConfig, OverrideOptions().apply {
                autoRedirect = false
                includePackage = StringArray(verifiedPolicy.includePackages)
                excludePackage = StringArray(verifiedPolicy.excludePackages)
            })
            checkStartupCancellation(cancelled)
            if (!waitForTun(bridge, cancelled)) throw IOException("BF-TUN-NOT-CONSUMED")
            // Consume partial native health results while startup is still
            // checking connectivity. Waiting until after the health gate
            // leaves the first unavailable candidate selected for the whole
            // round and can fail startup before a healthy candidate wins.
            startStage = "selection"
            startTrafficObserver(runtimeConfig)
            startStage = "data-plane"
            val healthDeadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(BifrostDataPlaneHealth.startupBudgetMs(parsed))
            var healthy = false
            while (System.nanoTime() < healthDeadline) {
                checkStartupCancellation(cancelled)
                val result = health.check(TimeUnit.NANOSECONDS.toMillis(healthDeadline - System.nanoTime()), cancelled)
                checkStartupCancellation(cancelled)
                if (result) { healthy = true; break }
                Thread.sleep(250)
            }
            if (!healthy) throw IOException(health.lastFailure)
            val readback = bridge.applicationPolicyReadback() ?: throw IOException("BF-APP-POLICY-READBACK")
            check(readback.digest == verifiedPolicy.digest && readback.generation == verifiedPolicy.generation) {
                "BF-APP-POLICY-READBACK"
            }
            // Publish the verified immutable snapshot only after the complete
            // core/readback boundary succeeds.  The service's subsequent
            // readback must therefore observe the exact snapshot used for
            // compilation; a failed start never leaves a prepared policy.
            preparedPolicy = verifiedPolicy
            return true
        } catch (error: Exception) {
            android.util.Log.w("BifrostCoreDiagnostic", "stage=$startStage code=${BifrostUiErrorMapper.code(error)}")
            stop()
            throw if (error is IOException) error else IOException("BF-CORE-START", error)
        }
    }

    @Synchronized
    @Throws(IOException::class)
    override fun applicationPolicyReadback(
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>?,
    ): BifrostApplicationPolicySnapshot {
        val expected = preparedPolicy ?: throw IOException("BF-APP-POLICY-MISSING")
        val readback = platform?.applicationPolicyReadback(expectedApplicationBindings)
            ?: throw IOException("BF-APP-POLICY-READBACK")
        if (readback.canonicalJson != expected.canonicalJson ||
            readback.digest != expected.digest ||
            readback.generation != expected.generation) {
            throw IOException("BF-APP-POLICY-READBACK")
        }
        return readback
    }

    /** Raw package-list starts are deliberately not a compatibility path. */
    @Synchronized
    @Throws(IOException::class)
    fun start(
        configContent: String,
        requestedCore: String,
        includePackages: List<String>,
        excludePackages: List<String>,
        appPolicyMode: String,
    ): Boolean = throw IOException("BF-APP-POLICY-MISSING")

    private fun containsTunInbound(config: JSONObject): Boolean {
        val inbounds = config.optJSONArray("inbounds") ?: return false
        for (index in 0 until inbounds.length()) {
            if (inbounds.optJSONObject(index)?.optString("type") == "tun") return true
        }
        return false
    }

    private fun checkStartupCancellation(cancelled: () -> Boolean) {
        if (cancelled() || Thread.currentThread().isInterrupted) throw IOException("BF-CONNECTION-RELEASED")
    }

    private fun waitForTun(bridge: BifrostLibboxPlatform, cancelled: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            checkStartupCancellation(cancelled)
            if (bridge.tunOpened) return true
            Thread.sleep(50)
        }
        return false
    }

    @Synchronized
    override fun stop() {
        networkWakeLock?.let { if (it.isHeld) it.release() }; networkWakeLock = null
        dataPlaneHealth?.close()
        dataPlaneHealth = null
        activeRuntimeConfig = null
        trafficObserver.stop()
        var failure: Throwable? = null
        commandServer?.let { server ->
            var closed = true
            try { server.closeService() } catch (error: Throwable) { closed = false; failure = error }
            try { server.close() } catch (error: Throwable) { closed = false; if (failure == null) failure = error }
            if (closed) commandServer = null
        }
        platform?.let { bridge ->
            try {
                bridge.deactivate()
                bridge.tunOpened = false
                platform = null
            } catch (error: Throwable) {
                if (failure == null) failure = error
            }
        }
        xray?.let { transport ->
            try {
                transport.stop()
                xray = null
            } catch (error: Throwable) {
                if (failure == null) failure = error
            }
        }
        if (failure == null) preparedPolicy = null
        failure?.let { throw IllegalStateException("BF-CORE-STOP", it) }
    }

    // The user-selected performance policy keeps the active core runnable while
    // the screen is off. stop() releases this lease on disconnect and failures;
    // Android releases the Binder-owned lease if the daemon process dies.
    @android.annotation.SuppressLint("WakelockTimeout")
    private fun acquireNetworkWakeLock() {
        if (networkWakeLock?.isHeld == true) return
        val wake = context.getSystemService(android.os.PowerManager::class.java)
            .newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "Bifrost:network")
        wake.setReferenceCounted(false)
        wake.acquire()
        networkWakeLock = wake
    }

    private fun startTrafficObserver(config: String) {
        acquireNetworkWakeLock()
        trafficObserver.start(config, activeCandidateLabels,
            probeBudget = BifrostProbeBudgetStore.open(context),
            network = { AndroidNetworkBucket.fingerprint(context) },
            metered = { BifrostUnderlyingNetwork.isMetered(context) },
            // Performance-first selection also runs with the screen off.
            // User traffic still preempts probes, including background downloads.
            interactive = { true },
            observeNetwork = { callback -> AndroidNetworkBucket.observe(context, callback) },
            onNetworkChanged = { if (root != null) { root.networkChanged(); BifrostRootDnsCache.flush(context) } },
            diagnostic = { event -> BifrostDiagnostics.record(context, event) })
    }

    @Synchronized override fun isReady(): Boolean = !serviceFailed && commandServer != null && platform?.tunOpened == true &&
        (root?.alive() != false) && (xray == null || xray?.isReady() == true)

    override fun isDataPlaneHealthy(): Boolean = dataPlaneHealth?.check() == true

    override fun refreshOutboundHealth() {
        trafficObserver.refreshOutboundHealth()
        // Only refresh native URLTest children. Probing the outer selector
        // also starts a separate full sweep of its leaves, duplicating work
        // and delaying the watchdog on large provider lists.
    }

    /** libbox invokes this callback when its service dies. Do not tear down
     * the owned TUN first: the service must install its blackhole boundary
     * before releasing the failed core. */
    override fun serviceStop() { serviceFailed = true; onStopped() }
    override fun serviceReload() = Unit
    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus().apply { available = false; enabled = false }
    override fun setSystemProxyEnabled(enabled: Boolean) { check(!enabled) { "BF-SYSTEM-PROXY-DISABLED" } }
    override fun writeDebugMessage(message: String) {
        // TEMPORARY local-device diagnosis.  Keep this deliberately narrow and
        // scrub network identities; remove before the production release.
        val lower = message.lowercase()
        if (!lower.contains("dns") && !lower.contains("exchange") && !lower.contains("tls")) return
        val scrubbed = message.take(1200)
            .replace(Regex("(?i)\\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\b"), "<uuid>")
            .replace(Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"), "<ip>")
            .replace(Regex("(?i)(?:[a-z0-9-]+\\.)+[a-z]{2,}"), "<host>")
        android.util.Log.w("BifrostNativeDns", scrubbed)
    }

    private class StringArray(private val items: List<String>) : StringIterator {
        private val iterator = items.iterator()
        override fun len(): Int = items.size
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): String = iterator.next()
    }
}
