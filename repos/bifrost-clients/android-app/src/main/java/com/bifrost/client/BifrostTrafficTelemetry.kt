package com.bifrost.client

import android.os.SystemClock
import com.bifrost.client.ui.model.BifrostUiMetrics
import io.nekohasekai.libbox.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale

internal object BifrostTrafficTelemetry {
    val notificationTraffic = BifrostNotificationTraffic()
    private val current = MutableStateFlow(BifrostUiMetrics())
    val metrics = current.asStateFlow()
    private val selectedRoute = MutableStateFlow<String?>(null)
    val route = selectedRoute.asStateFlow()
    private var routeGeneration = 0L
    @Synchronized fun beginRoute(): Long { selectedRoute.value = null; return ++routeGeneration }
    @Synchronized fun acceptRoute(generation: Long, label: String?) {
        if (generation == routeGeneration) selectedRoute.value = label
    }
    @Synchronized fun acceptRemoteRoute(label: String?) { selectedRoute.value = label }
    private var startedAt = 0L
    @Volatile var totalBytes = 0L
        private set
    private var lastRemoteSample = 0L
    fun runningMillis(now: Long) = if (startedAt > 0) (now - startedAt).coerceAtLeast(0) else 0L
    @Volatile var lastReceiveAt = 0L
        private set
    @Volatile var lastSendAt = 0L
        private set
    @Volatile var lastTransportFailureAt = 0L
        private set
    fun recordTransportFailure(now: Long = SystemClock.elapsedRealtime()) {
        lastTransportFailureAt = now
    }
    @Synchronized fun reset() {
        notificationTraffic.reset()
        startedAt = SystemClock.elapsedRealtime(); current.value = BifrostUiMetrics()
        lastReceiveAt = 0; lastSendAt = 0
        lastTransportFailureAt = 0
        totalBytes = 0; lastRemoteSample = 0
    }
    @Synchronized fun accept(message: StatusMessage) {
        notificationTraffic.accept(message.downlink, message.uplink, SystemClock.elapsedRealtime(), message.trafficAvailable)
        if (!message.trafficAvailable) return
        val now = SystemClock.elapsedRealtime()
        if (message.downlink > 1024) lastReceiveAt = now
        if (message.uplink > 1024) lastSendAt = now
        totalBytes = message.downlinkTotal.coerceAtLeast(0) + message.uplinkTotal.coerceAtLeast(0)
        // The VPN still needs cheap traffic counters for busy-link and outage
        // detection. Formatting and chart allocations belong to the visible UI.
        publish(message.downlink, message.uplink, totalBytes, runningMillis(now))
    }
    @Synchronized fun acceptRemote(down: Long, up: Long, at: Long, total: Long, elapsed: Long) {
        notificationTraffic.accept(down, up, at, at > 0)
        if (at <= 0 || at == lastRemoteSample) return
        lastRemoteSample = at
        totalBytes = total.coerceAtLeast(0)
        startedAt = (SystemClock.elapsedRealtime() - elapsed).coerceAtLeast(1)
        if (down > 1024) lastReceiveAt = at
        if (up > 1024) lastSendAt = at
        publish(down, up, totalBytes, elapsed)
    }
    private fun publish(downlink: Long, uplink: Long, total: Long, elapsed: Long) {
        if (!BifrostAppVisibility.visible) return
        val down = downlink.coerceAtLeast(0).toFloat()
        val up = uplink.coerceAtLeast(0).toFloat()
        val seconds = (elapsed / 1000).coerceAtLeast(0)
        current.value = BifrostUiMetrics(
            download = format(down.toDouble()) + "/s", upload = format(up.toDouble()) + "/s",
            sessionTraffic = format(total.toDouble()),
            duration = String.format(Locale.ROOT, "%02d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60),
            samples = (current.value.samples + down).takeLast(60),
            uploadSamples = (current.value.uploadSamples + up).takeLast(60),
        )
    }
    private fun format(bytes: Double): String {
        var value = bytes; var unit = 0
        val units = arrayOf("B", "KB", "MB", "GB")
        while (value >= 1024 && unit < units.lastIndex) { value /= 1024; unit++ }
        return String.format(Locale.ROOT, "%.1f", value) + " " + units[unit]
    }
}

internal class BifrostTrafficObserver : CommandClientHandler {
    private var client: CommandClient? = null
    @Volatile private var progressive: BifrostProgressiveSelector? = null
    @Volatile private var quietTraffic: BifrostProbeTrafficGuard? = null
    private var lastNetworkCheckAt = 0L
    private var networkObserver: java.io.Closeable? = null
    private var networkWorker: java.util.concurrent.ScheduledExecutorService? = null
    @Volatile private var networkCheck: ((Long) -> Unit)? = null
    fun start(config: String, labels: Map<String, String> = emptyMap(), network: () -> String = { "" }, metered: () -> Boolean = { true }, interactive: () -> Boolean = { true },
        probeBudget: BifrostProbeBudget = BifrostProbeBudget(), observeNetwork: ((() -> Unit) -> java.io.Closeable?) = { null }, onNetworkChanged: () -> Unit = {}, diagnostic: (String) -> Unit = {}) {
        stop()
        val selector = BifrostProgressiveSelector(config,
            probeBudget = probeBudget,
            // Connection ownership, not the Activity, owns optimization. Users
            // normally leave Bifrost to browse; idle/traffic and power budgets
            // below still prevent measurement from competing with their traffic.
            // Match Windows: the recovery gate decides admission and the
            // in-flight traffic threshold yields immediately when needed.
            // An extra 30-second all-idle gate kept slower incumbents pinned.
            automaticWorkAllowed = interactive,
            recoveryWorkAllowed = interactive,
            reportDiagnostic = { event ->
                if (event.startsWith("round=completed")) diagnostic("optimizer-round-completed")
                else if (event.startsWith("round=recovery-requested")) diagnostic(
                    if (event.endsWith("reason=slow-traffic")) "optimizer-slow-traffic-recovery" else "optimizer-failure-recovery")
                else if (event.startsWith("round=promoted")) diagnostic("optimizer-candidate-promoted")
                else if (event.startsWith("round=progress")) diagnostic("optimizer-sample-completed")
                else if (event.startsWith("round=retry")) diagnostic("optimizer-round-retry")
            })
        progressive = selector
        quietTraffic = null
        val routeGeneration = BifrostTrafficTelemetry.beginRoute()
        val routeLabels = labels.toMap()
        BifrostTrafficTelemetry.acceptRoute(routeGeneration, BifrostRouteReadback.resolve(routeLabels, emptyMap()))
        lastNetworkCheckAt = 0
        progressive?.metered = metered()
        var lastFingerprint = runCatching { network() }.getOrDefault("")
        selector.networkChanged(lastFingerprint)
        val handover = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { work ->
            Thread(work, "bifrost-network-handover").apply { isDaemon = true }
        }
        networkWorker = handover
        val gate = Any()
        var pending: java.util.concurrent.ScheduledFuture<*>? = null
        networkCheck = { delay -> synchronized(gate) {
            if (progressive === selector && !handover.isShutdown) {
                pending?.cancel(false)
                pending = handover.schedule({
                    runCatching {
                        if (progressive !== selector) return@schedule
                        val fingerprint = network()
                        selector.metered = metered()
                        if (fingerprint != lastFingerprint) {
                            onNetworkChanged()
                            if (progressive === selector) {
                                selector.networkChanged(fingerprint)
                                lastFingerprint = fingerprint
                                diagnostic("optimizer-network-changed")
                            }
                        }
                    }.onFailure { diagnostic("optimizer-network-retry") }
                }, delay, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
        } }
        networkObserver = observeNetwork { networkCheck?.invoke(750L) }
        BifrostTrafficTelemetry.reset()
        val options = CommandClientOptions().apply {
            statusInterval = 1_000_000_000L
            addCommand(Libbox.CommandStatus)
            addCommand(Libbox.CommandLog)
            addCommand(Libbox.CommandGroup)
        }
        val handler = object : CommandClientHandler by this {
            override fun writeGroups(message: OutboundGroupIterator) {
                val groups = mutableListOf<OutboundGroup>()
                while (message.hasNext()) message.next()?.let { groups.add(it) }
                val selections = groups.associate { it.tag to it.selected }
                BifrostTrafficTelemetry.acceptRoute(routeGeneration, BifrostRouteReadback.resolve(routeLabels, selections))
                selector.accept(object : OutboundGroupIterator {
                    private val iterator = groups.iterator()
                    override fun hasNext() = iterator.hasNext()
                    override fun next() = iterator.next()
                })
            }
        }
        client = Libbox.newCommandClient(handler, options).also { it.connect() }
        diagnostic(if (selector.automaticSelection) "optimizer-started" else "manual-selection-active")
    }
    fun stop() {
        quietTraffic = null
        networkCheck = null; networkObserver?.close(); networkObserver = null
        networkWorker?.shutdownNow(); networkWorker = null
        BifrostTrafficTelemetry.beginRoute(); progressive?.close(); progressive = null
        runCatching { client?.disconnect() }; client = null; BifrostTrafficTelemetry.reset()
    }
    fun refreshOutboundHealth() {
        // An optional URLTest IPC failure must not terminate the service's
        // scheduled watchdog. The optimizer handles its own retry separately.
        runCatching { progressive?.refresh() }
    }
    override fun writeStatus(message: StatusMessage) {
        BifrostTrafficTelemetry.accept(message)
        val now = SystemClock.elapsedRealtime()
        if (now - lastNetworkCheckAt >= 5_000) {
            lastNetworkCheckAt = now
            networkCheck?.invoke(0L)
        }
        val probeBytes = progressive?.takeProbeBodyBytes() ?: 0L
        val rate = if (message.trafficAvailable) BifrostUserTrafficLoad.rate(message.downlink, message.uplink, probeBytes) else Double.NaN
        progressive?.updateUserTraffic(rate)
    }
    override fun clearLogs() = Unit
    override fun connected() = Unit
    override fun disconnected(message: String) = Unit
    override fun initializeClashMode(modeList: StringIterator, currentMode: String) = Unit
    override fun setDefaultLogLevel(level: Int) = Unit
    override fun updateClashMode(newMode: String) = Unit
    override fun writeConnectionEvents(events: ConnectionEvents) = Unit
    override fun writeGroups(message: OutboundGroupIterator) { progressive?.accept(message) }
    private var lastDiagnostic = ""
    override fun writeLogs(messageList: LogIterator) {
        while (messageList.hasNext()) {
            val entry = messageList.next() ?: continue
            // Native levels 0..3 are panic/fatal/error/warn; sniff INFO
            // messages mentioning TLS or DNS are not transport failures.
            if (entry.level !in 0..3) continue
            val message = entry.message.orEmpty()
            progressive?.observeTransportFailure(message)
            // Diagnose transport failure without disclosing destinations, profiles or payloads.
            val terms = listOf("EOF", "tls", "websocket", "bad handshake", "connection reset",
                "connection closed", "dns", "timeout", "network is unreachable", "no such host",
                "x509", "certificate", "unknown authority", "expired", "handshake", "record header",
                "unrecognized name", "remote error", "first record", "invalid response", "loop", "not found",
                "exchange failed", "dial tcp", "lookup", "socks", "connection refused", "context canceled",
                "permission denied", "network unreachable", "operation not permitted")
                .filter { message.contains(it, ignoreCase = true) }.joinToString(",")
            if (terms.isNotEmpty() && terms != lastDiagnostic) {
                lastDiagnostic = terms
                BifrostTrafficTelemetry.recordTransportFailure()
                android.util.Log.w("BifrostDataPlaneDiagnostic", "terms=$terms")
            }
        }
    }
}
