package com.bifrost.client

import android.content.Intent
import android.os.*
import com.topjohnwu.superuser.ipc.RootService
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** The transport, kernel TUN, DNS, failover and quality probes live here.
 * Recents cleanup can destroy every ordinary app process without closing them.
 * libsu supervises APK replacement/uninstall; explicit stop closes exact routes.
 */
class BifrostRootRuntimeService : RootService() {
    private val gate = Any()
    private val maintenance = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "bifrost-root-maintenance").apply { isDaemon = true } }
    private val healthWorker = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "bifrost-root-health").apply { isDaemon = true } }
    @Volatile private var epoch = ""
    private var sourcePolicy: String? = null
    private var policy: BifrostApplicationPolicySnapshot? = null
    private var owner: String? = null
    private var tunnel: BifrostRootTunnel? = null
    private var core: BifrostCoreAdapter? = null
    private var initialized = false
    private var lastAuth = 0L
    private var lastControl = 0L
    private var committed = false
    private var lastConfig: JSONObject? = null
    private var lastXray: JSONObject? = null
    private var failures = 0
    private var retryAt = 0L
    @Volatile private var stopping = false
    @Volatile private var startupCancelled = false
    private var testScope = false
    private var lastHealthCheck = 0L
    private var healthFailures = 0
    private var healthRecoveryRequested = false

    override fun onCreate() {
        check(Process.myUid() == 0) { "BF-ROOT-PERMISSION" }
        maintenance.scheduleWithFixedDelay({ runCatching { maintain() } }, 5, 5, TimeUnit.SECONDS)
        healthWorker.scheduleWithFixedDelay({ runCatching { checkTrafficHealth() } }, 5, 5, TimeUnit.SECONDS)
    }
    override fun onBind(intent: Intent): IBinder = object : IBifrostRootRuntime.Stub() {
        override fun exchange(request: Bundle, payload: ParcelFileDescriptor?): Bundle {
            // RootService also authenticates clients, but the returned Binder
            // can be passed to another app. Check UID on every transaction.
            check(Binder.getCallingUid() == applicationInfo.uid) { "BF-ROOT-PEER" }
            return try {
                // Cancellation cannot queue behind a slow native startup.
                // It only cancels the exact caller-owned epoch; cleanup still
                // runs through the ordinary fenced transaction.
                if (request.getString("op") == "cancel-start") {
                    check(request.getString("epoch") == epoch && epoch.isNotEmpty()) { "BF-CONNECTION-RELEASED" }
                    payload?.close()
                    startupCancelled = true
                    return Bundle().apply { putBoolean("ok", true) }
                }
                val content = payload?.let { descriptor ->
                    ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                        val buffer = ByteArray(8192)
                        val output = java.io.ByteArrayOutputStream()
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            check(output.size() + read <= BifrostRootIpc.MAX_PAYLOAD) { "BF-ROOT-PAYLOAD" }
                            output.write(buffer, 0, read)
                        }
                        JSONObject(output.toString("UTF-8"))
                    }
                }
                synchronized(gate) {
                    dispatch(request.getString("op").orEmpty(), request.getString("epoch").orEmpty(), content)
                        .apply { putBoolean("ok", true) }
                }
            } catch (error: Exception) {
                BifrostDiagnostics.record(this@BifrostRootRuntimeService, "root-operation-failed", error)
                Bundle().apply { putBoolean("ok", false); putString("error", BifrostUiErrorMapper.code(error)) }
            }
        }
    }

    private fun dispatch(op: String, requested: String, content: JSONObject?): Bundle {
        check(requested.matches(Regex("[0-9a-f]{32}"))) { "BF-CONNECTION-ID" }
        if (op == "configure" && epoch.isEmpty()) {
            BifrostRootBackgroundAccess.acquire(this)
            epoch = requested; lastAuth = SystemClock.elapsedRealtime(); stopping = false; startupCancelled = false
            tunnel = BifrostRootTunnel(this, ownerUid = applicationInfo.uid)
            core = BifrostCoreAdapter(this, null, tunnel, ::initializeRuntime) {
                // Never re-enter the native close callback synchronously.
                maintenance.execute { synchronized(gate) { runCatching { tunnel?.block() } } }
            }
        }
        if (epoch.isEmpty() && op in setOf("status", "close", "release", "stop-core", "terminate")) return Bundle()
        check(epoch == requested && !stopping) { "BF-CONNECTION-RELEASED" }
        val result = Bundle()
        when (op) {
            "configure" -> {
                val supplied = content!!.getJSONObject("policy")
                val identities = supplied.getJSONArray("identities").let { list -> (0 until list.length()).map(list::getString) }
                val next = BifrostApplicationPolicy.normalize(supplied.getString("route_mode"), supplied.getString("policy_mode"),
                    if (supplied.getString("policy_mode") == "allow") identities else emptyList(),
                    if (supplied.getString("policy_mode") == "exclude") identities else emptyList())
                val previous = policy
                // Client generations are process-local capabilities. The daemon
                // issues its own and retains it across UI process replacement.
                if (previous != null && (core?.isReady() == true || tunnel?.attached == true)) {
                    check(previous.routeMode == next.routeMode && previous.policyMode == next.policyMode &&
                        previous.includePackages == next.includePackages && previous.excludePackages == next.excludePackages) { "BF-ROOT-POLICY-CHANGED" }
                } else { policy = next; tunnel!!.configure(next) }
                sourcePolicy = supplied.toString()
                tunnel!!.setHotspotMode(content.optString("hotspot_mode", BifrostFeaturePreferences.hotspotMode(this)))
                testScope = BuildConfig.BIFROST_TEST_VARIANT && next.policyMode == "allow" && identities == listOf("com.android.shell")
            }
            "hotspot" -> tunnel!!.setHotspotMode(content!!.getString("mode"))
            "block" -> result.putBoolean("blocked", tunnel!!.block())
            "release" -> {
                tunnel!!.releaseFence()
                if (core?.isReady() != true) clearSession()
            }
            "xray" -> {
                verifyInput(content!!)
                result.putInt("port", core!!.prepareXray(content.getString("config"), policy!!, bindings(content)))
                lastXray = JSONObject(content.toString())
            }
            "start" -> {
                verifyInput(content!!)
                val labels = content.getJSONObject("labels").let { map -> map.keys().asSequence().associateWith(map::getString) }
                val ready = core!!.start(content.getString("config"), content.getString("core"), policy!!, bindings(content), labels) { stopping || startupCancelled }
                if (ready) lastConfig = JSONObject(content.toString())
                result.putBoolean("ready", ready)
            }
            "readback" -> {
                verifyInput(content!!)
                check(core!!.applicationPolicyReadback(bindings(content)).canonicalJson == policy!!.canonicalJson) { "BF-APP-POLICY-READBACK" }
                result.putString("policy", sourcePolicy)
            }
            "commit" -> {
                verifyInput(content!!)
                check(core!!.isReady()) { "BF-ROOT-NOT-READY" }
                core!!.applicationPolicyReadback(bindings(content))
                owner = content.toString(); committed = true; failures = 0
                healthFailures = 0; healthRecoveryRequested = false
            }
            "status" -> {
                result.putBoolean("ready", core?.isReady() == true)
                result.putBoolean("alive", tunnel?.alive() == true)
                result.putInt("pid", Process.myPid())
                result.putString("owner", owner)
                val traffic = BifrostTrafficTelemetry.notificationTraffic.latest
                result.putLong("down", traffic.down); result.putLong("up", traffic.up); result.putLong("at", traffic.at)
                result.putLong("total", BifrostTrafficTelemetry.totalBytes)
                result.putLong("elapsed", BifrostTrafficTelemetry.runningMillis(SystemClock.elapsedRealtime()))
                result.putString("route", BifrostTrafficTelemetry.route.value)
            }
            "health" -> result.putBoolean("healthy", core?.isDataPlaneHealthy() == true)
            "refresh" -> core?.refreshOutboundHealth()
            "stop-core" -> {
                committed = false; owner = null; lastConfig = null; lastXray = null
                healthFailures = 0; healthRecoveryRequested = false
                core?.stop()
            }
            "close" -> { core?.stop(); tunnel?.close(); clearSession() }
            "authorized" -> lastAuth = SystemClock.elapsedRealtime()
            "terminate" -> terminate()
            else -> error("BF-ROOT-PROTOCOL")
        }
        return result
    }
    private fun verifyInput(content: JSONObject) {
        check(content.getJSONObject("policy").toString() == sourcePolicy) { "BF-APP-POLICY-READBACK" }
        BifrostApplicationPolicyPackageValidator(AndroidApplicationPackageCatalog(this), packageName).validate(policy!!, bindings(content))
    }
    private fun bindings(content: JSONObject) = BifrostApplicationPackageBindings.decode(content.getString("bindings"))
    private fun initializeRuntime() {
        if (initialized) return
        // Root-only ephemeral/runtime files never replace the app's encrypted
        // configuration, Keystore data, account metadata or ordinary core cache.
        val base = File(noBackupFilesDir, "root-runtime").apply { mkdirs() }
        android.system.Os.chmod(base.absolutePath, 0x1c0)
        Libbox.setup(SetupOptions().apply {
            basePath = base.absolutePath; workingPath = base.absolutePath
            tempPath = File(base, "tmp").apply { mkdirs() }.absolutePath
            commandServerListenPort = 0; commandServerSecret = ""
            fixAndroidStack = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
            // Production Root runs without verbose native diagnostics.  The
            // bounded app-side lifecycle log remains available for failures.
            logMaxLines = 0; debug = false
        })
        initialized = true
    }
    private fun maintain() {
        val wakeEpoch = synchronized(gate) {
            if (epoch.isEmpty() || stopping || startupCancelled) return
            val now = SystemClock.elapsedRealtime()
            if (!testScope && now - lastControl >= 60_000L) {
                lastControl = now
                epoch
            } else null
        }
        if (wakeEpoch != null) wakeControlWorker(wakeEpoch)
        synchronized(gate) {
            if (epoch.isEmpty() || epoch != wakeEpoch && wakeEpoch != null || stopping || startupCancelled) return@synchronized
            val now = SystemClock.elapsedRealtime()
        // A transient control/network failure does not tear down a working
        // tunnel. Explicit revocation stops immediately; unrenewed authority
        // has a finite offline grace period, including while the UI is absent.
            if (!testScope && now - lastAuth > TimeUnit.HOURS.toMillis(24)) { terminate(); return@synchronized }
            tunnel?.refreshHotspot()
            if (!committed || now < retryAt || core?.isReady() == true && !healthRecoveryRequested) return@synchronized
            val config = lastConfig ?: return@synchronized
            val recovered = runCatching {
                BifrostRootRecoverySequence.prepare(tunnel!!.alive(), { tunnel!!.block() }, { core!!.stop() })
                if (config.getString("core") == "xray") {
                    val transport = lastXray ?: error("BF-XRAY-TRANSPORT-NOT-READY")
                    core!!.prepareXray(transport.getString("config"), policy!!, bindings(transport))
                }
                val labels = config.getJSONObject("labels").let { map -> map.keys().asSequence().associateWith(map::getString) }
                check(core!!.start(config.getString("config"), config.getString("core"), policy!!, bindings(config), labels) { stopping || startupCancelled }) { "BF-ROOT-NOT-READY" }
                tunnel!!.releaseFence()
            }.onFailure { BifrostDiagnostics.record(this, "root-recovery-failed", it) }.isSuccess
            if (recovered) {
                healthRecoveryRequested = false
                healthFailures = 0
                BifrostDiagnostics.record(this, "root-recovery-completed")
            }
            failures = if (recovered) 0 else (failures + 1).coerceAtMost(6)
            retryAt = now + (5_000L shl failures).coerceAtMost(60_000L)
        }
    }
    private fun wakeControlWorker(requestEpoch: String) {
        if (testScope) return
        // This can wait for Android's activity manager, so it must never hold
        // the Binder/runtime gate used by status, stop and disconnect.
        runCatching {
            val child = ProcessBuilder("/system/bin/am", "start-foreground-service", "--user",
                (applicationInfo.uid / 100000).toString(), "-n", "$packageName/.BifrostRootControlService",
                "--es", "epoch", requestEpoch).redirectErrorStream(true).start()
            val drain = Thread {
                runCatching { child.inputStream.use { stream -> while (stream.read() >= 0) {} } }
            }.apply { isDaemon = true; start() }
            if (!child.waitFor(8, TimeUnit.SECONDS)) child.destroy()
            drain.join(1000)
        }.onFailure { BifrostDiagnostics.record(this, "root-control-wake-failed", it) }
    }
    private fun checkTrafficHealth() {
        val activeCore = synchronized(gate) {
            if (!committed || stopping || startupCancelled) return
            core ?: return
        }
        // isReady() can perform a Root tunnel STATUS readback. Never hold the
        // Binder/runtime gate across that IPC; status, stop and maintenance
        // must remain responsive while health work checks the data plane.
        if (!activeCore.isReady()) return
        val admitted = synchronized(gate) {
            if (core !== activeCore || !committed || stopping || startupCancelled) return
            val now = SystemClock.elapsedRealtime()
            if (!BifrostMaintenancePolicy.shouldProbe(now, lastHealthCheck, false,
                getSystemService(android.os.PowerManager::class.java).isInteractive,
                BifrostTrafficTelemetry.lastReceiveAt, BifrostTrafficTelemetry.lastSendAt, healthFailures,
                BifrostTrafficTelemetry.lastTransportFailureAt)) return
            lastHealthCheck = now
            true
        }
        if (!admitted) return
        // Never hold the control/stop gate while waiting for a remote host.
        val healthy = activeCore.isDataPlaneHealthy()
        var refresh = false
        synchronized(gate) {
            if (core !== activeCore || !committed || stopping) return
            if (healthy) healthFailures = 0 else {
                healthFailures = (healthFailures + 1).coerceAtMost(8)
                // URLTest refresh can block on native IPC. Recording the
                // failure/recovery intent is cheap; perform the refresh after
                // releasing the Binder/runtime gate so status, stop and UI
                // telemetry are never queued behind maintenance work.
                refresh = true
                // Refreshing URLTest children cannot recover a wedged DNS or
                // UDP engine. After two consecutive end-to-end failures while
                // the traffic policy observes demand, request a fenced rebuild
                // on the maintenance worker. The Root TUN remains owned and
                // blocked during recovery, so there is no direct-path leak.
                if (healthFailures >= 2 && !healthRecoveryRequested) {
                    healthRecoveryRequested = true
                    retryAt = 0L
                    BifrostDiagnostics.record(this, "root-health-recovery-requested")
                }
            }
        }
        if (refresh) activeCore.refreshOutboundHealth()
    }
    private fun terminate() {
        stopping = true; committed = false; lastConfig = null; lastXray = null; owner = null
        healthFailures = 0; healthRecoveryRequested = false
        core?.stop(); tunnel?.close()
        BifrostRootBackgroundAccess.release(this)
        Handler(Looper.getMainLooper()).post { stopSelf() }
    }
    private fun clearSession() {
        BifrostRootBackgroundAccess.release(this)
        committed = false; owner = null; lastConfig = null; lastXray = null; sourcePolicy = null; policy = null; epoch = ""
        healthFailures = 0; healthRecoveryRequested = false
        Handler(Looper.getMainLooper()).postDelayed({ synchronized(gate) { if (epoch.isEmpty()) stopSelf() } }, 10_000)
    }
    override fun onDestroy() {
        maintenance.shutdownNow()
        healthWorker.shutdownNow()
        synchronized(gate) { runCatching { core?.stop() }; runCatching { tunnel?.close() } }
        BifrostRootBackgroundAccess.release(this)
    }
}
