package com.bifrost.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.*
import com.topjohnwu.superuser.ipc.RootService
import com.topjohnwu.superuser.Shell
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** One UID-authenticated Binder connection per client process. */
internal object BifrostRootIpc {
    const val MAX_PAYLOAD = 4 * 1024 * 1024
    private val main = Handler(Looper.getMainLooper())
    private val writer = Executors.newCachedThreadPool { task -> Thread(task, "bifrost-root-pipe").apply { isDaemon = true } }
    internal val cancellation = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "bifrost-root-cancel").apply { isDaemon = true } }
    private var connection: CompletableFuture<IBifrostRootRuntime>? = null
    internal var testTaskRunner: ((Shell.Task) -> Unit)? = null
    private fun service(context: Context): IBifrostRootRuntime {
        check(Looper.myLooper() != Looper.getMainLooper()) { "BF-ROOT-MAIN-THREAD" }
        val pending = synchronized(this) {
            connection ?: CompletableFuture<IBifrostRootRuntime>().also { future ->
                connection = future
                main.post {
                    runCatching {
                        val intent = Intent(context.applicationContext, BifrostRootRuntimeService::class.java)
                            .addCategory(RootService.CATEGORY_DAEMON_MODE)
                        val callback = object : ServiceConnection {
                            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                                future.complete(IBifrostRootRuntime.Stub.asInterface(binder))
                            }
                            override fun onServiceDisconnected(name: ComponentName) {
                                synchronized(this@BifrostRootIpc) { if (connection === future) connection = null }
                            }
                            override fun onNullBinding(name: ComponentName) {
                                future.completeExceptionally(IllegalStateException("BF-ROOT-BIND"))
                            }
                        }
                        val runner = testTaskRunner
                        if (runner != null) {
                            check(BuildConfig.BIFROST_TEST_VARIANT) { "BF-RELEASE-TEST-ONLY" }
                            RootService.bindOrTask(intent, context.mainExecutor, callback)?.let { task -> writer.execute { runner(task) } }
                        } else RootService.bind(intent, callback)
                    }.onFailure { future.completeExceptionally(it) }
                }
            }
        }
        return try { pending.get(35, TimeUnit.SECONDS) } catch (error: Exception) {
            synchronized(this) { if (connection === pending) connection = null }
            throw IllegalStateException("BF-ROOT-BIND", error)
        }
    }

    fun call(context: Context, operation: String, epoch: String, content: JSONObject? = null): Bundle = try {
        exchangeOnce(context, operation, epoch, content)
    } catch (error: IllegalStateException) {
        if (operation != "configure" || error.message != "BF-CONNECTION-RELEASED" ||
            !BifrostRootConnectionIntent.matches(context, epoch)) throw error
        // A daemon can outlive an APK replacement with the previous session
        // epoch and code still loaded. libsu's daemon stop closes its TUN and
        // routes before a fresh process binds to the installed APK.
        val stopped = CompletableFuture<Unit>()
        main.post {
            runCatching {
                RootService.stop(Intent(context.applicationContext, BifrostRootRuntimeService::class.java)
                    .addCategory(RootService.CATEGORY_DAEMON_MODE))
            }.onSuccess { stopped.complete(Unit) }.onFailure { stopped.completeExceptionally(it) }
        }
        stopped.get(10, TimeUnit.SECONDS)
        synchronized(this) { connection = null }
        Thread.sleep(750)
        check(BifrostRootConnectionIntent.matches(context, epoch)) { "BF-CONNECTION-RELEASED" }
        exchangeOnce(context, operation, epoch, content)
    }

    private fun exchangeOnce(context: Context, operation: String, epoch: String, content: JSONObject?): Bundle {
        val bytes = content?.toString()?.toByteArray(Charsets.UTF_8)
        check(bytes == null || bytes.size <= MAX_PAYLOAD) { "BF-ROOT-PAYLOAD" }
        val request = Bundle().apply { putString("op", operation); putString("epoch", epoch) }
        val remote = service(context)
        val pipe = bytes?.let { ParcelFileDescriptor.createReliablePipe() }
        val writing = pipe?.let { ends -> writer.submit {
            ParcelFileDescriptor.AutoCloseOutputStream(ends[1]).use { it.write(bytes!!) }
        } }
        try {
            val response = remote.exchange(request, pipe?.get(0))
            check(response.getBoolean("ok")) { response.getString("error") ?: "BF-ROOT-IPC" }
            writing?.get(10, TimeUnit.SECONDS)
            return response
        } catch (error: DeadObjectException) {
            synchronized(this) { connection = null }
            throw IllegalStateException("BF-ROOT-CLOSED", error)
        } finally { runCatching { pipe?.get(0)?.close() }; writing?.cancel(true) }
    }
}

internal enum class BifrostRootSessionState {
    READY,
    OWNER_NOT_READY,
    EMPTY,
    STALE_EPOCH,
    UNREACHABLE,
}

/** Only IPC metadata is shared; native handles and the optimizer stay in Root. */
internal class BifrostRootRemote(private val context: Context, val epoch: String) : BifrostRootBoundary, BifrostCoreRuntime {
    private var policy: BifrostApplicationPolicySnapshot? = null
    private fun call(op: String, content: JSONObject? = null) = BifrostRootIpc.call(context, op, epoch, content)
    override fun configure(snapshot: BifrostApplicationPolicySnapshot) {
        val verified = BifrostApplicationPolicy.verify(snapshot)
        BifrostRootTunnel.prepareExecutable(context)
        call("configure", JSONObject().put("policy", JSONObject(verified.canonicalJson))
            .put("hotspot_mode", BifrostFeaturePreferences.hotspotMode(context)))
        policy = verified
    }
    override fun block() = call("block").getBoolean("blocked")
    override fun releaseFence() { call("release") }
    override fun close() { call("close") }
    override fun alive() = runCatching { call("status").getBoolean("alive") }.getOrDefault(false)
    override fun prepareXray(config: String, applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>?): Int = call("xray",
        input(applicationPolicy, expectedApplicationBindings).put("config", config)).getInt("port")
    override fun start(configContent: String, requestedCore: String, applicationPolicy: BifrostApplicationPolicySnapshot,
        expectedApplicationBindings: List<BifrostApplicationPackageBinding>?, candidateLabels: Map<String, String>, cancelled: () -> Boolean): Boolean {
        check(!cancelled()) { "BF-CONNECTION-RELEASED" }
        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val observer = BifrostRootIpc.cancellation.scheduleWithFixedDelay({
            if (cancelled() && sent.compareAndSet(false, true)) runCatching { call("cancel-start") }
        }, 100, 100, TimeUnit.MILLISECONDS)
        return try {
            val result = call("start", input(applicationPolicy, expectedApplicationBindings)
                .put("config", configContent).put("core", requestedCore).put("labels", JSONObject(candidateLabels))).getBoolean("ready")
            check(!cancelled()) { "BF-CONNECTION-RELEASED" }
            result
        } finally { observer.cancel(false) }
    }
    private fun input(snapshot: BifrostApplicationPolicySnapshot, bindings: List<BifrostApplicationPackageBinding>?): JSONObject {
        check(policy?.canonicalJson == BifrostApplicationPolicy.verify(snapshot).canonicalJson) { "BF-APP-POLICY-READBACK" }
        return JSONObject().put("policy", JSONObject(snapshot.canonicalJson))
            .put("bindings", BifrostApplicationPackageBindings.encode(bindings ?: BifrostApplicationPolicyPackageValidator(
                AndroidApplicationPackageCatalog(context), context.packageName).validate(snapshot)))
    }
    override fun applicationPolicyReadback(expectedApplicationBindings: List<BifrostApplicationPackageBinding>?): BifrostApplicationPolicySnapshot {
        val expected = policy ?: error("BF-APP-POLICY-MISSING")
        val result = call("readback", input(expected, expectedApplicationBindings))
        check(result.getString("policy") == expected.canonicalJson) { "BF-APP-POLICY-READBACK" }
        return BifrostApplicationPolicy.verify(expected)
    }
    override fun stop() { call("stop-core") }
    override fun isReady(): Boolean = runCatching { refreshTelemetry() }.getOrDefault(false)
    fun refreshTelemetry(): Boolean {
        val response = call("status")
        BifrostTrafficTelemetry.acceptRemote(response.getLong("down"), response.getLong("up"),
            response.getLong("at"), response.getLong("total"), response.getLong("elapsed"))
        BifrostTrafficTelemetry.acceptRemoteRoute(response.getString("route"))
        return response.getBoolean("ready")
    }
    override fun isDataPlaneHealthy() = call("health").getBoolean("healthy")
    override fun refreshOutboundHealth() { call("refresh") }
    fun commit(owner: BifrostServiceOwnershipSnapshot) {
        call("commit", JSONObject().put("policy", JSONObject(owner.snapshot.canonicalJson))
            .put("bindings", owner.token.bindings).put("description", JSONObject().apply {
                put("core", owner.description.core); put("mode", owner.description.mode)
                put("source", owner.description.source); put("country", owner.description.country)
                put("frontSource", owner.description.frontSource); put("candidate", owner.description.candidate)
                put("connectionType", owner.description.connectionType)
            }))
    }
    fun snapshot(): JSONObject? = call("status").getString("owner")?.let(::JSONObject)
    fun sessionState(): BifrostRootSessionState = try {
        val response = call("status")
        val owner = response.getString("owner")
        when {
            owner == null -> BifrostRootSessionState.EMPTY
            response.getBoolean("ready") -> BifrostRootSessionState.READY
            else -> BifrostRootSessionState.OWNER_NOT_READY
        }
    } catch (error: IllegalStateException) {
        if (error.message == "BF-CONNECTION-RELEASED" &&
            BifrostRootConnectionIntent.matches(context, epoch)) BifrostRootSessionState.STALE_EPOCH
        else BifrostRootSessionState.UNREACHABLE
    }
}
