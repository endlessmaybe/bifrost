package com.bifrost.client

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import com.bifrost.client.ui.model.BifrostRoutingContract
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Reuses the exact policy/selection/service handshake without requiring an Activity. */
internal object BifrostBackgroundConnection {
    private val gate = Any()
    fun connect(context: Context, recoveryEpoch: String? = null) = synchronized(gate) {
        check(!BifrostFeaturePreferences.changing) { "BF-CONNECTION-IN-FLIGHT" }
        check(!BifrostUpdateInstallGate.pending) { "BF-CONNECTION-IN-FLIGHT" }
        val root = BifrostFeaturePreferences.rootMode(context)
        if (recoveryEpoch != null) check(root && BifrostRootConnectionIntent.matches(context, recoveryEpoch)) { "BF-CONNECTION-RELEASED" }
        val live = BifrostServiceOwnershipRegistry.current()
        if (live?.phase == BifrostServiceOwnershipPhase.COMMITTED && BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY) return@synchronized
        val epoch = if (root) recoveryEpoch ?: BifrostRootConnectionIntent.begin(context) else null
        fun checkRequest() { if (epoch != null) check(BifrostRootConnectionIntent.matches(context, epoch)) { "BF-CONNECTION-RELEASED" } }
        if (live != null) {
            check(live.phase in setOf(BifrostServiceOwnershipPhase.BLOCKED_FAILED, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED)) { "BF-CONNECTION-IN-FLIGHT" }
            disconnectFailed(context, live.token, epoch)
        }
        checkRequest()
        check(!BifrostUpdateInstallGate.pending && BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED) { "BF-CONNECTION-IN-FLIGHT" }
        check(BifrostFeaturePreferences.rootMode(context) || VpnService.prepare(context) == null) { "BF-VPN-PERMISSION" }
        val control = BifrostControlClient(context)
        check(control.accountSnapshot().enrolled) { "BF-NOT-ENROLLED" }
        val cached = BifrostConfigStore.load(context) ?: error("BF-CONFIG-CACHE-MISSING")
        val values = BifrostSecureStore.readBatch(context, BifrostSecureStore.UiKeys)
        fun value(key: String, default: String = "") = values[key].orEmpty().ifBlank { default }
        val selection = BifrostConnectionRouteContract.parse(value("connection_type"), value("route_mode"))
        val presentation = BifrostConnectionRouteContract.presentationMode(selection)
        val source = value("source")
        check(source.isNotBlank()) { "BF-SOURCE-SELECTION-REQUIRED" }
        val country = if (presentation == "smartgate") value("country", "auto") else "auto"
        val front = if (presentation == "smartgate") value("front_source", "auto") else "auto"
        val core = value("core", "auto")
        val candidateMode = if (presentation == "global") "manual" else "auto"
        val node = BifrostCandidateSelectionContract.validate(cached.content, source, presentation, country,
            BifrostNodeSelection(BifrostCandidateMode.parse(candidateMode), value("candidate_label").ifBlank { null }, core))
        // A successful non-per-app connection persists the effective policy
        // as "none". Restore the same allow/exclude UI default as MainActivity.
        val routing = BifrostRoutingContract.select(selection, restoredAppPolicy(values["app_policy"]),
            BifrostApplicationPolicy.parseUiList(value("include_apps")),
            BifrostApplicationPolicy.parseUiList(value("exclude_apps")))
        val policy = BifrostApplicationPolicy.normalize(selection.routeMode.wireValue,
            routing.policyMode, routing.include, routing.exclude)
        val bindings = BifrostApplicationPolicyPackageValidator(AndroidApplicationPackageCatalog(context),
            context.packageName).validate(policy)
        val encoded = BifrostApplicationPackageBindings.encode(bindings)
        val transaction = UUID.randomUUID().toString().replace("-", "")
        val token = BifrostServiceTransactionToken(transaction, policy.generation, policy.digest, encoded)
        synchronized(BifrostFeaturePreferences.transitionGate) {
            checkRequest()
            check(!BifrostUpdateInstallGate.pending &&
                BifrostApplicationPolicySnapshotRegistry.register(transaction, policy)) { "BF-CONNECTION-ACTIVE" }
        }
        var dispatched = false
        try {
            val sources = JSONObject(cached.content).getJSONArray("sources")
            val sourceObject = (0 until sources.length()).map { sources.getJSONObject(it) }
                .first { it.getString("code").equals(source, true) }
            val seed = if (candidateMode == "manual") node.manualLabel
                else sourceObject.getJSONArray("candidates").getJSONObject(0).getString("label")
            val selected = AtomicReference<Result<BifrostCandidateSelectionReceipt>?>(null)
            val selectionDone = CountDownLatch(1)
            val coordinator = (context.applicationContext as BifrostApplication).candidateProbeCoordinator
            val request = coordinator.selectForConnection(source, seed) { result -> selected.set(result); selectionDone.countDown() }
            val receipt = try {
                val budget = BifrostCandidateSelector.connectionBudgetMs(sourceObject.getJSONArray("candidates").length())
                check(selectionDone.await(budget, TimeUnit.MILLISECONDS)) { "BF-PROBE-TIMEOUT" }
                selected.get()?.getOrThrow() ?: error("BF-CANDIDATE-MISSING")
            } finally { request.close() }
            val acknowledged = CountDownLatch(1)
            val acknowledgementError = AtomicReference<String?>(null)
            val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(code: Int, data: Bundle?) {
                    if (data?.getString(BifrostVpnService.EXTRA_TRANSACTION_ID) != transaction) return
                    if (code != BifrostVpnService.RESULT_READY) acknowledgementError.set(
                        data.getString(BifrostVpnService.EXTRA_ACK_CODE) ?: "BF-CONNECTION-READBACK")
                    acknowledged.countDown()
                }
            }
            val binding = receipt.binding
            val intent = Intent(context, BifrostVpnService::class.java)
                .putExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH, epoch)
                .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, transaction)
                .putExtra(BifrostVpnService.EXTRA_CORE, core)
                .putExtra(BifrostVpnService.EXTRA_MODE, selection.routeMode.wireValue)
                .putExtra(BifrostVpnService.EXTRA_CONNECTION_TYPE, selection.connectionType.wireValue)
                .putExtra(BifrostVpnService.EXTRA_ROUTE_MODE, selection.routeMode.wireValue)
                .putExtra(BifrostVpnService.EXTRA_SOURCE, source)
                .putExtra(BifrostVpnService.EXTRA_COUNTRY, country)
                .putExtra(BifrostVpnService.EXTRA_FRONT_SOURCE, front.takeIf { it != "auto" })
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE, receipt.label)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_MODE, candidateMode)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_NETWORK, binding.networkFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_CONFIG_VERSION, binding.configVersion)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_CONFIG_DIGEST, binding.configDigest)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_FINGERPRINT, binding.candidateFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_TRANSPORT_FINGERPRINT, binding.transportFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_GENERATION, binding.generation)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, policy.digest)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, policy.generation)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, encoded)
                .putExtra(BifrostVpnService.EXTRA_ACK_RECEIVER, receiver)
            checkRequest()
            context.startForegroundService(intent); dispatched = true
            check(acknowledged.await(315, TimeUnit.SECONDS)) { "BF-CONNECTION-TIMEOUT" }
            acknowledgementError.get()?.let { error(it) }
            checkRequest()
            val owner = BifrostServiceOwnershipRegistry.current()
            check(owner?.token == token && owner.phase == BifrostServiceOwnershipPhase.COMMITTED &&
                BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY) { "BF-CONNECTION-READBACK" }
            BifrostRuntimeStatus.publish(BifrostRuntimeStatus.current)
        } catch (error: Throwable) {
            if (dispatched) {
                BifrostServiceOwnershipRegistry.requestDisconnect(token)
                runCatching { context.startForegroundService(Intent(context, BifrostVpnService::class.java)
                    .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_DISCONNECT)
                    .putExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH, epoch)
                    .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, transaction)
                    .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, policy.generation)
                    .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, policy.digest)
                    .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, encoded)) }
            } else BifrostApplicationPolicySnapshotRegistry.remove(transaction)
            throw error
        }
    }
    private fun disconnectFailed(context: Context, token: BifrostServiceTransactionToken, epoch: String?) {
        val done = CountDownLatch(1)
        val failure = AtomicReference<String?>(null)
        val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                if (data?.getString(BifrostVpnService.EXTRA_TRANSACTION_ID) != token.transactionId) return
                if (code != BifrostVpnService.RESULT_DISCONNECTED) failure.set(data.getString(BifrostVpnService.EXTRA_ACK_CODE) ?: "BF-CONNECTION-READBACK")
                done.countDown()
            }
        }
        BifrostServiceOwnershipRegistry.requestDisconnect(token)
        context.startForegroundService(Intent(context, BifrostVpnService::class.java)
            .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_DISCONNECT)
            .putExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH, epoch)
            .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, token.transactionId)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, token.generation)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, token.digest)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, token.bindings)
            .putExtra(BifrostVpnService.EXTRA_ACK_RECEIVER, receiver))
        check(done.await(45, TimeUnit.SECONDS)) { "BF-CONNECTION-TIMEOUT" }
        failure.get()?.let { error(it) }
        check(BifrostServiceOwnershipRegistry.current() == null && BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED) { "BF-CONNECTION-READBACK" }
    }
    internal fun restoredAppPolicy(value: String?): String = value?.takeIf { it == "allow" || it == "exclude" } ?: "allow"
}
