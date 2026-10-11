package com.bifrost.client

import android.app.Activity
import android.app.PendingIntent
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.bifrost.client.ui.model.BifrostUiText

/** Uses the ordinary connection transaction; repeated taps never request disconnect. */
class BifrostQuickTileService : TileService() {
    private val main = android.os.Handler(android.os.Looper.getMainLooper())
    private var listener: AutoCloseable? = null
    override fun onStartListening() {
        super.onStartListening()
        listener?.close()
        listener = BifrostRuntimeStatus.addListener { refreshTile() }
        refreshTile()
    }
    override fun onStopListening() { listener?.close(); listener = null; super.onStopListening() }
    override fun onDestroy() { listener?.close(); listener = null; super.onDestroy() }
    private fun refreshTile() {
        if (android.os.Looper.myLooper() != android.os.Looper.getMainLooper()) {
            main.post { refreshTile() }; return
        }
        val tile = qsTile ?: return
        val state = BifrostRuntimeStatus.current.state
        val preparing = BifrostQuickConnectService.preparing
        tile.label = "Bifrost"
        tile.state = if (state == BifrostLeakState.HEALTHY) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = if (preparing) BifrostUiText.notificationPreparing else when (state) {
            BifrostLeakState.HEALTHY -> BifrostUiText.vpnConnectedNotification
            BifrostLeakState.STARTING -> BifrostUiText.notificationPreparing
            BifrostLeakState.BLOCKING -> BifrostUiText.coreBlocked
            else -> BifrostUiText.quickConnectLabel
        }
        tile.updateTile()
    }
    // Android 13 and earlier have only the Intent overload. The guarded
    // Android 14+ branch always uses PendingIntent as required by target 35.
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
    override fun onClick() {
        super.onClick()
        unlockAndRun {
            val state = BifrostRuntimeStatus.current.state
            val live = BifrostServiceOwnershipRegistry.current()
            val phase = live?.phase
            val retainedFailedSnapshot = live != null &&
                phase in setOf(BifrostServiceOwnershipPhase.BLOCKED_FAILED, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED) &&
                BifrostApplicationPolicySnapshotRegistry.count() == 1 &&
                BifrostApplicationPolicySnapshotRegistry.lookup(live.token.transactionId) != null
            val idle = !BifrostFeaturePreferences.changing &&
                BifrostQuickConnectionPolicy.canStart(state, phase) && !BifrostUpdateInstallGate.pending &&
                (BifrostApplicationPolicySnapshotRegistry.count() == 0 || retainedFailedSnapshot) && !BifrostQuickConnectService.preparing
            if (!idle) { refreshTile(); return@unlockAndRun }
            if (BifrostFeaturePreferences.rootMode(this) || VpnService.prepare(this) == null) {
                // Dispatch immediately while the user-initiated tile click
                // grants foreground-service startup. The service loads the
                // saved selection off the UI thread and never opens an Activity.
                runCatching { startForegroundService(Intent(this, BifrostQuickConnectService::class.java)) }
                    .onFailure { BifrostDiagnostics.record(this, "quick-connect-dispatch", it) }
                refreshTile()
                return@unlockAndRun
            }
            // Only the first system VPN consent requires an Activity.
            val intent = Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .putExtra(EXTRA_CONNECT, true)
            val pending = PendingIntent.getActivity(this, 2213, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(pending)
            else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        }
    }
    companion object {
        const val EXTRA_CONNECT = "bifrost.quick.connect"
        fun requestAdd(activity: Activity, completed: (String) -> Unit) {
            if (Build.VERSION.SDK_INT >= 33) {
                activity.getSystemService(StatusBarManager::class.java).requestAddTileService(
                    ComponentName(activity, BifrostQuickTileService::class.java), "Bifrost",
                    Icon.createWithResource(activity, R.drawable.bifrost_direction_a_monochrome),
                    activity.mainExecutor,
                ) { result ->
                    completed(if (result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED ||
                        result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED)
                        BifrostUiText.quickTileAdded else BifrostUiText.quickTileManual)
                }
            } else completed(BifrostUiText.quickTileManual)
        }
        fun refresh(context: Context) {
            runCatching { requestListeningState(context, ComponentName(context, BifrostQuickTileService::class.java)) }
        }
    }
}

internal object BifrostQuickConnectionPolicy {
    fun canStart(state: BifrostLeakState, phase: BifrostServiceOwnershipPhase?): Boolean =
        (state == BifrostLeakState.STOPPED && phase == null) ||
            (state in setOf(BifrostLeakState.BLOCKING, BifrostLeakState.UNPROTECTED, BifrostLeakState.ERROR) &&
                phase in setOf(null, BifrostServiceOwnershipPhase.BLOCKED_FAILED, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED))
}
