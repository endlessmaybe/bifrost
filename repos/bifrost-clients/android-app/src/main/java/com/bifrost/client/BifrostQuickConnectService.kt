package com.bifrost.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.bifrost.client.ui.model.BifrostUiText
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Owns preparation after a user taps the tile, without opening the app. */
class BifrostQuickConnectService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var latestStartId = 0
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Bifrost", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 2216, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL).setContentTitle("Bifrost")
            .setSmallIcon(R.drawable.bifrost_direction_a_monochrome).setOnlyAlertOnce(true).setContentIntent(open)
        startForeground(1005, notification.setContentText(BifrostUiText.notificationPreparing).build())
        if (!active.compareAndSet(false, true)) return START_NOT_STICKY
        manager.cancel(1006)
        val recovery = intent?.getStringExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH)
        BifrostQuickTileService.refresh(this)
        worker.execute {
            try {
                var epoch = recovery
                if (BifrostFeaturePreferences.rootMode(this)) {
                    epoch = epoch ?: BifrostRootConnectionIntent.current(this)
                    if (epoch != null) {
                        val state = runCatching { BifrostRootIpc.call(this, "status", epoch) }
                        val status = state.getOrElse { error ->
                            // A freshly spawned daemon can carry no session or
                            // an obsolete epoch after process death. Proceed to
                            // configure: that operation owns the bounded
                            // stop/rebind recovery path in BifrostRootIpc.
                            if (error is IllegalStateException &&
                                error.message == "BF-CONNECTION-RELEASED" &&
                                BifrostRootConnectionIntent.matches(this, epoch)) null
                            else throw error
                        }
                        if (status?.getBoolean("ready") == true && status.getString("owner") != null) {
                            startForegroundService(Intent(this, BifrostVpnService::class.java)
                                .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_ROOT_ATTACH)
                                .putExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH, epoch))
                            return@execute
                        }
                        // An interrupted, uncommitted transaction owns no live
                        // selection to resume. Release it before compiling anew.
                        if (status != null && BifrostServiceOwnershipRegistry.current() == null)
                            BifrostRootIpc.call(this, "close", epoch)
                    }
                    if (epoch == null) epoch = BifrostRootConnectionIntent.begin(this)
                }
                var result: Result<Unit>
                do {
                    if (epoch != null && !BifrostRootConnectionIntent.matches(this, epoch)) break
                    if (epoch != null && !recoveryBudget.claim(epoch, android.os.SystemClock.elapsedRealtime())) break
                    result = runCatching { BifrostBackgroundConnection.connect(this, epoch) }
                    if (result.isSuccess) {
                        manager.cancel(1006)
                        BifrostDiagnostics.record(this, "quick-connect-ready")
                        break
                    }
                    val error = result.exceptionOrNull()!!
                    BifrostDiagnostics.record(this, "quick-connect-failed", error)
                    manager.notify(1006, notification.setAutoCancel(true)
                        .setStyle(Notification.BigTextStyle().bigText(BifrostUiErrorMapper.message("VPN", error)))
                        .setContentText(BifrostUiErrorMapper.message("VPN", error)).build())
                    if (epoch == null) break
                    if (!BifrostRootConnectionIntent.retryable(error)) {
                        BifrostRootConnectionIntent.stopExact(this, epoch)
                        break
                    }
                    repeat(100) {
                        if (!BifrostRootConnectionIntent.matches(this, epoch)) return@repeat
                        Thread.sleep(100)
                    }
                } while (epoch != null && BifrostRootConnectionIntent.matches(this, epoch))
            } catch (error: Exception) {
                BifrostDiagnostics.record(this, "quick-connect-restore-failed", error)
                manager.notify(1006, notification.setAutoCancel(true)
                    .setContentText(BifrostUiErrorMapper.message("VPN", error)).build())
            } finally {
                active.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                BifrostQuickTileService.refresh(this)
                stopSelfResult(latestStartId)
            }
        }
        return START_NOT_STICKY
    }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
    companion object {
        private const val CHANNEL = "bifrost-quick-connect"
        private val active = AtomicBoolean(false)
        private val recoveryBudget = BifrostRootRecoveryBudget()
        val preparing: Boolean get() = active.get()
    }
}

internal class BifrostRootRecoveryBudget {
    private var epoch = ""
    private var started = 0L
    private var attempts = 0
    @Synchronized fun claim(request: String, now: Long): Boolean {
        if (request != epoch || now - started !in 0 until 600_000L) {
            epoch = request; started = now; attempts = 0
        }
        if (attempts >= 3) return false
        attempts++
        return true
    }
}
