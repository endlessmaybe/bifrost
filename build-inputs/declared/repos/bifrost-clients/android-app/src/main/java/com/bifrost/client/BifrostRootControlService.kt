package com.bifrost.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.util.concurrent.Executors

/** Short app-UID worker, so Android Keystore remains in its original UID.
 * A persistent Root data plane never implies persistent account authorization.
 */
class BifrostRootControlService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val channel = "bifrost-root-control"
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(channel, "Bifrost 后台连接", NotificationManager.IMPORTANCE_MIN))
        startForeground(1008, Notification.Builder(this, channel).setContentTitle("Bifrost")
            .setContentText("正在维护后台连接").setSmallIcon(R.drawable.bifrost_direction_a_monochrome)
            .setOnlyAlertOnce(true).build())
        val epoch = intent?.getStringExtra("epoch") ?: BifrostRootConnectionIntent.current(this)
        worker.execute {
            try {
                if (epoch == null) return@execute
                if (!BifrostRootConnectionIntent.matches(this, epoch)) {
                    runCatching { BifrostRootIpc.call(this, "terminate", epoch) }
                    return@execute
                }
                val control = BifrostControlClient(this)
                if (!control.isEnrolled()) {
                    BifrostRootIpc.call(this, "terminate", epoch)
                    BifrostRootConnectionIntent.stopExact(this, epoch)
                    return@execute
                }
                try {
                    val outcome = control.refresh()
                    if (outcome.state != "offline") BifrostRootIpc.call(this, "authorized", epoch)
                } catch (error: BifrostDeviceRevokedException) {
                    BifrostRootIpc.call(this, "terminate", epoch)
                    BifrostRootConnectionIntent.stopExact(this, epoch)
                    return@execute
                }
                if (BifrostRootConnectionIntent.matches(this, epoch)) {
                    val state = BifrostRootIpc.call(this, "status", epoch)
                    if (state.getBoolean("ready") && state.getString("owner") != null) {
                        startForegroundService(Intent(this, BifrostVpnService::class.java)
                            .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_ROOT_ATTACH)
                            .putExtra(BifrostVpnService.EXTRA_RECOVERY_EPOCH, epoch))
                    }
                }
            } catch (error: Exception) {
                BifrostDiagnostics.record(this, "root-control-retry", error)
            } finally { stopSelfResult(startId) }
        }
        return START_NOT_STICKY
    }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
}
