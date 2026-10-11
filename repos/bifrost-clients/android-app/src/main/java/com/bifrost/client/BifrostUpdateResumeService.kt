package com.bifrost.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.IBinder
import com.bifrost.client.ui.model.BifrostUiText
import org.json.JSONObject
import java.util.concurrent.Executors

internal object BifrostUpdateResume {
    private val gate = Any()
    fun record(context: Context, connect: Boolean, automatic: Boolean) = synchronized(gate) {
        BifrostSecureStore.put(context, "update_resume_intent", JSONObject()
            .put("version", BuildConfig.VERSION_CODE).put("time", System.currentTimeMillis())
            .put("connect", connect).put("automatic", automatic).toString())
    }
    fun start(context: Context, failure: Boolean = false, retain: Boolean = false) {
        if (runCatching { BifrostSecureStore.get(context, "update_resume_intent", "").isBlank() }.getOrDefault(true)) return
        runCatching { context.startForegroundService(Intent(context, BifrostUpdateResumeService::class.java)
            .putExtra("installation_failed", failure).putExtra("retain_intent", retain)) }
            .onFailure { BifrostDiagnostics.record(context, "update-resume-dispatch", it) }
    }
    fun resume(context: Context, failed: Boolean, retain: Boolean = false) =
        synchronized(BifrostAutomaticUpdate.operationGate) { synchronized(gate) resume@{
        val raw = BifrostSecureStore.get(context, "update_resume_intent", "")
        if (raw.isBlank()) return@resume
        val record = JSONObject(raw)
        if (!failed && record.optInt("version") >= BuildConfig.VERSION_CODE) return@resume
        val age = System.currentTimeMillis() - record.optLong("time")
        if (!record.optBoolean("connect") || age !in 0..24 * 3_600_000L) {
            BifrostSecureStore.put(context, "update_resume_intent", "")
            return@resume
        }
        if (BifrostUpdateInstallGate.pending) return@resume
        BifrostBackgroundConnection.connect(context)
        if (!retain && BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY)
            BifrostSecureStore.put(context, "update_resume_intent", "")
    } }
}

class BifrostUpdateResumeService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("bifrost-update", BifrostUiText.updateAction, NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 2214, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        startForeground(1003, Notification.Builder(this, "bifrost-update").setContentTitle("Bifrost")
            .setContentText(BifrostUiText.updateRestoring).setSmallIcon(R.drawable.bifrost_direction_a_monochrome)
            .setOnlyAlertOnce(true).setContentIntent(open).build())
        worker.execute {
            runCatching { BifrostUpdateResume.resume(this, intent?.getBooleanExtra("installation_failed", false) == true,
                intent?.getBooleanExtra("retain_intent", false) == true) }
                .onFailure { BifrostDiagnostics.record(this, "update-resume-failed", it) }
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
}

class BifrostPackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        runCatching {
            if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
                BifrostUpdateResume.start(context)
                BifrostAutomaticUpdate.schedule(context)
            } else if (intent.action == Intent.ACTION_BOOT_COMPLETED) BifrostAutomaticUpdate.schedule(context)
        }.onFailure { BifrostDiagnostics.record(context, "update-receiver-failed", it) }
    }
}
