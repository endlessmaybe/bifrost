package com.bifrost.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.os.SystemClock
import com.bifrost.client.ui.model.BifrostUiText
import java.util.concurrent.Executors
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

internal object BifrostAutomaticUpdate {
    const val JOB_ID = 221300
    const val RETRY_JOB_ID = 221301
    const val EXTRA_UPDATE = "bifrost.open.update"
    val operationGate = Any()
    fun schedule(context: Context) {
        if (BuildConfig.BIFROST_TEST_VARIANT) return
        val scheduler = context.getSystemService(JobScheduler::class.java)
        if (!BifrostFeaturePreferences.automaticUpdates(context)) {
            scheduler.cancel(JOB_ID); scheduler.cancel(RETRY_JOB_ID); return
        }
        if (scheduler.getPendingJob(JOB_ID) != null) return
        scheduler.schedule(JobInfo.Builder(JOB_ID, ComponentName(context, BifrostUpdateJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
            .setRequiresBatteryNotLow(true).setRequiresStorageNotLow(true)
            .setPeriodic(6 * 3_600_000L, 3_600_000L).setPersisted(true).build())
    }
    fun retryWhenIdle(context: Context) {
        if (!BifrostFeaturePreferences.automaticUpdates(context)) return
        context.getSystemService(JobScheduler::class.java).schedule(
            JobInfo.Builder(RETRY_JOB_ID, ComponentName(context, BifrostUpdateJobService::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                .setRequiresBatteryNotLow(true).setRequiresStorageNotLow(true)
                .setMinimumLatency(15 * 60_000L).build())
    }
    fun idle(context: Context): Boolean {
        if (BifrostFeaturePreferences.changing) return false
        if (BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED &&
            BifrostApplicationPolicySnapshotRegistry.count() > 0) return false
        val now = SystemClock.elapsedRealtime()
        return BifrostAutomaticUpdatePolicy.idle(
            context.getSystemService(PowerManager::class.java).isInteractive, BifrostRuntimeStatus.current.state,
            BifrostServiceOwnershipRegistry.current() != null, BifrostUpdateInstallGate.pending,
            now, BifrostTrafficTelemetry.notificationTraffic.latest, BifrostTrafficTelemetry.runningMillis(now),
            maxOf(BifrostTrafficTelemetry.lastReceiveAt, BifrostTrafficTelemetry.lastSendAt))
    }
    fun showUpdateRequired(context: Context, permission: Boolean = false) {
        val activity = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(EXTRA_UPDATE, true)
        val pending = PendingIntent.getActivity(context, 2215, activity,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("bifrost-update",
            BifrostUiText.updateAction, NotificationManager.IMPORTANCE_DEFAULT))
        manager.notify(1004, Notification.Builder(context, "bifrost-update")
            .setContentTitle("Bifrost").setContentText(if (permission)
                BifrostUiText.updatePermissionRequired else BifrostUiText.updateConfirmInstall)
            .setSmallIcon(R.drawable.bifrost_direction_a_monochrome).setOnlyAlertOnce(true)
            .setAutoCancel(true).setContentIntent(pending).build())
    }
}

class BifrostUpdateJobService : JobService() {
    private val worker = Executors.newSingleThreadExecutor()
    private val jobs = ConcurrentHashMap<Int, AtomicBoolean>()
    override fun onStartJob(params: JobParameters): Boolean {
        val cancelled = AtomicBoolean(false)
        jobs.put(params.jobId, cancelled)?.set(true)
        worker.execute {
            try {
                if (!cancelled.get() && BifrostFeaturePreferences.automaticUpdates(this) && BifrostAutomaticUpdate.idle(this)) {
                    val result = BifrostUpdateManager(this).checkAndStage(automatic = true,
                        permitted = { !cancelled.get() && BifrostFeaturePreferences.automaticUpdates(this) &&
                            BifrostAutomaticUpdate.idle(this) })
                    if (result.state == "deferred" && !cancelled.get()) BifrostAutomaticUpdate.retryWhenIdle(this)
                } else if (!cancelled.get()) BifrostAutomaticUpdate.retryWhenIdle(this)
            } catch (error: Throwable) {
                BifrostDiagnostics.record(this, "automatic-update", error)
            } finally {
                jobs.remove(params.jobId, cancelled)
                jobFinished(params, false)
            }
        }
        return true
    }
    override fun onStopJob(params: JobParameters): Boolean { jobs.remove(params.jobId)?.set(true); return true }
    override fun onDestroy() { jobs.values.forEach { it.set(true) }; jobs.clear(); worker.shutdown(); super.onDestroy() }
}
