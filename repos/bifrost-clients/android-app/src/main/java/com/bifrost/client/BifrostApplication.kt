package com.bifrost.client

import android.app.Application
import android.os.Build
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.io.File

/**
 * Owns the shared candidate coordinator. Native networking starts only when
 * the VPN worker prepares a core, after ordinary control requests can run.
 */
class BifrostApplication : Application() {
    internal lateinit var candidateProbeCoordinator: BifrostCandidateProbeCoordinator
        private set

    private var libboxInitialized = false

    override fun onCreate() {
        super.onCreate()
        BifrostDiagnostics.install(this)
        File(noBackupFilesDir, "bifrost-config").apply { mkdirs() }
        candidateProbeCoordinator = BifrostCandidateProbeCoordinator(this)
        runCatching { BifrostAutomaticUpdate.schedule(this) }
            .onFailure { BifrostDiagnostics.record(this, "automatic-update-schedule", it) }
        BifrostRootConnectionIntent.current(this)?.let { epoch ->
            runCatching { startForegroundService(android.content.Intent(this, BifrostRootControlService::class.java)
                .putExtra("epoch", epoch)) }
                .onFailure { BifrostDiagnostics.record(this, "root-control-start-deferred", it) }
        }
    }

    @Synchronized
    internal fun ensureLibboxInitialized() {
        if (libboxInitialized) return
        // Runtime state must never live in external storage.  The no-backup
        // root is app-private and is excluded from cloud/device migration.
        val working = File(noBackupFilesDir, "bifrost-working").apply { mkdirs() }
        Libbox.setup(SetupOptions().apply {
            basePath = filesDir.absolutePath
            workingPath = working.absolutePath
            tempPath = cacheDir.absolutePath
            fixAndroidStack = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
            commandServerListenPort = 0
            commandServerSecret = ""
            logMaxLines = 2000
            debug = BuildConfig.DEBUG
        })
        libboxInitialized = true
    }
}
