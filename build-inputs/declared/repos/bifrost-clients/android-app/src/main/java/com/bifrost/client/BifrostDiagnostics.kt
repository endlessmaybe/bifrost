package com.bifrost.client

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import java.io.File
import org.json.JSONObject

/** Bounded, local lifecycle evidence. No exception messages or account material. */
internal object BifrostDiagnostics {
    private const val MAX_BYTES = 64 * 1024
    private val lock = Any()

    fun install(context: Context) {
        val app = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            record(app, "uncaught", error)
            if (previous != null) previous.uncaughtException(thread, error)
            else {
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(10)
            }
        }
        // Avoid disk and ActivityManager calls on the launch thread.
        Thread({
            record(app, "process-start")
            if (Build.VERSION.SDK_INT >= 30) runCatching {
                app.getSystemService(ActivityManager::class.java)
                    .getHistoricalProcessExitReasons(app.packageName, 0, 4).forEach { exit ->
                        append(app, JSONObject().put("event", "previous-exit").put("time", exit.timestamp)
                            .put("reason", exit.reason).put("status", exit.status)
                            .put("importance", exit.importance).put("pss_kib", exit.pss))
                    }
            }
        }, "bifrost-start-diagnostics").start()
    }

    fun record(context: Context, event: String, error: Throwable? = null) {
        runCatching {
            val record = JSONObject().put("event", event).put("time", System.currentTimeMillis())
                .put("version", BuildConfig.VERSION_NAME).put("pid", android.os.Process.myPid())
            if (error != null) {
                record.put("error_type", error.javaClass.name)
                record.put("code", BifrostUiErrorMapper.code(error))
                record.put("frames", org.json.JSONArray(error.stackTrace.take(12).map {
                    "${it.className}.${it.methodName}:${it.lineNumber}"
                }))
            }
            append(context.applicationContext, record)
        }
    }

    private fun append(context: Context, record: JSONObject) {
        runCatching {
            synchronized(lock) {
                val directory = File(context.noBackupFilesDir, "diagnostics").apply { mkdirs() }
                val file = File(directory, "lifecycle.jsonl")
                val line = record.toString() + "\n"
                if (file.length() + line.toByteArray(Charsets.UTF_8).size > MAX_BYTES) file.writeText("")
                file.appendText(line, Charsets.UTF_8)
            }
        }
    }

    fun report(context: Context): String = runCatching {
        val events = synchronized(lock) {
            val file = File(context.noBackupFilesDir, "diagnostics/lifecycle.jsonl")
            if (file.isFile && file.length() <= MAX_BYTES) file.readText(Charsets.UTF_8) else ""
        }
        "Bifrost ${BuildConfig.VERSION_NAME} / Android ${Build.VERSION.SDK_INT}\n" +
            "运行诊断（不包含账号凭据、节点配置或浏览内容）\n" + events
    }.getOrDefault("Bifrost ${BuildConfig.VERSION_NAME}：暂时无法读取运行诊断")
}
