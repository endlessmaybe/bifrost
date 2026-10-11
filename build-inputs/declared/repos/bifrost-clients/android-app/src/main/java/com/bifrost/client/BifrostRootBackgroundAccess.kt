package com.bifrost.client

import android.content.Context
import android.os.Build
import android.os.Process
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/** Xiaomi denies even root's app-UID control worker while AUTO_START is
 * ignored. Lease only this app's operation while a user-started Root session
 * exists; preserve its previous mode across daemon replacement and restore it
 * when the connection stops. Never change global power/security services.
 */
internal object BifrostRootBackgroundAccess {
    private val modes = setOf("allow", "ignore", "default", "deny", "foreground")
    private fun record(context: Context) = File(context.noBackupFilesDir, "root-runtime/background-access.json")
    private fun supported() = Process.myUid() == 0 &&
        Build.MANUFACTURER.lowercase(java.util.Locale.ROOT) in setOf("xiaomi", "redmi")

    fun acquire(context: Context) {
        if (!supported()) return
        runCatching {
            val current = mode(context) ?: return
            val record = record(context)
            if (current == "allow" && !record.exists()) return
            if (!record.exists()) {
                check(record.parentFile!!.isDirectory || record.parentFile!!.mkdirs())
                android.system.Os.chmod(record.parent, 0x1c0)
                val saved = JSONObject().put("uid", context.applicationInfo.uid)
                    .put("package", context.packageName).put("mode", current).toString()
                record.outputStream().use { it.write(saved.toByteArray(Charsets.UTF_8)); it.fd.sync() }
                android.system.Os.chmod(record.path, 0x180)
            }
            if (current != "allow") command(context, "set", "allow")
            check(mode(context) == "allow") { "BF-ROOT-BACKGROUND" }
        }.onFailure { BifrostDiagnostics.record(context, "root-background-access-failed", it) }
    }

    fun release(context: Context) {
        if (!supported()) return
        runCatching {
            val record = record(context)
            if (!record.exists()) return
            val saved = JSONObject(record.readText())
            check(saved.getInt("uid") == context.applicationInfo.uid &&
                saved.getString("package") == context.packageName && saved.getString("mode") in modes)
            // A user change made during the connection takes precedence.
            if (mode(context) == "allow") {
                command(context, "set", saved.getString("mode"))
                check(mode(context) == saved.getString("mode")) { "BF-ROOT-BACKGROUND" }
            }
            check(record.delete())
        }.onFailure { BifrostDiagnostics.record(context, "root-background-restore-failed", it) }
    }

    private fun mode(context: Context): String? = Regex("MIUIOP\\(10008\\): (allow|ignore|default|deny|foreground)")
        .find(command(context, "get"))?.groupValues?.get(1)

    private fun command(context: Context, operation: String, mode: String? = null): String {
        val args = listOf("/system/bin/cmd", "appops", operation, "--user",
            (context.applicationInfo.uid / 100000).toString(), context.packageName, "10008") + listOfNotNull(mode)
        val child = ProcessBuilder(args).redirectErrorStream(true).start()
        return try {
            check(child.waitFor(3, TimeUnit.SECONDS) && child.exitValue() == 0) { "BF-ROOT-BACKGROUND" }
            child.inputStream.bufferedReader().use { it.readText().take(2048) }
        } finally {
            child.inputStream.close(); child.outputStream.close(); child.errorStream.close()
            if (child.isAlive) child.destroy()
        }
    }
}
