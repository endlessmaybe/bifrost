package com.bifrost.client

import android.content.Context
import android.os.Process
import android.system.Os
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Shared by ordinary VPN and Root; contains only timestamps and byte counts. */
internal object BifrostProbeBudgetStore {
    fun open(context: Context): BifrostProbeBudget {
        val directory = File(context.noBackupFilesDir, "probe-budget")
        val file = File(directory, "ledger.json")
        fun secure(target: File, mode: Int) {
            Os.chmod(target.absolutePath, mode)
            if (Process.myUid() == 0) Os.chown(target.absolutePath, context.applicationInfo.uid, context.applicationInfo.uid)
        }
        var unreadableAt: Long? = null
        return BifrostProbeBudget(read = {
            try {
                if (!file.exists()) emptyList() else {
                    check(file.length() <= 128 * 1024)
                    val data = JSONArray(file.readText())
                    (0 until data.length()).map { index ->
                        val row = data.getJSONObject(index)
                        val at = row.getLong("at"); val bytes = row.getLong("bytes")
                        check(at > 0 && bytes > 0 && bytes <= BifrostProbeBudget.WIFI_BYTES)
                        BifrostProbeBudget.Entry(at, bytes, row.getBoolean("metered"))
                    }
                }
            } catch (_: Exception) {
                // A damaged ledger must not grant unlimited automatic traffic.
                listOf(BifrostProbeBudget.Entry(unreadableAt ?: System.currentTimeMillis().also { unreadableAt = it }, BifrostProbeBudget.WIFI_BYTES, true))
            }
        }, write = { entries ->
            check(directory.isDirectory || directory.mkdirs())
            secure(directory, 0x1c0)
            val pending = File(directory, "ledger.new")
            val rows = JSONArray()
            entries.forEach { rows.put(JSONObject().put("at", it.at).put("bytes", it.bytes).put("metered", it.metered)) }
            pending.writeText(rows.toString()); secure(pending, 0x180)
            Files.move(pending.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        })
    }
}
