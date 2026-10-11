package com.bifrost.client

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

internal object BifrostNodeUpdateNotifications {
    internal fun shouldNotify(previous: Long, current: Long, lastNotified: Long, contentChanged: Boolean = true): Boolean =
        contentChanged && previous > 0 && current > previous && current > lastNotified

    internal fun fingerprint(content: String?): String? {
        if (content.isNullOrBlank()) return null
        val config = JSONObject(content)
        val nodes = JSONObject()
        for (key in listOf("sources", "countries", "routing", "core_policy")) {
            if (!config.has(key) || config.isNull(key)) return null
            nodes.put(key, config.get(key))
        }
        return MessageDigest.getInstance("SHA-256").digest(canonical(nodes).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    private fun canonical(value: Any?): String = when (value) {
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") {
            BifrostJsonString.quote(it) + ":" + canonical(value.get(it))
        }
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
        is String -> BifrostJsonString.quote(value)
        null, JSONObject.NULL -> "null"
        else -> value.toString()
    }

    @Synchronized fun updated(context: Context, previous: Long, current: Long, contentChanged: Boolean) {
        val preferences = context.getSharedPreferences("node-update-notifications", Context.MODE_PRIVATE)
        if (!shouldNotify(previous, current, preferences.getLong("last_version", 0), contentChanged)) return
        val manager = context.getSystemService(NotificationManager::class.java)
        if (!manager.areNotificationsEnabled()) return
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        manager.createNotificationChannel(NotificationChannel("bifrost-nodes", "节点更新", NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(context, 1002, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        manager.notify(1002, Notification.Builder(context, "bifrost-nodes")
            .setSmallIcon(R.drawable.bifrost_direction_a_monochrome)
            .setContentTitle("节点已更新")
            .setContentText("新节点已同步，下次连接即可使用，无需更新软件")
            .setContentIntent(open).setAutoCancel(true).build())
        preferences.edit().putLong("last_version", current).apply()
    }
}
