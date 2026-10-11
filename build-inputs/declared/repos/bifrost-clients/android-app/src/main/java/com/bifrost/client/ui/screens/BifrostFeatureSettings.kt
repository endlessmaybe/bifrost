package com.bifrost.client.ui.screens

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.bifrost.client.BifrostFeaturePreferences
import com.bifrost.client.BifrostAutomaticUpdate
import com.bifrost.client.BifrostQuickTileService
import com.bifrost.client.BifrostRootTunnel
import com.bifrost.client.BifrostUiErrorMapper
import com.bifrost.client.BifrostDiagnostics
import com.bifrost.client.ui.model.BifrostUiText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun BifrostFeatureSettings() {
    val context = LocalContext.current
    var message by remember { mutableStateOf("") }
    var autoUpdate by remember { mutableStateOf(BifrostFeaturePreferences.automaticUpdates(context)) }
    var rootMode by remember { mutableStateOf(BifrostFeaturePreferences.rootMode(context)) }
    var rootChecking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    OutlinedButton(onClick = {
        var activity: Context = context
        while (activity is ContextWrapper && activity !is Activity) activity = activity.baseContext
        (activity as? Activity)?.let { BifrostQuickTileService.requestAdd(it) { result -> message = result } }
    }, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.quickTileAdd) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(BifrostUiText.automaticUpdates, modifier = Modifier.weight(1f))
        Switch(checked = autoUpdate, onCheckedChange = { enabled ->
            runCatching { BifrostFeaturePreferences.setAutomaticUpdates(context, enabled) }
                .onSuccess { autoUpdate = enabled; BifrostAutomaticUpdate.schedule(context) }
                .onFailure { message = BifrostUiText.storageUnavailable }
        })
    }
    Text(BifrostUiText.automaticUpdatesHint, style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(BifrostUiText.rootMode, modifier = Modifier.weight(1f))
        Switch(checked = rootMode, enabled = !rootChecking, onCheckedChange = { enabled ->
            rootChecking = true
            scope.launch {
                val result = withContext(Dispatchers.IO) { runCatching {
                    BifrostFeaturePreferences.setRootMode(context, enabled)
                } }
                rootChecking = false
                result.onSuccess { rootMode = enabled; message = "" }
                    .onFailure {
                        BifrostDiagnostics.record(context, "root-mode-change-failed", it)
                        message = BifrostUiErrorMapper.message(BifrostUiText.rootMode, it)
                    }
            }
        })
    }
    Text(BifrostUiText.rootModeHint, style = MaterialTheme.typography.bodySmall)
    if (rootMode) {
        Text(BifrostUiText.rootBackgroundHint, style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = {
            val power = context.getSystemService(android.os.PowerManager::class.java)
            val intent = if (power.isIgnoringBatteryOptimizations(context.packageName))
                android.content.Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            else android.content.Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                android.net.Uri.parse("package:" + context.packageName))
            runCatching { context.startActivity(intent) }
                .onFailure { message = BifrostUiText.rootBackgroundHint }
        }, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.rootBackgroundAllow) }
    }
    if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
}
