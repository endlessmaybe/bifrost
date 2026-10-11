package com.bifrost.client.ui.screens

import androidx.compose.foundation.layout.Row
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import com.bifrost.client.BifrostFeaturePreferences
import com.bifrost.client.BifrostUiErrorMapper
import com.bifrost.client.ui.model.BifrostUiText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun BifrostHotspotSettings() {
    val context = LocalContext.current
    var mode by remember { mutableStateOf(BifrostFeaturePreferences.hotspotMode(context)) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    SettingsSection(BifrostUiText.hotspotRouting) {
        for ((value, label) in listOf("smart" to BifrostUiText.hotspotSmart, "direct" to BifrostUiText.hotspotDirect)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = mode == value, enabled = !busy, onClick = {
                    if (mode != value) {
                        busy = true
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                runCatching { BifrostFeaturePreferences.setHotspotMode(context, value) }
                            }
                            busy = false
                            result.onSuccess { mode = value; message = BifrostUiText.hotspotReconnect }
                                .onFailure { message = BifrostUiErrorMapper.message(BifrostUiText.hotspotRouting, it) }
                        }
                    }
                })
                Text(label)
            }
        }
        Text(if (BifrostFeaturePreferences.rootMode(context)) BifrostUiText.hotspotHint else BifrostUiText.hotspotRootRequired,
            style = MaterialTheme.typography.bodySmall)
        if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
    }
}
