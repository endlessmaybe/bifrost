package com.bifrost.client.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import com.bifrost.client.ui.components.BifrostGlassCard
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bifrost.client.BuildConfig
import com.bifrost.client.ui.model.BifrostUiText

@Composable
internal fun BifrostSettingsScreen(
    enrolled: Boolean,
    accountStateReady: Boolean,
    accountStateMessage: String,
    onRetryAccount: () -> Unit,
    onShareDiagnostics: () -> Unit,
    busy: Boolean,
    feedback: String,
    settingsBusy: Boolean,
    settingsFeedback: String,
    publicId: String,
    credential: String,
    onCredential: (String) -> Unit,
    recovery: String,
    onRecovery: (String) -> Unit,
    pairing: String,
    onPairing: (String) -> Unit,
    hasSavedRecovery: Boolean,
    recoveryCode: String,
    showRecovery: Boolean,
    onRevealRecovery: () -> Unit,
    onCopyRecovery: () -> Unit,
    onHideRecovery: () -> Unit,
    pairingCode: String,
    showPairing: Boolean,
    onRevealPairing: () -> Unit,
    onCopyPairing: () -> Unit,
    onActivate: () -> Unit,
    onRecover: () -> Unit,
    onRedeemPairing: () -> Unit,
    onCreatePairing: () -> Unit,
    onRotateRecovery: () -> Unit,
    onLogout: () -> Unit,
    onRefresh: () -> Unit,
    onCheckUpdate: () -> Unit,
    onOpenVpnSettings: () -> Unit,
    onOpenNotificationSettings: () -> Unit,
    connectionSummary: String,
    connectionSettingsContent: @Composable () -> Unit,
) {
    var activationTab by remember { mutableIntStateOf(0) }
    var confirmAction by remember { mutableStateOf("") }
    var licenseOpen by remember { mutableStateOf(false) }
    var settingsPage by remember { mutableStateOf("root") }
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        if (settingsPage == "root") {
            Text(BifrostUiText.settings, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(horizontal = 18.dp))
            Text(
                BifrostUiText.settingsOverview,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 18.dp),
            )
            SettingsMenuItem(BifrostUiText.connectionAndRouting, connectionSummary.ifBlank { BifrostUiText.connectionSettingsSummary }) {
                settingsPage = "connection"
            }
            val accountSummary = when {
                !accountStateReady -> accountStateMessage
                enrolled -> BifrostUiText.activated + " · " + BifrostUiText.accountSettingsSummary
                else -> BifrostUiText.needsActivation + " · " + BifrostUiText.accountSettingsSummary
            }
            SettingsMenuItem(BifrostUiText.deviceAndAccount, accountSummary) { settingsPage = "account" }
            SettingsMenuItem(BifrostUiText.systemAndPermissions, BifrostUiText.systemSettingsSummary) { settingsPage = "system" }
            SettingsMenuItem(BifrostUiText.updateAndAbout, BifrostUiText.updateSettingsSummary) { settingsPage = "about" }
            Spacer(Modifier.height(10.dp))
            Text(
                "Bifrost " + BuildConfig.VERSION_NAME,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
        } else {
            SettingsDetailHeader(
                title = when (settingsPage) {
                    "connection" -> BifrostUiText.connectionAndRouting
                    "account" -> BifrostUiText.deviceAndAccount
                    "system" -> BifrostUiText.systemAndPermissions
                    else -> BifrostUiText.updateAndAbout
                },
                onBack = { settingsPage = "root" },
            )
        }

        if (settingsPage == "connection") connectionSettingsContent()

        if (settingsPage == "account") SettingsSection(BifrostUiText.deviceAndAccount) {
            SettingsValue(BifrostUiText.deviceStatus, if (!accountStateReady) accountStateMessage else if (enrolled) BifrostUiText.activated else BifrostUiText.needsActivation)
            if (enrolled) SettingsValue(BifrostUiText.anonymousAccountId, publicId)
            if (!accountStateReady) {
                Text(accountStateMessage, style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = onRetryAccount, enabled = !settingsBusy, modifier = Modifier.fillMaxWidth()) {
                    Text("重新读取账号")
                }
            } else if (!enrolled) {
                Text(BifrostUiText.crossPlatformHelp, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TabRow(selectedTabIndex = activationTab, containerColor = MaterialTheme.colorScheme.surface) {
                    listOf(BifrostUiText.activationCode, BifrostUiText.accountRecoveryCode, BifrostUiText.pairingTab).forEachIndexed { index, title ->
                        Tab(selected = activationTab == index, onClick = { activationTab = index }, enabled = !busy, text = { Text(title) })
                    }
                }
                val value = when (activationTab) { 1 -> recovery; 2 -> pairing; else -> credential }
                val normalizedValue = value.trim()
                val mismatchMessage = when {
                    activationTab == 1 && normalizedValue.startsWith("PAIR-", ignoreCase = true) -> BifrostUiText.pairingCodeInRecoveryField
                    activationTab == 2 && normalizedValue.isNotBlank() && !normalizedValue.startsWith("PAIR-", ignoreCase = true) -> BifrostUiText.recoveryCodeInPairingField
                    else -> ""
                }
                val inputHelp = when (activationTab) {
                    1 -> BifrostUiText.recoveryActivationHelp
                    2 -> BifrostUiText.pairingActivationHelp
                    else -> BifrostUiText.invitationActivationHelp
                }
                OutlinedTextField(
                    value = value,
                    onValueChange = { next -> if (next.length <= 256) when (activationTab) { 1 -> onRecovery(next); 2 -> onPairing(next); else -> onCredential(next) } },
                    label = { Text(when (activationTab) { 1 -> BifrostUiText.accountRecoveryCode; 2 -> BifrostUiText.otherDevicePairing; else -> BifrostUiText.activationCode }) },
                    supportingText = { Text(mismatchMessage.ifBlank { inputHelp }) },
                    isError = mismatchMessage.isNotBlank(),
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(onClick = when (activationTab) { 1 -> onRecover; 2 -> onRedeemPairing; else -> onActivate }, enabled = !busy && value.isNotBlank() && mismatchMessage.isBlank(), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Text(if (busy) BifrostUiText.activating else BifrostUiText.activate)
                }
            } else {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Text(BifrostUiText.accountRecoveryCode, style = MaterialTheme.typography.titleMedium)
                Text(BifrostUiText.savedRecoveryHelp, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (hasSavedRecovery || recoveryCode.isNotBlank()) {
                    Text(if (showRecovery && recoveryCode.isNotBlank()) recoveryCode else "••••  ••••  ••••  ••••", fontFamily = FontFamily.Monospace, modifier = Modifier.padding(vertical = 6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = if (showRecovery) onHideRecovery else onRevealRecovery, enabled = !busy, modifier = Modifier.weight(1f)) { Text(if (showRecovery) BifrostUiText.hide else BifrostUiText.showCode) }
                        OutlinedButton(onClick = onCopyRecovery, enabled = !busy, modifier = Modifier.weight(1f)) { Text(BifrostUiText.copy) }
                    }
                } else Text(BifrostUiText.noSavedRecovery, style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { confirmAction = "rotate" }, enabled = !busy) { Text(BifrostUiText.rotateRecovery) }
                OutlinedButton(onClick = onCreatePairing, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.createWindowsPairing) }
                if (pairingCode.isNotBlank()) {
                    Text(if (showPairing) pairingCode else BifrostUiText.pairingHidden, fontFamily = FontFamily.Monospace)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = onRevealPairing) { Text(BifrostUiText.showPairingCode) }
                        TextButton(onClick = onCopyPairing) { Text(BifrostUiText.copy) }
                    }
                }
                TextButton(onClick = { confirmAction = "logout" }, enabled = !busy) { Text(BifrostUiText.logoutDevice, color = MaterialTheme.colorScheme.error) }
            }
            if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            if (feedback.isNotBlank()) Text(feedback, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        }
        if (settingsPage == "system") SettingsSection(BifrostUiText.general) {
            Text(BifrostUiText.androidSystemSettingsHelp, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedButton(onClick = onOpenVpnSettings, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.systemVpnSettings) }
            OutlinedButton(onClick = onOpenNotificationSettings, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.notificationSettings) }
        }
        if (settingsPage == "about") SettingsSection(BifrostUiText.updateAndAbout) {
            BifrostFeatureSettings()
            Button(onClick = onCheckUpdate, enabled = !busy && !settingsBusy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(BifrostUiText.checkProgramUpdate) }
            OutlinedButton(onClick = onRefresh, enabled = enrolled && !busy && !settingsBusy, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.checkConfig) }
            if (settingsBusy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            if (settingsFeedback.isNotBlank()) Text(settingsFeedback, style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            TextButton(onClick = onShareDiagnostics, modifier = Modifier.fillMaxWidth()) { Text("分享运行诊断") }
            TextButton(onClick = { licenseOpen = true }, modifier = Modifier.fillMaxWidth()) { Text(BifrostUiText.licenses) }
        }
    }
    if (confirmAction.isNotEmpty()) {
        val rotating = confirmAction == "rotate"
        AlertDialog(
            onDismissRequest = { confirmAction = "" },
            title = { Text(if (rotating) BifrostUiText.rotateRecovery else BifrostUiText.logoutDevice) },
            text = { Text(if (rotating) BifrostUiText.rotateRecoveryConfirmation else BifrostUiText.logoutConfirmation) },
            confirmButton = { TextButton(onClick = { confirmAction = ""; if (rotating) onRotateRecovery() else onLogout() }) { Text(BifrostUiText.confirm) } },
            dismissButton = { TextButton(onClick = { confirmAction = "" }) { Text(BifrostUiText.cancel) } },
        )
    }
    if (licenseOpen) LicenseDialog { licenseOpen = false }
}

@Composable
private fun SettingsMenuItem(title: String, summary: String, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = .24f)),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .38f)),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 15.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(summary.ifBlank { "—" }, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text("›", color = MaterialTheme.colorScheme.primary, fontSize = 26.sp, fontWeight = FontWeight.Light)
        }
    }
}

@Composable
private fun SettingsDetailHeader(title: String, onBack: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        TextButton(onClick = onBack) { Text(BifrostUiText.settingsBack) }
        Text(title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f).padding(end = 16.dp))
    }
}

@Composable
internal fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    BifrostGlassCard(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            content()
        }
    }
}

@Composable
private fun SettingsValue(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(value.ifBlank { "—" }, modifier = Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.End)
    }
}

@Composable
private fun LicenseDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var index by remember { mutableIntStateOf(0) }
    val documents = remember {
        listOf("COPYING", "THIRD_PARTY_NOTICES.md", "INSTALLATION_INFORMATION.md", "LICENSES.txt").map { asset ->
            asset to runCatching { context.assets.open(asset).bufferedReader().use { it.readText() } }.getOrDefault(BifrostUiText.licenseMissing)
        }
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(documents[index].first) }, text = { Text(documents[index].second, modifier = Modifier.verticalScroll(rememberScrollState())) }, confirmButton = {
        Row {
            TextButton(onClick = { index-- }, enabled = index > 0) { Text(BifrostUiText.licensePrevious) }
            TextButton(onClick = { index++ }, enabled = index < documents.lastIndex) { Text(BifrostUiText.licenseNext) }
            TextButton(onClick = onDismiss) { Text(BifrostUiText.licenseDialogClose) }
        }
    })
}
