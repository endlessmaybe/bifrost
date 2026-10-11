package com.bifrost.client.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import com.bifrost.client.ui.components.BifrostGlassCard
import com.bifrost.client.ui.components.BifrostBackdrop
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.RadioButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Switch
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bifrost.client.ui.components.BifrostBottomNavigation
import com.bifrost.client.ui.components.BifrostConnectionRing
import com.bifrost.client.ui.components.BifrostMetricRow
import com.bifrost.client.ui.components.BifrostModeControl
import com.bifrost.client.ui.components.BifrostSummaryCard
import com.bifrost.client.ui.model.BifrostChartScale
import com.bifrost.client.ui.model.BifrostPresentationState
import com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy
import com.bifrost.client.ui.model.BifrostAndroidLayoutPlan
import com.bifrost.client.ui.model.BifrostSummaryLayout
import com.bifrost.client.ui.model.BifrostUiEvent
import com.bifrost.client.ui.model.BifrostUiState
import com.bifrost.client.ui.model.BifrostUiText
import com.bifrost.client.ui.model.BifrostUiViewModel
import com.bifrost.client.ui.theme.BifrostTheme
import com.bifrost.client.ui.theme.LocalBifrostDesign
import com.bifrost.client.R
import com.bifrost.client.BifrostCandidateOption
import com.bifrost.client.BifrostCoreOption
import com.bifrost.client.BifrostApplicationPackageOption

@Composable
fun BifrostAHomeScreen(
    initialCore: String,
    initialMode: String,
    initialSource: String,
    initialCountry: String,
    initialFrontSource: String,
    initialCandidateMode: String,
    initialCandidateLabel: String?,
    initialAppPolicy: String,
    initialAppPolicyEnabled: Boolean,
    initialIncludeApps: List<String>,
    initialExcludeApps: List<String>,
    sourceOptions: List<String>,
    countryOptions: List<String>,
    countryDisplayNames: Map<String, String>,
    frontSourceOptions: List<String>,
    candidateOptions: List<BifrostCandidateOption>,
    coreOptions: List<BifrostCoreOption>,
    applicationOptions: List<BifrostApplicationPackageOption>,
    onRefreshApplications: () -> Unit,
    hasCachedConfig: Boolean,
    isEnrolled: Boolean,
    accountStateReady: Boolean,
    accountStateMessage: String,
    onRetryAccount: () -> Unit,
    onShareDiagnostics: () -> Unit,
    accountBusy: Boolean,
    accountStatus: String,
    settingsBusy: Boolean,
    settingsFeedback: String,
    hasSavedRecovery: Boolean,
    presentation: BifrostPresentationState,
    initialBaseUrl: String,
    recoveryCode: String,
    initialPublicId: String,
    pairingCode: String,
    sensitiveGeneration: Int,
    onEnroll: (String, String) -> Unit,
    onRecover: (String, String) -> Unit,
    onRotateRecovery: () -> Unit,
    onCreatePairing: () -> Unit,
    onRedeemPairing: (String, String) -> Unit,
    onRecoverySaved: () -> Unit,
    onRevealRecovery: () -> Boolean,
    onRevealPairing: () -> Boolean,
    onRecoveryExpired: () -> Unit,
    onPairingExpired: () -> Unit,
    onCopyRecovery: () -> Unit,
    onCopyPairing: () -> Unit,
    onAccountPageLeft: () -> Unit,
    onLogout: () -> Unit,
    onRefresh: () -> Unit,
    onSourceChanged: (String) -> Boolean,
    onCandidateModeChanged: (String) -> Boolean,
    onCandidateLabelChanged: (String) -> Boolean,
    onConnect: (String, String, String, String, String, String, Boolean, List<String>, List<String>, String, String?) -> Unit,
    onOpenVpnSettings: () -> Unit,
    onOpenNotificationSettings: () -> Unit,
    onDisconnect: () -> Unit,
    onCheckUpdate: () -> Unit = {},
) {
    val stateViewModel: BifrostUiViewModel = viewModel()
    stateViewModel.initialize(
        BifrostUiState(
            mode = initialMode.takeIf { it in setOf("smart", "global", "smartgate") } ?: "smart",
            core = initialCore,
            source = initialSource,
            country = initialCountry,
            frontSource = initialFrontSource,
            candidateMode = initialCandidateMode,
            candidateLabel = initialCandidateLabel.orEmpty(),
            appPolicy = initialAppPolicy,
            appPolicyEnabled = initialAppPolicyEnabled && initialMode == "smart",
            baseUrl = initialBaseUrl,
            publicId = initialPublicId,
            includeText = initialIncludeApps.joinToString("\n"),
            excludeText = initialExcludeApps.joinToString("\n"),
        ),
    )
    val uiState by stateViewModel.state.collectAsStateWithLifecycle()
    fun dispatch(event: BifrostUiEvent) {
        stateViewModel.dispatch(event)
    }
    val connectionSettingsEditable = presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.IDLE ||
        presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.ERROR
    val activeApplications = if (uiState.appPolicy == "exclude") parseList(uiState.excludeText) else parseList(uiState.includeText)
    val inactiveApplications = if (uiState.appPolicy == "exclude") parseList(uiState.includeText) else parseList(uiState.excludeText)
    val connectSelectionReady = hasCachedConfig &&
        sourceOptions.any { it.equals(uiState.source, true) } &&
        (uiState.mode != "smartgate" || uiState.country != "auto" && countryOptions.any { it.equals(uiState.country, true) }) &&
        frontSourceOptions.any { it.equals(uiState.frontSource, true) } &&
        coreOptions.any { it.code == uiState.core } &&
        (uiState.mode == "smartgate" || uiState.candidateMode != "manual" || candidateOptions.any { it.label == uiState.candidateLabel }) &&
        (!uiState.appPolicyEnabled || (activeApplications.isNotEmpty() && inactiveApplications.isEmpty()))

    LaunchedEffect(sensitiveGeneration) {
        dispatch(BifrostUiEvent.ShowRecovery(false))
        dispatch(BifrostUiEvent.ShowPairing(false))
    }
    LaunchedEffect(recoveryCode) {
        if (recoveryCode.isNotBlank()) {
            kotlinx.coroutines.delay(com.bifrost.client.BifrostSensitiveValueStore.DEFAULT_TTL_MS)
            onRecoveryExpired()
        }
    }
    LaunchedEffect(pairingCode) {
        if (pairingCode.isNotBlank()) {
            kotlinx.coroutines.delay(com.bifrost.client.BifrostSensitiveValueStore.DEFAULT_TTL_MS)
            onPairingExpired()
        }
    }
    // Only the account page can reveal these values. Re-running cleanup on
    // every ordinary tab switch increments the Activity's sensitive epoch
    // and needlessly recomposes the entire screen a second time.
    val accountPageWasVisible = remember { booleanArrayOf(true) }
    LaunchedEffect(uiState.page) {
        if (uiState.page != "settings" && accountPageWasVisible[0]) {
            onAccountPageLeft()
            dispatch(BifrostUiEvent.Invite(""))
            dispatch(BifrostUiEvent.Recovery(""))
            dispatch(BifrostUiEvent.Pairing(""))
        }
        accountPageWasVisible[0] = uiState.page == "settings"
    }
    LaunchedEffect(isEnrolled, initialPublicId) {
        dispatch(BifrostUiEvent.PublicId(initialPublicId))
        if (isEnrolled) {
            dispatch(BifrostUiEvent.Invite(""))
            dispatch(BifrostUiEvent.Recovery(""))
            dispatch(BifrostUiEvent.Pairing(""))
        }
    }
    LaunchedEffect(sourceOptions, countryOptions, frontSourceOptions, candidateOptions) {
        stateViewModel.reconcileAuthorities(sourceOptions, countryOptions, frontSourceOptions, candidateOptions.map { it.label })
    }

    BifrostTheme {
        BoxWithConstraints(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).windowInsetsPadding(WindowInsets.safeDrawing)) {
            val design = LocalBifrostDesign.current
            val useLightMaterial = false
            val layoutPlan = BifrostAndroidLayoutPolicy.forViewport(maxWidth.value, maxHeight.value, LocalDensity.current.fontScale)
            BifrostBackdrop(Modifier.matchParentSize())
            Box(Modifier.matchParentSize().background(androidx.compose.ui.graphics.Brush.verticalGradient(
                listOf(Color(0x7813293C), Color(0xAB0A1A2A)))))
            var quickMenuOpen by remember { mutableStateOf(false) }
            Column(Modifier.fillMaxSize()) {
                Row(Modifier.fillMaxWidth().padding(horizontal = design.pageHorizontal, vertical = 14.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(painterResource(R.drawable.bifrost_teal_rune_symbol), contentDescription = null, modifier = Modifier.size(34.dp), contentScale = ContentScale.Fit)
                        Text("BIFROST", fontFamily = FontFamily.SansSerif, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(start = 8.dp))
                    }
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.semantics { contentDescription = BifrostUiText.connectionStatus(presentation.statusText) }) {
                        Box(
                            Modifier.size(8.dp).clip(CircleShape).background(
                                when {
                                    presentation.isConnected -> MaterialTheme.colorScheme.tertiary
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.PREPARING -> androidx.compose.ui.graphics.Color(0xFF19CDD3)
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.RECONNECTING -> androidx.compose.ui.graphics.Color(0xFF73CFC4)
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.BLOCKED -> androidx.compose.ui.graphics.Color(0xFFD89A42)
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.ERROR -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            ),
                        )
                        Text(presentation.statusText, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.padding(start = 8.dp))
                        Box {
                            TextButton(onClick = { quickMenuOpen = true }) { Text("⋯", fontSize = 22.sp) }
                            DropdownMenu(expanded = quickMenuOpen, onDismissRequest = { quickMenuOpen = false }) {
                                DropdownMenuItem(text = { Text(if (com.bifrost.client.ui.model.BifrostUiActions.canStop(presentation.state)) BifrostUiText.quickDisconnect else BifrostUiText.quickConnect) }, onClick = {
                                    quickMenuOpen = false
                                    if (com.bifrost.client.ui.model.BifrostUiActions.canStop(presentation.state)) onDisconnect() else if (connectSelectionReady)
                                        onConnect(uiState.mode, uiState.core, uiState.source, uiState.country, uiState.frontSource, uiState.appPolicy,
                                            uiState.appPolicyEnabled, parseList(uiState.includeText), parseList(uiState.excludeText), uiState.candidateMode,
                                            uiState.candidateLabel.takeIf { it.isNotBlank() })
                                }, enabled = com.bifrost.client.ui.model.BifrostUiActions.canStop(presentation.state) || connectSelectionReady)
                                DropdownMenuItem(text = { Text(BifrostUiText.quickRoutes) }, onClick = { dispatch(BifrostUiEvent.Page("nodes")); quickMenuOpen = false })
                                DropdownMenuItem(text = { Text(BifrostUiText.settings) }, onClick = { dispatch(BifrostUiEvent.Page("settings")); quickMenuOpen = false })
                                DropdownMenuItem(text = { Text(BifrostUiText.updateCheck) }, onClick = { quickMenuOpen = false; onCheckUpdate() })
                            }
                        }
                    }
                }
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when (uiState.page) {
                        "home" -> HomeContent(
                            mode = uiState.mode,
                            presentation = presentation,
                            hasCachedConfig = hasCachedConfig,
                            source = uiState.source,
                            country = uiState.country,
                            core = uiState.core,
                            candidateMode = uiState.candidateMode,
                            candidateLabel = uiState.candidateLabel,
                            candidateOptions = candidateOptions,
                            coreOptions = coreOptions,
                            layoutPlan = layoutPlan,
                            useLightMaterial = useLightMaterial,
                            canStartConnection = connectSelectionReady,
                            canEditConnectionSettings = connectionSettingsEditable,
                            onConnect = {
                                val teardown = presentation.isConnected ||
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.PREPARING ||
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.RECONNECTING ||
                                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.BLOCKED
                                if (teardown) onDisconnect() else onConnect(uiState.mode, uiState.core, uiState.source, uiState.country, uiState.frontSource, uiState.appPolicy, uiState.appPolicyEnabled, parseList(uiState.includeText), parseList(uiState.excludeText), uiState.candidateMode, uiState.candidateLabel.takeIf { it.isNotBlank() })
                            },
                            onRefresh = onRefresh,
                            onOpenSettings = { dispatch(BifrostUiEvent.Page("settings")) },
                            onOpenRoutes = { dispatch(BifrostUiEvent.Page("nodes")) },
                            onCandidateMode = { value -> if (onCandidateModeChanged(value)) dispatch(BifrostUiEvent.CandidateMode(value)) },
                            onCandidate = { value -> if (onCandidateLabelChanged(value)) dispatch(BifrostUiEvent.CandidateLabel(value)) },
                            onOpenSmartGate = {
                                if (connectionSettingsEditable) {
                                    dispatch(BifrostUiEvent.Mode("smartgate"))
                                    dispatch(BifrostUiEvent.Page("nodes"))
                                }
                            },
                        )
                        "nodes" -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(vertical = design.pageVertical)) { RoutesContent(uiState.mode, uiState.showAdvancedFront, uiState.source, uiState.country, uiState.frontSource, uiState.candidateMode, uiState.candidateLabel, uiState.core, sourceOptions, countryOptions, countryDisplayNames, frontSourceOptions, candidateOptions, coreOptions, { value -> if (onSourceChanged(value)) dispatch(BifrostUiEvent.Source(value)) }, { dispatch(BifrostUiEvent.Country(it)) }, { dispatch(BifrostUiEvent.FrontSource(it)) }, { if (onCandidateModeChanged(it)) dispatch(BifrostUiEvent.CandidateMode(it)) }, { if (onCandidateLabelChanged(it)) dispatch(BifrostUiEvent.CandidateLabel(it)) }, { dispatch(BifrostUiEvent.Core(it)) }, { dispatch(BifrostUiEvent.ShowAdvancedFront(it)) }, onRefresh, editable = connectionSettingsEditable) }
                        "activity" -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(vertical = design.pageVertical)) { ActivityContent(presentation, layoutPlan) }
                        else -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(vertical = design.pageVertical)) {
                            BifrostSettingsScreen(
                                accountStateReady = accountStateReady, accountStateMessage = accountStateMessage,
                                onRetryAccount = onRetryAccount, onShareDiagnostics = onShareDiagnostics,
                                enrolled = isEnrolled, busy = accountBusy || !accountStateReady, feedback = accountStatus, publicId = initialPublicId,
                                settingsBusy = settingsBusy, settingsFeedback = settingsFeedback,
                                credential = uiState.invite, onCredential = { dispatch(BifrostUiEvent.Invite(it)) },
                                recovery = uiState.recovery, onRecovery = { dispatch(BifrostUiEvent.Recovery(it)) },
                                pairing = uiState.pairing, onPairing = { dispatch(BifrostUiEvent.Pairing(it)) },
                                hasSavedRecovery = hasSavedRecovery, recoveryCode = recoveryCode, showRecovery = uiState.showRecovery,
                                onRevealRecovery = { if (onRevealRecovery()) dispatch(BifrostUiEvent.ShowRecovery(true)) },
                                onCopyRecovery = onCopyRecovery, onHideRecovery = { onRecoverySaved(); dispatch(BifrostUiEvent.ShowRecovery(false)) },
                                pairingCode = pairingCode, showPairing = uiState.showPairing,
                                onRevealPairing = { if (onRevealPairing()) dispatch(BifrostUiEvent.ShowPairing(true)) }, onCopyPairing = onCopyPairing,
                                onActivate = { onEnroll(uiState.baseUrl, uiState.invite) }, onRecover = { onRecover(uiState.baseUrl, uiState.recovery) },
                                onRedeemPairing = { onRedeemPairing(uiState.baseUrl, uiState.pairing) }, onCreatePairing = onCreatePairing,
                                onRotateRecovery = onRotateRecovery, onLogout = onLogout, onRefresh = onRefresh, onCheckUpdate = onCheckUpdate,
                                onOpenVpnSettings = onOpenVpnSettings, onOpenNotificationSettings = onOpenNotificationSettings,
                                connectionSummary = when (uiState.mode) {
                                    "global" -> BifrostUiText.global
                                    "smartgate" -> BifrostUiText.smartGate
                                    else -> BifrostUiText.smart
                                } + if (uiState.appPolicyEnabled) " · " + BifrostUiText.applicationRouting else "",
                                connectionSettingsContent = {
                                    BifrostHotspotSettings()
                                    BifrostModeControl(uiState.mode, { dispatch(BifrostUiEvent.Mode(it)) }, enabled = connectionSettingsEditable)
                                    SettingsSection(BifrostUiText.currentStrategy) {
                                        Text(
                                            when (uiState.mode) {
                                                "global" -> BifrostUiText.globalStrategy
                                                "smartgate" -> BifrostUiText.smartGateStrategy
                                                else -> BifrostUiText.smartStrategy
                                            },
                                            style = MaterialTheme.typography.bodyMedium,
                                        )
                                        DetailRow(BifrostUiText.origin, uiState.source)
                                        DetailRow(BifrostUiText.candidateMode, if (uiState.mode == "global") BifrostUiText.candidateManual else BifrostUiText.candidateAuto)
                                        TextButton(onClick = { dispatch(BifrostUiEvent.Page("nodes")) }) { Text(BifrostUiText.quickRoutes) }
                                    }
                                    if (uiState.mode == "smart") {
                                        RoutingContent(
                                            uiState.appPolicyEnabled,
                                            { dispatch(BifrostUiEvent.AppPolicyEnabled(it)) },
                                            uiState.appPolicy,
                                            uiState.includeText,
                                            uiState.excludeText,
                                            { dispatch(BifrostUiEvent.AppPolicy(it)) },
                                            { dispatch(BifrostUiEvent.Include(it)) },
                                            { dispatch(BifrostUiEvent.Exclude(it)) },
                                            applicationOptions,
                                            onRefreshApplications,
                                            editable = connectionSettingsEditable,
                                        )
                                    }
                                },
                            )
                        }
                    }
                }
                BifrostBottomNavigation(uiState.page, { dispatch(BifrostUiEvent.Page(it)) }, Modifier.windowInsetsPadding(WindowInsets.navigationBars))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeContent(mode: String, presentation: BifrostPresentationState, hasCachedConfig: Boolean, source: String, country: String, core: String, candidateMode: String, candidateLabel: String, candidateOptions: List<BifrostCandidateOption>, coreOptions: List<BifrostCoreOption>, layoutPlan: BifrostAndroidLayoutPlan, useLightMaterial: Boolean, canStartConnection: Boolean, canEditConnectionSettings: Boolean, onConnect: () -> Unit, onRefresh: () -> Unit, onOpenSettings: () -> Unit, onOpenRoutes: () -> Unit, onCandidateMode: (String) -> Unit, onCandidate: (String) -> Unit, onOpenSmartGate: () -> Unit) {
    val design = LocalBifrostDesign.current
    val coreLabel = coreOptions.firstOrNull { it.code == core }?.displayName ?: core
    var showDetails by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val routeValue = if (presentation.isConnected) presentation.route else if (candidateMode == "manual") candidateLabel.ifBlank { BifrostUiText.chooseRoute } else BifrostUiText.automaticBest
    val sourceValue = if (presentation.isConnected) presentation.source else source.takeIf { it.isNotBlank() }?.let { "${BifrostUiText.origin} $it" } ?: BifrostUiText.chooseRoute
    val coreValue = if (presentation.isConnected) presentation.core else coreLabel
    val dialSize = layoutPlan.dialSizeDp.coerceIn(design.heroMinDp, design.heroMaxDp).dp
    val panelModifier = Modifier.fillMaxWidth()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(vertical = design.pageVertical),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(design.sectionGap),
    ) {
        BifrostGlassCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(design.cardPadding), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            if (design.brandRailWidth > 0.dp) Box(Modifier.width(design.brandRailWidth).height(48.dp).background(MaterialTheme.colorScheme.primary).padding(end = 8.dp))
            Column(Modifier.weight(1f).padding(start = if (design.brandRailWidth > 0.dp) 10.dp else 0.dp)) {
            Text(presentation.statusText, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.headlineSmall)
            Text(BifrostUiText.overviewTagline, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }

        val canStop = com.bifrost.client.ui.model.BifrostUiActions.canStop(presentation.state)
        Button(onClick = {
            when {
                canStop -> onConnect()
                !hasCachedConfig -> onOpenSettings()
                !canStartConnection -> onOpenRoutes()
                else -> onConnect()
            }
        }, modifier = Modifier.fillMaxWidth().heightIn(min = 54.dp), shape = RoundedCornerShape(design.controlRadius)) {
            Text(when {
                presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.PREPARING ||
                    presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.RECONNECTING -> BifrostUiText.cancelConnection
                presentation.state == com.bifrost.client.ui.model.BifrostConnectionState.BLOCKED -> BifrostUiText.quickUnblock
                canStop -> BifrostUiText.quickDisconnect
                !hasCachedConfig -> BifrostUiText.goActivate
                !canStartConnection -> BifrostUiText.chooseRoute
                else -> BifrostUiText.quickConnect
            }, fontSize = 17.sp)
        }
            }
        }

        BifrostGlassCard(panelModifier) {
            Column(Modifier.fillMaxWidth().padding(design.cardPadding), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text(BifrostUiText.currentConnection, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                    Text(if (presentation.isConnected) BifrostUiText.stable else presentation.statusText, color = if (presentation.isConnected) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column { Text(routeValue, fontSize = 18.sp, fontWeight = FontWeight.SemiBold); Text(sourceValue, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp) }
                    Text(coreValue, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
                Box(Modifier.fillMaxWidth().height(1.dp).background(MaterialTheme.colorScheme.outline.copy(alpha = .45f)))

            }
        }

        BifrostMetricRow(presentation, layoutPlan)

        if (mode == "smartgate") BifrostGlassCard(panelModifier.clickable(enabled = canEditConnectionSettings) { onOpenSmartGate() }) {
            Column(Modifier.fillMaxWidth().padding(design.cardPadding), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(BifrostUiText.smartGate, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                    Text(when { presentation.isConnected -> BifrostUiText.connected; canStartConnection -> BifrostUiText.ready; else -> BifrostUiText.chooseRoute }, color = if (canStartConnection || presentation.isConnected) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
                DetailRow(BifrostUiText.countryRegion, country)
                DetailRow(BifrostUiText.currentPrimaryRoute, routeValue)
                DetailRow(BifrostUiText.failover, BifrostUiText.selectedGatewayOnly)
                DetailRow(BifrostUiText.networkProtection, when {
                    presentation.isProtected -> BifrostUiText.normal
                    presentation.isConnected -> BifrostUiText.systemProtectionUnconfirmed
                    else -> BifrostUiText.waitingConnection
                }, showDivider = false)
            }
        }

        BifrostGlassCard(panelModifier) {
            Column(Modifier.fillMaxWidth().padding(design.cardPadding), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(BifrostUiText.nodes, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                    Text(if (candidateMode == "manual") BifrostUiText.manual else BifrostUiText.automaticBest, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
                val shownCandidates = candidateOptions.take(3)
                if (shownCandidates.isEmpty()) {
                    Text(if (hasCachedConfig) BifrostUiText.waitingCandidates else BifrostUiText.activationRequired, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                } else {
                    shownCandidates.forEach { candidate ->
                        val selected = candidateMode == "manual" && candidate.label == candidateLabel
                        Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(enabled = canEditConnectionSettings) { onCandidateMode("manual"); onCandidate(candidate.label) }.padding(vertical = 7.dp, horizontal = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(candidate.displayName, fontSize = 13.sp)
                            Text(if (selected) BifrostUiText.manual else BifrostUiText.candidate, color = if (selected) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                        }
                    }
                }
                TextButton(onClick = onRefresh, enabled = canEditConnectionSettings, modifier = Modifier.align(Alignment.End)) { Text(BifrostUiText.refreshNodesAction) }
            }
        }

        TextButton(onClick = { showDetails = true }, modifier = Modifier.fillMaxWidth().semantics { contentDescription = BifrostUiText.connectionDetails }) { Text(BifrostUiText.connectionDetails) }

        if (showDetails) {
            ModalBottomSheet(onDismissRequest = { showDetails = false }, sheetState = sheetState) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(BifrostUiText.connectionDetails, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
                    DetailRow(BifrostUiText.origin, sourceValue)
                    DetailRow(BifrostUiText.routeCountry, routeValue)
                    DetailRow(BifrostUiText.core, coreValue)
                    DetailRow(BifrostUiText.connectionQuality, if (presentation.isConnected) presentation.statusText else "—")
                    DetailRow(BifrostUiText.sessionTraffic, presentation.metrics.sessionTraffic, showDivider = false)
                    Spacer(Modifier.height(12.dp))
                }
            }
        }
    }
}

@Composable
private fun NordicMetric(label: String, value: String, accent: androidx.compose.ui.graphics.Color) {
    Column(horizontalAlignment = Alignment.Start) {
        Text(label, color = accent, fontSize = 10.sp)
        Text(value, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

@Composable
private fun BifrostDetailPreview(state: BifrostPresentationState, modifier: Modifier = Modifier) {
    BifrostGlassCard(modifier) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(BifrostUiText.connectionDetails, fontWeight = FontWeight.SemiBold)
            DetailRow(BifrostUiText.origin, if (state.isConnected) state.source else "—")
            DetailRow(BifrostUiText.routeCountry, if (state.isConnected) state.route else "—")
            DetailRow(BifrostUiText.connectionQuality, if (state.isConnected) state.statusText else "—")
            DetailRow(BifrostUiText.sessionTraffic, state.metrics.sessionTraffic, showDivider = false)
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, showDivider: Boolean = true) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
            Text(value.ifBlank { "—" }, modifier = Modifier.weight(1f).padding(start = 12.dp), fontSize = 13.sp, fontWeight = FontWeight.Medium, textAlign = TextAlign.End)
        }
        if (showDivider) {
            // Inset, low-contrast hairline shared with the Obsidian inspector.
            Box(Modifier.fillMaxWidth().padding(horizontal = 8.dp).height(1.dp).background(MaterialTheme.colorScheme.outline.copy(alpha = if (MaterialTheme.colorScheme.background.luminance() < .5f) .08f else .10f)))
        }
    }
}

@Composable
private fun RoutesContent(uiMode: String, showAdvancedFront: Boolean, source: String, country: String, front: String, candidateMode: String, candidateLabel: String, core: String, sources: List<String>, countries: List<String>, countryDisplayNames: Map<String, String>, fronts: List<String>, candidateOptions: List<BifrostCandidateOption>, coreOptions: List<BifrostCoreOption>, onSource: (String) -> Unit, onCountry: (String) -> Unit, onFront: (String) -> Unit, onCandidateMode: (String) -> Unit, onCandidate: (String) -> Unit, onCore: (String) -> Unit, onAdvanced: (Boolean) -> Unit, onRefresh: () -> Unit, editable: Boolean = true) {
    BifrostGlassCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(BifrostUiText.nodes, color = MaterialTheme.colorScheme.primary, fontSize = 23.sp, fontWeight = FontWeight.SemiBold)
            Text(BifrostUiText.routeDescription, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            ChoiceGroup(BifrostUiText.origin, source, sources.map { it to "${BifrostUiText.origin} $it" }, onSource, editable)
            if (uiMode == "smartgate") ChoiceGroup(BifrostUiText.countryRegion, country, countries.filter { it != "auto" }.map { it to countryDisplayNames[it].orEmpty().ifBlank { it } }, onCountry, editable)
            if (uiMode == "smartgate") {
                ChoiceGroup(BifrostUiText.advancedFront, if (showAdvancedFront) "open" else "closed", listOf("closed" to BifrostUiText.advancedClose, "open" to BifrostUiText.advancedOpen), { value -> onAdvanced(value == "open") }, editable)
                if (showAdvancedFront && country != "auto") ChoiceGroup(BifrostUiText.advancedFront, front, fronts.map { it to if (it == "auto") BifrostUiText.frontDefault else "${BifrostUiText.origin} $it" }, onFront, editable)
            }
            ChoiceGroup(BifrostUiText.core, core, coreOptions.map { it.code to it.displayName }, onCore, editable)
            if (uiMode != "smartgate") {
                ChoiceGroup(BifrostUiText.candidateMode, candidateMode, listOf("auto" to BifrostUiText.candidateAuto, "manual" to BifrostUiText.candidateManual), onCandidateMode, editable)
                if (candidateOptions.isNotEmpty()) {
                    Text("${BifrostUiText.candidateLabel} · ${candidateOptions.size}", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                    LazyColumn(Modifier.fillMaxWidth().heightIn(max = 420.dp)) {
                        items(candidateOptions, key = { it.label }) { candidate ->
                            Row(Modifier.fillMaxWidth().clickable(enabled = editable && candidateMode == "manual") {
                                onCandidate(candidate.label)
                            }.padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                                RadioButton(selected = candidate.label == candidateLabel, onClick = null, enabled = editable && candidateMode == "manual")
                                Text(candidate.displayName, modifier = Modifier.weight(1f).padding(start = 8.dp), fontSize = 14.sp)
                            }
                        }
                    }
                }
            }
            TextButton(onClick = onRefresh, enabled = editable, modifier = Modifier.align(Alignment.End)) { Text(BifrostUiText.refreshNodesAction) }
        }
    }
}

@Composable
private fun RoutingContent(enabled: Boolean, onEnabled: (Boolean) -> Unit, policy: String, include: String, exclude: String, onPolicy: (String) -> Unit, onInclude: (String) -> Unit, onExclude: (String) -> Unit, applicationOptions: List<BifrostApplicationPackageOption>, onRefreshApplications: () -> Unit, editable: Boolean = true) {
    BifrostGlassCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(BifrostUiText.routing, color = MaterialTheme.colorScheme.primary, fontSize = 23.sp, fontWeight = FontWeight.SemiBold)
            Text(BifrostUiText.routingDescription, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(BifrostUiText.applicationRouting, fontWeight = FontWeight.SemiBold)
                    Text(BifrostUiText.applicationRoutingDescription, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                }
                Switch(checked = enabled, onCheckedChange = onEnabled, enabled = editable, modifier = Modifier.semantics { contentDescription = BifrostUiText.routingToggle(enabled) })
            }
            ChoiceGroup(BifrostUiText.policyMode, policy, listOf("allow" to BifrostUiText.allowPolicy, "exclude" to BifrostUiText.excludePolicy), onPolicy, enabled && editable)
            val selected = parseList(if (policy == "allow") include else exclude).toSet()
            TextButton(onClick = onRefreshApplications) { Text("刷新应用列表") }
            if (applicationOptions.isEmpty()) {
                Text(BifrostUiText.noInstalledApplications, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            } else {
                Text(BifrostUiText.selectInstalledApplications, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
                Text("已识别 ${applicationOptions.size} 个应用", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                var applicationSearch by remember { mutableStateOf("") }
                OutlinedTextField(applicationSearch, { applicationSearch = it }, label = { Text(BifrostUiText.searchApplications) }, singleLine = true, keyboardOptions = KeyboardOptions(autoCorrectEnabled = false), modifier = Modifier.fillMaxWidth())
                val filteredApplications = remember(applicationOptions, applicationSearch) { applicationOptions.filter { applicationSearch.isBlank() || it.label.contains(applicationSearch, true) || it.packageName.contains(applicationSearch, true) } }
                if (filteredApplications.isEmpty()) Text(BifrostUiText.noMatchingApplications, color = MaterialTheme.colorScheme.onSurfaceVariant)
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 360.dp)) {
                items(filteredApplications, key = { it.packageName }) { option ->
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 52.dp).clickable(enabled = enabled && editable) {
                            val next = if (option.packageName in selected) selected - option.packageName else selected + option.packageName
                            val text = next.sorted().joinToString("\n")
                            if (policy == "allow") onInclude(text) else onExclude(text)
                        },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = option.packageName in selected,
                            onCheckedChange = null,
                            enabled = enabled && editable,
                        )
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(option.label, fontWeight = FontWeight.Medium)
                            Text(option.packageName, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                        }
                    }
                }
                }
            }
            if (policy == "allow") OutlinedTextField(include, onInclude, enabled = enabled && editable, label = { Text(BifrostUiText.includeApplications) }, modifier = Modifier.fillMaxWidth()) else OutlinedTextField(exclude, onExclude, enabled = enabled && editable, label = { Text(BifrostUiText.excludeApplications) }, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun ActivityContent(state: BifrostPresentationState, layoutPlan: BifrostAndroidLayoutPlan, chartOnly: Boolean = false) {
    val design = LocalBifrostDesign.current
    val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = .26f)
    val downColor = MaterialTheme.colorScheme.secondary
    val upColor = Color(0xFF7CA7FF)
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (!chartOnly) Column(Modifier.padding(horizontal = design.pageHorizontal)) {
            Text(BifrostUiText.activity, color = MaterialTheme.colorScheme.primary, fontSize = 23.sp, fontWeight = FontWeight.SemiBold)
            Text(BifrostUiText.activityDescription, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
        }
        if (!chartOnly) BifrostMetricRow(state, layoutPlan, Modifier.fillMaxWidth())
        BifrostGlassCard(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(BifrostUiText.realtimeTraffic, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                    Text(BifrostUiText.downloadUploadLegend, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
                }
                val download = state.metrics.samples
                val upload = state.metrics.uploadSamples
                val maximum = BifrostChartScale.maximum(download + upload)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("下载 ${state.metrics.download}", color = downColor, fontSize = 12.sp)
                    Text("上传 ${state.metrics.upload}", color = upColor, fontSize = 12.sp)
                }
                Row(Modifier.fillMaxWidth().height(180.dp)) {
                    Column(Modifier.width(72.dp).fillMaxHeight(), verticalArrangement = Arrangement.SpaceBetween) {
                        listOf(1f, .75f, .5f, .25f, 0f).forEach { fraction ->
                            Text(BifrostChartScale.rate(maximum * fraction), color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontSize = 10.sp, maxLines = 1)
                        }
                    }
                    Canvas(Modifier.weight(1f).fillMaxHeight().padding(vertical = 7.dp)) {
                        repeat(5) { row ->
                            val y = size.height * row / 4f
                            drawLine(gridColor, androidx.compose.ui.geometry.Offset(0f, y), androidx.compose.ui.geometry.Offset(size.width, y), strokeWidth = 1f)
                        }
                        fun path(series: List<Float>): Path = Path().apply {
                            series.forEachIndexed { index, sample ->
                                val slots = maxOf(60, series.size)
                                val x = 2.dp.toPx() + (size.width - 4.dp.toPx()).coerceAtLeast(0f) * (slots - series.size + index) / (slots - 1f)
                                val value = if (sample.isFinite()) sample.coerceAtLeast(0f) else 0f
                                val y = size.height * (1f - (value / maximum).coerceIn(0f, 1f))
                                if (index == 0) moveTo(x, y) else lineTo(x, y)
                            }
                        }
                        if (download.size >= 2) drawPath(path(download), downColor, style = Stroke(2.5.dp.toPx()))
                        if (upload.size >= 2) drawPath(path(upload), upColor, style = Stroke(1.8.dp.toPx(),
                            pathEffect = androidx.compose.ui.graphics.PathEffect.dashPathEffect(floatArrayOf(9f, 6f))))
                    }
                }
                Row(Modifier.fillMaxWidth().padding(start = 72.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    listOf("59 秒前", "30 秒前", "现在").forEach { label ->
                        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
                    }
                }
                if (state.metrics.samples.size < 2) Text(BifrostUiText.noSamples, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun ChoiceGroup(title: String, selected: String, choices: List<Pair<String, String>>, onSelect: (String) -> Unit, enabled: Boolean = true) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
        choices.forEach { (value, label) ->
            val active = selected == value
            val shape = RoundedCornerShape(14.dp)
            Text(
                label,
                color = if (!enabled) MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = .55f) else if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth().height(48.dp).clip(shape)
                    .background(if (active) MaterialTheme.colorScheme.primary.copy(alpha = .10f) else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = .18f))
                    .border(1.dp, if (active) MaterialTheme.colorScheme.primary.copy(alpha = .68f) else MaterialTheme.colorScheme.outline.copy(alpha = .36f), shape)
                    .clickable(enabled = enabled) { onSelect(value) }.semantics {
                    contentDescription = label
                    role = Role.RadioButton
                    this.selected = active
                    if (!enabled) disabled()
                }.padding(horizontal = 8.dp, vertical = 12.dp),
            )
        }
    }
}

private fun parseList(value: String): List<String> = value.replace("\r\n", "\n").split(',', ';', '\n').map(String::trim).filter(String::isNotEmpty)
