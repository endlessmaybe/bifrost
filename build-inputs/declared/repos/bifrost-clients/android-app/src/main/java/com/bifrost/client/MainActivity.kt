package com.bifrost.client

import android.content.Intent
import android.content.ClipData
import android.content.ClipboardManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.remember
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import com.bifrost.client.ui.theme.BifrostTheme
import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import com.bifrost.client.ui.model.BifrostRuntimeEvidence
import com.bifrost.client.ui.model.BifrostRuntimeSignal
import com.bifrost.client.ui.model.BifrostRoutingContract
import com.bifrost.client.ui.model.BifrostUiReducer
import com.bifrost.client.ui.model.BifrostUiText
import com.bifrost.client.ui.screens.BifrostAHomeScreen
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume

/**
 * Bifrost's small, stateful Android shell.  Secrets are held by the control
 * client/Keystore store; this activity only persists harmless UI choices and
 * passes the selected policy into BifrostVpnService.
 */
class MainActivity : ComponentActivity() {
    private companion object {
        const val STATE_DISCONNECT_TRANSACTION_ID = "bifrost.disconnect.transaction_id"
        const val STATE_DISCONNECT_GENERATION = "bifrost.disconnect.generation"
        const val STATE_DISCONNECT_DIGEST = "bifrost.disconnect.digest"
        const val STATE_DISCONNECT_BINDINGS = "bifrost.disconnect.bindings"
    }

    private val updates by lazy { BifrostUpdateManager(this) }
    private val control by lazy { BifrostControlClient(this) }
    private val applicationPackageCatalog by lazy { AndroidApplicationPackageCatalog(this) }
    private val applicationPolicyValidator by lazy {
        BifrostApplicationPolicyPackageValidator(applicationPackageCatalog, packageName)
    }
    private val applicationPolicyCoordinator by lazy {
        BifrostApplicationPolicyConnectionCoordinator(applicationPolicyValidator)
    }
    private val status = mutableStateOf(BifrostUiText.checkingUpdates)
    // Display-only cache; connection authority continues to load and verify independently.
    private var displayContent by mutableStateOf<String?>(null)
    private var displayApplications by mutableStateOf(emptyList<BifrostApplicationPackageOption>())
    private var applicationScan: kotlinx.coroutines.Job? = null
    private var accountDisplay by mutableStateOf(BifrostAccountDisplay())
    private var displayEnrolled by mutableStateOf(false)
    private var displayHasRecovery by mutableStateOf(false)
    private var displayPublicId by mutableStateOf("")
    private var displayGeneration = 0L
    private var updatePrompt by mutableStateOf(false)
    private var pendingUpdatePermission = false
    private val hasConfig = mutableStateOf(false)
    private val sources = mutableStateOf(emptyList<String>())
    private val countries = mutableStateOf(listOf("auto"))
    private val frontSources = mutableStateOf(listOf("auto"))
    private val recoveryCode = mutableStateOf("")
    private val accountBusy = mutableStateOf(false)
    private val settingsBusy = mutableStateOf(false)
    private val settingsFeedback = mutableStateOf("")
    private val recoveryPublicId = mutableStateOf("")
    private val pairingCode = mutableStateOf("")
    private val sensitiveValues = BifrostSensitiveValueStore()
    private val sensitiveEpoch = mutableIntStateOf(0)
    private val sensitiveClipboard by lazy { BifrostSensitiveClipboardController(AndroidSensitiveClipboard()) }
    private val sensitiveClipboardClear = Runnable {
        if (!sensitiveClipboard.clearOwned()) status.value = BifrostUiText.clipboardNotCleared
    }
    // Sensitive clipboard work has its own lifecycle-owned scheduler.  Probe
    // scheduling must never be able to delay or resurrect secret cleanup.
    private val sensitiveHandler = Handler(Looper.getMainLooper())
    private val candidateProbeCoordinator by lazy {
        (application as BifrostApplication).candidateProbeCoordinator
    }
    private val sourceAuthorityController by lazy {
        BifrostSourceAuthorityController(
            persistSource = { value -> uiPut(mapOf("source" to value)) },
            updateOwner = { value -> candidateProbeCoordinator.updateSource(value) },
        )
    }
    private var activityProbeLease: Closeable? = null
    private var selectedCore = "auto"
    private var selectedMode = "smart"
    private var selectedConnectionType = BifrostConnectionType.DIRECT_VMESH.wireValue
    private var selectedRouteMode = BifrostRouteMode.SMART.wireValue
    private var selectedSource = ""
    private var selectedCountry = "auto"
    private var selectedFrontSource = "auto"
    private var selectedAppPolicy = "allow"
    private var selectedAppPolicyEnabled = false
    private var includeApplications = emptyList<String>()
    private var excludeApplications = emptyList<String>()
    private var selectedApplicationPolicy: BifrostApplicationPolicySnapshot? = null
    private var selectedApplicationBindings = emptyList<BifrostApplicationPackageBinding>()
    /** Last observed automatic/service candidate; never treated as a manual
     * user request on a later connection. */
    private var observedCandidate: String? = null
    private var manualCandidateMode: String = "auto"
    private var manualCandidate: String? = null
    private var lastDisplayedProbeGeneration = 0L
    @Volatile private var activityVisible = false
    private var selectedTransactionId: String? = null
    private var blockedConnection: PendingConnection? = null
    private val connectionTransactionGate = BifrostConnectionTransactionGate()
    private val connectionTimeout = Runnable {
        pendingConnection?.let { failPendingConnection(it, "BF-CONNECTION-TIMEOUT") }
    }
    private data class PendingConnection(
        val transactionId: String,
        val uiMode: String,
        val connectionType: String,
        val routeMode: String,
        val appPolicyEnabled: Boolean,
        val mode: String,
        val core: String,
        val source: String,
        val country: String,
        val frontSource: String,
        val snapshot: BifrostApplicationPolicySnapshot,
        val bindings: List<BifrostApplicationPackageBinding>,
        val candidateMode: String = "auto",
        val manualCandidate: String? = null,
        val candidate: String? = null,
        val selectionReceipt: BifrostCandidateSelectionReceipt? = null,
        val receiptRetries: Int = 0,
    )
    private fun PendingConnection.token(): BifrostConnectionTransactionToken =
        BifrostConnectionTransactionToken(transactionId, snapshot.generation, snapshot.digest, BifrostApplicationPackageBindings.encode(bindings))
    private var pendingConnection: PendingConnection? by mutableStateOf(null)
    private val pendingCandidateRequest = AtomicReference<BifrostConnectionProbeRequest?>(null)
    /** Exact disconnect handshakes remain fenced until Service proves IDLE. */
    private var pendingDisconnect: BifrostConnectionTransactionToken? = null
    private var connectionFailure: Pair<BifrostConnectionTransactionToken, String>? = null
    private var disconnectAttempts = 0
    private val disconnectReconcile = Runnable {
        pendingDisconnect?.let(::reconcileDisconnect)
    }
    private val vpnAckReceiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
            handleVpnAck(resultCode, resultData)
        }
    }
    private val probeHandler = Handler(Looper.getMainLooper())
    private val uiKeys = BifrostSecureStore.UiKeys

    private val installPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        if (packageManager.canRequestPackageInstalls()) launchUpdateCheck(install = true)
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val pending = pendingConnection
        if (result.resultCode == RESULT_OK && pending != null && connectionTransactionGate.isActive(pending.token())) {
            probeHandler.removeCallbacks(connectionTimeout)
            probeHandler.postDelayed(connectionTimeout, connectionProbeBudget(pending.source))
            requestVpn(pending)
        } else if (pending != null) {
            if (connectionTransactionGate.cancelExact(pending.token())) {
                BifrostApplicationPolicySnapshotRegistry.remove(pending.transactionId)
                probeHandler.removeCallbacks(connectionTimeout)
                cancelPendingCandidateRequest()
                pendingConnection = null
            }
            status.value = BifrostUiErrorMapper.message(
                BifrostUiText.vpnPermission,
                IllegalArgumentException("BF-VPN-PERMISSION-DENIED"),
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        runCatching { DeviceKeys.ensure(this) }
            .onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.deviceKeys, it) }
        // Migrate the old plaintext UI namespace once, then use the same
        // Keystore-backed store as account/session state.  A failed commit or
        // scrub is surfaced and the secure defaults remain fail-closed.
        runCatching { BifrostSecureStore.migrateLegacyPreferences(this, "bifrost-ui", uiKeys) }
            .onFailure { status.value = BifrostUiText.storageUnavailable }
        runCatching { BifrostSecureStore.putBatch(this, mapOf("theme" to null, "design_direction" to null)) }
            .onFailure { status.value = BifrostUiText.storageUnavailable }
        selectedCore = uiGet("core", "auto")
            ?.takeIf { it == "auto" || it == "sing-box" || it == "xray" } ?: "auto"
        val persistedSelection = runCatching {
            BifrostConnectionRouteContract.parse(uiGet("connection_type"), uiGet("route_mode"))
        }.getOrNull()
        val legacyAmbiguous = persistedSelection == null && uiGet("mode").isNotBlank()
        selectedConnectionType = when {
            persistedSelection != null -> persistedSelection.connectionType.wireValue
            legacyAmbiguous -> ""
            else -> BifrostConnectionType.DIRECT_VMESH.wireValue
        }
        selectedRouteMode = when {
            persistedSelection != null -> persistedSelection.routeMode.wireValue
            legacyAmbiguous -> ""
            else -> BifrostRouteMode.SMART.wireValue
        }
        selectedMode = persistedSelection?.let(BifrostConnectionRouteContract::presentationMode) ?: "smart"
        selectedSource = uiGet("source")
        selectedCountry = if (selectedMode == "smartgate") uiGet("country", "auto") else "auto"
        selectedFrontSource = if (selectedMode == "smartgate") uiGet("front_source", "auto") else "auto"
        manualCandidateMode = uiGet("candidate_mode", "auto")
            ?.takeIf { it == "auto" || it == "manual" } ?: "auto"
        manualCandidate = uiGet("candidate_label")?.takeIf { it.isNotBlank() }
        if (manualCandidateMode != "manual") manualCandidate = null
        selectedAppPolicy = uiGet("app_policy", "allow")
            ?.takeIf { it == "allow" || it == "exclude" } ?: "allow"
        selectedAppPolicyEnabled = selectedMode == "smart" && uiGet("app_policy_enabled", "false") == "true"
        val persistedInclude = uiGet("include_apps")
        val persistedExclude = uiGet("exclude_apps")
        includeApplications = runCatching { BifrostApplicationPolicy.parseUiList(persistedInclude) }
            .getOrElse {
                status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationRoutingPolicy, it)
                listOf("\u0000BF-APP-PERSISTED-INVALID")
            }
        excludeApplications = runCatching { BifrostApplicationPolicy.parseUiList(persistedExclude) }
            .getOrElse {
                status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationRoutingPolicy, it)
                listOf("\u0000BF-APP-PERSISTED-INVALID")
        }
        restoreCommittedConnectionMetadata()
        restoreSavedDisconnectHandoff(savedInstanceState)
        refreshOptions()
        launchControlRefresh()
        if (intent?.getBooleanExtra("bifrost.quick.disconnect", false) == true) stopVpnService()
        else runCatching { resumeAfterPackageUpdate() }.onFailure {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.updateAction, it)
            BifrostDiagnostics.record(this, "update-resume-failed", it)
        }
        setContent {
            DisposableEffect(Unit) {
                val listener = BifrostRuntimeStatus.addListener { snapshot ->
                    runOnUiThread {
                        if (pendingConnection == null && snapshot.state == BifrostLeakState.HEALTHY) {
                            val live = BifrostServiceOwnershipRegistry.current()
                            if (live?.phase == BifrostServiceOwnershipPhase.COMMITTED &&
                                live.token.transactionId != selectedTransactionId) {
                                // PackageInstaller can cancel after the updater
                                // stopped the old connection. Release the old
                                // UI token only with its exact Service receipt,
                                // then adopt the newly restored live owner.
                                connectionTransactionGate.committedToken()?.let { old ->
                                    val oldService = BifrostServiceTransactionToken(old.transactionId, old.generation, old.digest, old.bindings)
                                    if (BifrostServiceOwnershipRegistry.releaseReceipt(oldService) != null &&
                                        connectionTransactionGate.beginDisconnectExact(old))
                                        connectionTransactionGate.releaseDisconnectExact(old)
                                }
                                restoreCommittedConnectionMetadata()
                            }
                        }
                        if (pendingConnection != null && snapshot.state == BifrostLeakState.HEALTHY) {
                            status.value = BifrostUiText.waitingVpnAck
                            return@runOnUiThread
                        }
                        status.value = when (snapshot.state) {
                            BifrostLeakState.HEALTHY -> if (snapshot.strictProtection) BifrostUiText.vpnConnected else BifrostUiText.coreRunningUnverified
                            BifrostLeakState.BLOCKING -> BifrostUiText.coreBlockedEstablished
                            BifrostLeakState.UNPROTECTED -> BifrostUiText.coreUnprotected
                            BifrostLeakState.STARTING -> BifrostUiText.preparingTunnel
                            else -> status.value
                        }
                    }
                }
                onDispose { listener.close() }
            }
            val liveEvidence = BifrostServiceOwnershipRegistry.current()
            val selectedPolicy = selectedApplicationPolicy
            val expectedTransaction = selectedTransactionId
            val expectedBindings = selectedPolicy?.let {
                runCatching { BifrostApplicationPackageBindings.encode(selectedApplicationBindings) }.getOrNull()
            }
            val bindingPayloadMatches = liveEvidence != null && selectedPolicy != null &&
                expectedBindings != null && liveEvidence.token.bindings == expectedBindings &&
                runCatching {
                    BifrostApplicationPackageBindings.decode(liveEvidence.token.bindings)
                        .map { it.packageName } == selectedPolicy.identities
                }.getOrDefault(false)
            val exactCommittedOwner = liveEvidence?.phase == BifrostServiceOwnershipPhase.COMMITTED &&
                !expectedTransaction.isNullOrBlank() &&
                selectedPolicy != null &&
                liveEvidence.token.transactionId == expectedTransaction &&
                liveEvidence.token.digest == selectedPolicy.digest &&
                liveEvidence.token.generation == selectedPolicy.generation &&
                bindingPayloadMatches
            val runtimeSnapshot = BifrostRuntimeStatus.current
            val runtimeSignal = when (runtimeSnapshot.state) {
                BifrostLeakState.STOPPED -> if (pendingConnection != null) BifrostRuntimeSignal.PREPARING else BifrostRuntimeSignal.IDLE
                BifrostLeakState.STARTING -> BifrostRuntimeSignal.PREPARING
                BifrostLeakState.HEALTHY -> if (runtimeSnapshot.strictProtection) BifrostRuntimeSignal.PROTECTED else BifrostRuntimeSignal.CONNECTED
                BifrostLeakState.BLOCKING -> BifrostRuntimeSignal.BLOCKED
                BifrostLeakState.UNPROTECTED, BifrostLeakState.ERROR -> BifrostRuntimeSignal.ERROR
            }
            val trafficMetrics by BifrostTrafficTelemetry.metrics.collectAsStateWithLifecycle()
            val actualRoute by BifrostTrafficTelemetry.route.collectAsStateWithLifecycle()
            val presentation = BifrostUiReducer.fromRuntimeSignal(
                runtimeSignal,
                BifrostRuntimeEvidence(
                    serviceAccepted = exactCommittedOwner,
                    readbackVerified = exactCommittedOwner,
                    transactionId = liveEvidence?.token?.transactionId,
                    digest = liveEvidence?.token?.digest,
                    generation = liveEvidence?.token?.generation,
                    bindings = liveEvidence?.token?.bindings,
                    signal = runtimeSignal,
                ),
                expectedTransaction,
                selectedPolicy?.digest,
                selectedPolicy?.generation,
                expectedBindings,
            ).let { state ->
                 if (!state.isConnected) state else state.copy(
                     metrics = trafficMetrics,
                     source = selectedSource.takeIf { it.isNotBlank() } ?: BifrostUiText.notConnected,
                     route = actualRoute ?: BifrostUiText.readingRoute,
                     country = selectedCountry.takeIf { it.isNotBlank() } ?: BifrostUiText.notConnected,
                     core = BifrostCandidateSelectionContract.coreOptions.firstOrNull { it.code == selectedCore }?.displayName
                         ?: selectedCore,
                 )
             }
             val candidateOptions = remember(displayContent, selectedSource) {
                 displayContent?.let { BifrostCandidateSelectionContract.candidateOptions(it, selectedSource) }.orEmpty()
             }
             val countryDisplayNames = remember(displayContent) {
                 displayContent?.let { BifrostCandidateSelectionContract.countryOptions(it).toMap() }.orEmpty()
             }
             val applicationOptions = displayApplications
             if (updatePrompt) BifrostTheme {
                 AlertDialog(onDismissRequest = { updatePrompt = false },
                     title = { Text(BifrostUiText.updatePromptTitle) },
                     text = { Text(BifrostUiText.updatePromptMessage) },
                     confirmButton = { TextButton(onClick = { updatePrompt = false; launchUpdateCheck(install = true) }) { Text(BifrostUiText.updateNow) } },
                     dismissButton = { TextButton(onClick = { updatePrompt = false }) { Text(BifrostUiText.updateLater) } })
             }
             BifrostAHomeScreen(
                initialCore = selectedCore,
                initialMode = selectedMode,
                initialSource = selectedSource,
                initialCountry = selectedCountry,
                 initialFrontSource = selectedFrontSource,
                 initialCandidateMode = manualCandidateMode,
                 initialCandidateLabel = manualCandidate,
                initialAppPolicy = selectedAppPolicy,
                initialAppPolicyEnabled = selectedAppPolicyEnabled,
                initialIncludeApps = includeApplications,
                initialExcludeApps = excludeApplications,
                sourceOptions = sources.value,
                countryOptions = countries.value,
                countryDisplayNames = countryDisplayNames,
                frontSourceOptions = frontSources.value,
                candidateOptions = candidateOptions,
                coreOptions = BifrostCandidateSelectionContract.coreOptions,
                applicationOptions = applicationOptions,
                onRefreshApplications = ::refreshApplications,
                hasCachedConfig = hasConfig.value,
                isEnrolled = displayEnrolled,
                accountStateReady = accountDisplay.ready,
                accountStateMessage = accountDisplay.message,
                onRetryAccount = { refreshDisplayAccount(); launchControlRefresh(manual = true, checkProgramUpdates = false) },
                onShareDiagnostics = ::shareDiagnostics,
                accountBusy = accountBusy.value,
                accountStatus = status.value,
                settingsBusy = settingsBusy.value,
                settingsFeedback = settingsFeedback.value,
                hasSavedRecovery = displayHasRecovery,
                 presentation = presentation,
                initialBaseUrl = BuildConfig.CONTROL_BASE_URL,
                recoveryCode = recoveryCode.value,
                initialPublicId = displayPublicId,
                pairingCode = pairingCode.value,
                sensitiveGeneration = sensitiveEpoch.intValue,
                onEnroll = { _, invite -> enroll(BuildConfig.CONTROL_BASE_URL, invite) },
                onRecover = { _, code -> recover(BuildConfig.CONTROL_BASE_URL, code) },
                onRotateRecovery = ::rotateRecovery,
                onCreatePairing = ::createPairing,
                onRedeemPairing = { _, code -> redeemPairing(BuildConfig.CONTROL_BASE_URL, code) },
                onRecoverySaved = ::acknowledgeRecovery,
                onRevealRecovery = ::revealRecovery,
                onRevealPairing = ::revealPairing,
                onRecoveryExpired = ::expireRecovery,
                onPairingExpired = ::expirePairing,
                onCopyRecovery = ::copyRecovery,
                onCopyPairing = ::copyPairing,
                onAccountPageLeft = ::clearSensitiveUi,
                onLogout = ::logout,
                onRefresh = { launchControlRefresh(manual = true) },
                onSourceChanged = ::onSourceSelected,
                onCandidateModeChanged = { value ->
                    val oldMode = manualCandidateMode
                    val oldLabel = manualCandidate
                    manualCandidateMode = if (value == "manual") "manual" else "auto"
                    if (manualCandidateMode != "manual") manualCandidate = null
                    val saved = uiPut(mapOf("candidate_mode" to manualCandidateMode, "candidate_label" to manualCandidate))
                    if (!saved) { manualCandidateMode = oldMode; manualCandidate = oldLabel }
                    saved
                },
                onCandidateLabelChanged = { value ->
                    val oldLabel = manualCandidate
                    manualCandidate = value.takeIf { it.isNotBlank() }
                    val saved = uiPut(mapOf("candidate_mode" to manualCandidateMode, "candidate_label" to manualCandidate))
                    if (!saved) manualCandidate = oldLabel
                    saved
                },
                onConnect = ::connectSelection,
                onOpenVpnSettings = { startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) },
                onOpenNotificationSettings = {
                    startActivity(Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName))
                },
                onDisconnect = ::stopVpnService,
                onCheckUpdate = { lastPromptedUpdate = 0; launchUpdateCheck() },
            )
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        pendingDisconnect?.let { token ->
            outState.putString(STATE_DISCONNECT_TRANSACTION_ID, token.transactionId)
            outState.putString(STATE_DISCONNECT_GENERATION, token.generation)
            outState.putString(STATE_DISCONNECT_DIGEST, token.digest)
            outState.putString(STATE_DISCONNECT_BINDINGS, token.bindings)
        }
        super.onSaveInstanceState(outState)
    }

    /** Rehydrate only the exact token that this Activity had already handed
     * to the Service.  No registry-wide receipt/token enumeration is allowed
     * during recreation. */
    private fun connectSelection(mode: String, core: String, source: String, country: String,
        frontSource: String, appPolicy: String, appPolicyEnabled: Boolean, include: List<String>,
        exclude: List<String>, candidateMode: String, candidateLabel: String?) {
        if (BifrostFeaturePreferences.changing || BifrostUpdateInstallGate.pending || pendingConnection != null || blockedConnection != null ||
            pendingDisconnect != null || connectionTransactionGate.blockedToken() != null ||
            connectionTransactionGate.phase() == BifrostConnectionTransactionPhase.DISCONNECTING) {
            status.value = BifrostUiErrorMapper.message(
                "VPN",
                IllegalArgumentException("BF-CONNECTION-IN-FLIGHT"),
            )
            return
        }
        // App policy is an independent routing-page switch. It
        // deliberately does not add a fourth home mode: when
        // enabled it selects the existing typed per-app service
        // contract and carries the selected allow/exclude list.
        val effectiveCandidateMode = if (mode == "global") "manual" else "auto"
        connectionFailure = null
        val connectionSelection = try {
            BifrostConnectionRouteContract.fromUiMode(mode, appPolicyEnabled)
        } catch (error: Exception) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, error)
            return
        }
        val canonicalSource = sources.value.firstOrNull { it.equals(source, true) }
        val smartGate = connectionSelection.connectionType == BifrostConnectionType.SMARTGATE
        val canonicalCountry = if (smartGate) countries.value.firstOrNull { it.equals(country, true) && !it.equals("auto", true) } else "auto"
        val canonicalFrontSource = if (smartGate) frontSources.value.firstOrNull { it.equals(frontSource, true) } else "auto"
        if (canonicalSource == null || canonicalCountry == null || canonicalFrontSource == null) {
            status.value = BifrostUiErrorMapper.message(
                BifrostUiText.routeProbeAction,
                IllegalArgumentException(if (smartGate) "BF-SMARTGATE-COUNTRY" else "BF-SOURCE-NOT-READY"),
            )
            return
        }
        val verified = runCatching { BifrostConfigStore.load(this)?.content }.getOrNull()
        if (verified == null) {
            status.value = BifrostUiErrorMapper.message(
                BifrostUiText.routeProbeAction,
                IllegalArgumentException("BF-SOURCE-NOT-READY"),
            )
            return
        }
        val nodeSelection = try {
            BifrostCandidateSelectionContract.validate(
                verified,
                canonicalSource,
                mode,
                canonicalCountry,
                BifrostNodeSelection(
                    BifrostCandidateMode.parse(effectiveCandidateMode),
                    candidateLabel,
                    core,
                ),
            )
        } catch (error: Exception) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, error)
            return
        }
        val routing = try {
            BifrostRoutingContract.select(connectionSelection, appPolicy, include, exclude)
        } catch (error: Exception) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationRoutingPolicy, error)
            return
        }
        val wireMode = routing.wireMode
        val applicationPolicySnapshot = try {
            BifrostApplicationPolicy.normalize(
                routeMode = connectionSelection.routeMode.wireValue,
                policyMode = routing.policyMode,
                include = routing.include,
                exclude = routing.exclude,
            )
        } catch (error: Exception) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationRoutingPolicy, error)
            return
        }
        val applicationBindings = try {
            BifrostApplicationPolicy.verify(applicationPolicySnapshot)
            applicationPolicyCoordinator.validate(applicationPolicySnapshot)
        } catch (error: Exception) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationPackage, error)
            return
        }
        val pending = PendingConnection(
            transactionId = UUID.randomUUID().toString().replace("-", ""),
            uiMode = mode,
            connectionType = connectionSelection.connectionType.wireValue,
            routeMode = connectionSelection.routeMode.wireValue,
            appPolicyEnabled = appPolicyEnabled,
            mode = connectionSelection.routeMode.wireValue,
            core = core,
            source = canonicalSource,
            country = canonicalCountry,
            frontSource = canonicalFrontSource,
            snapshot = applicationPolicySnapshot,
            bindings = applicationBindings,
            candidateMode = nodeSelection.mode.wireValue,
            manualCandidate = nodeSelection.manualLabel,
        )
        if (!BifrostApplicationPolicySnapshotRegistry.register(pending.transactionId, applicationPolicySnapshot)) {
            status.value = BifrostUiErrorMapper.message("VPN", IllegalArgumentException("BF-CONNECTION-ACTIVE"))
            return
        }
        if (!connectionTransactionGate.begin(pending.token())) {
            BifrostApplicationPolicySnapshotRegistry.remove(pending.transactionId)
            status.value = BifrostUiErrorMapper.message(
                "VPN",
                IllegalArgumentException("BF-CONNECTION-IN-FLIGHT"),
            )
            return
        }
        pendingConnection = pending
        probeHandler.postDelayed(connectionTimeout, connectionProbeBudget(pending.source))
        // The signed configuration was already loaded and validated above.
        // Release discovery must not block the VPN needed to reach Control,
        // nor consume its startup deadline while waiting for HTTPS. Startup
        // refresh and the explicit update action still check releases.
        requestVpn(pending)
    }

    private fun connectionProbeBudget(source: String): Long {
        val content = BifrostConfigStore.load(this)?.content ?: return 30_000L
        val sources = JSONObject(content).optJSONArray("sources") ?: return 30_000L
        val nodes = (0 until sources.length()).mapNotNull { sources.optJSONObject(it) }
            .firstOrNull { it.optString("code").equals(source, true) }?.optJSONArray("candidates")?.length() ?: 1
        return BifrostCandidateSelector.connectionBudgetMs(nodes)
    }

    private fun restoreSavedDisconnectHandoff(savedInstanceState: Bundle?) {
        val state = savedInstanceState ?: return
        val transactionId = state.getString(STATE_DISCONNECT_TRANSACTION_ID)
        val generation = state.getString(STATE_DISCONNECT_GENERATION)
        val digest = state.getString(STATE_DISCONNECT_DIGEST)
        val bindings = state.getString(STATE_DISCONNECT_BINDINGS)
        if (transactionId.isNullOrBlank() || generation.isNullOrBlank() ||
            digest.isNullOrBlank() || bindings.isNullOrBlank() ||
            !transactionId.matches(Regex("[0-9a-f]{32}")) ||
            !generation.matches(Regex("[0-9a-f]{32}")) ||
            !digest.matches(Regex("[0-9a-f]{64}")) || bindings.length > 16 * 1024) return
        val token = BifrostConnectionTransactionToken(transactionId, generation, digest, bindings)
        val serviceToken = BifrostServiceTransactionToken(transactionId, generation, digest, bindings)
        if (!BifrostServiceOwnershipRegistry.isDisconnectRequested(serviceToken)) return
        // The exact overload is a proof check; it cannot reveal another
        // pending receipt even when several handoffs are queued.
        if (BifrostServiceOwnershipRegistry.releaseDiscoveryToken(serviceToken) == null &&
            BifrostServiceOwnershipRegistry.current()?.token != serviceToken &&
            BifrostServiceOwnershipRegistry.releaseReceipt(serviceToken) == null) return
        pendingDisconnect = token
        scheduleDisconnectReconciliation(token)
    }

    private fun discardPending(pending: PendingConnection, code: String): Boolean {
        // A physical-network callback or probe generation can settle while
        // resolving a signed seed after disconnect. Re-resolve it under the
        // same cancellable intent, before any Service command is dispatched.
        // The refreshed receipt still passes every network/config check.
        if (code == "BF-PROBE-BINDING-CHANGED" && pending.receiptRetries < 2 &&
            !isFinishing && !isDestroyed && pendingConnection?.token() == pending.token() &&
            connectionTransactionGate.canRefreshPreparation(pending.token())) {
            cancelPendingCandidateRequest()
            val refreshed = pending.copy(candidate = null, selectionReceipt = null,
                receiptRetries = pending.receiptRetries + 1)
            pendingConnection = refreshed
            android.util.Log.i("BifrostConnectionDiagnostic", "preparationRetry=${refreshed.receiptRetries} code=$code")
            lifecycleScope.launch { kotlinx.coroutines.yield(); requestVpn(refreshed) }
            return false
        }
        android.util.Log.w("BifrostConnectionDiagnostic", "discard=$code")
        connectionTransactionGate.fail(pending.token())
        probeHandler.removeCallbacks(connectionTimeout)
        cancelPendingCandidateRequest()
        if (pendingConnection?.token() == pending.token()) pendingConnection = null
        BifrostApplicationPolicySnapshotRegistry.remove(pending.transactionId)
        status.value = BifrostUiErrorMapper.message(BifrostUiText.connectAction, IllegalArgumentException(code))
        return true
    }

    private fun restoreCommittedConnectionMetadata() {
        val live = BifrostServiceOwnershipRegistry.current()
        if (live != null) {
            val token = BifrostConnectionTransactionToken(
                live.token.transactionId,
                live.token.generation,
                live.token.digest,
                live.token.bindings,
            )
            val bindings = runCatching {
                BifrostApplicationPackageBindings.decode(live.token.bindings)
            }.getOrNull()
            if (bindings == null) {
                selectedTransactionId = null
                selectedApplicationPolicy = null
                selectedApplicationBindings = emptyList()
                pendingDisconnect = token
                sendScopedDisconnect(token)
                return
            }
            if (live.token.generation != live.snapshot.generation || live.token.digest != live.snapshot.digest ||
                runCatching { BifrostApplicationPolicy.verify(live.snapshot) }.isFailure) {
                pendingDisconnect = token
                sendScopedDisconnect(token)
                return
            }
            val description = live.description
            val restored = PendingConnection(
                transactionId = live.token.transactionId,
                uiMode = runCatching {
                    BifrostConnectionRouteContract.presentationMode(
                        BifrostConnectionRouteContract.parse(uiGet("connection_type"), live.snapshot.routeMode),
                    )
                }.getOrDefault("smart"),
                connectionType = uiGet("connection_type") ?: "",
                routeMode = live.snapshot.routeMode,
                appPolicyEnabled = uiGet("app_policy_enabled", "false") == "true" || live.snapshot.routeMode == "per-app",
                mode = live.snapshot.routeMode,
                core = description.core,
                source = description.source,
                country = description.country,
                frontSource = description.frontSource,
                snapshot = live.snapshot,
                bindings = bindings,
                candidate = description.candidate,
            )
            if (BifrostServiceOwnershipRegistry.isDisconnectRequested(live.token)) {
                pendingDisconnect = token
                sendScopedDisconnect(token)
                return
            }
            if (live.phase == BifrostServiceOwnershipPhase.PENDING && connectionTransactionGate.adoptStarting(token)) {
                pendingConnection = restored
                probeHandler.removeCallbacks(connectionTimeout)
                probeHandler.postDelayed(connectionTimeout, 315_000L)
            } else if (live.phase == BifrostServiceOwnershipPhase.BLOCKED_FAILED && connectionTransactionGate.adoptBlocked(token)) {
                blockedConnection = restored
            } else if (live.phase == BifrostServiceOwnershipPhase.UNPROTECTED_FAILED) {
                // Keep the exact owner fenced in the Service and immediately
                // request a token-bound retry; never present it as IDLE or
                // BLOCKED after recreation.
                pendingDisconnect = token
                sendScopedDisconnect(token)
            } else if (live.phase == BifrostServiceOwnershipPhase.COMMITTED && connectionTransactionGate.adoptCommitted(token)) {
                selectedTransactionId = live.token.transactionId
                selectedApplicationPolicy = live.snapshot
                selectedApplicationBindings = bindings
                observedCandidate = description.candidate
                selectedConnectionType = runCatching { BifrostConnectionType.parse(description.connectionType).wireValue }
                    .getOrDefault("")
                selectedRouteMode = live.snapshot.routeMode
                selectedMode = runCatching {
                    BifrostConnectionRouteContract.presentationMode(
                        BifrostConnectionRouteContract.parse(description.connectionType, live.snapshot.routeMode),
                    )
                }.getOrDefault("")
                selectedCore = description.core
                selectedSource = description.source
                selectedCountry = description.country
                selectedFrontSource = description.frontSource
                selectedAppPolicyEnabled = live.snapshot.routeMode == "per-app"
            }
            if (live.phase == BifrostServiceOwnershipPhase.BLOCKED_FAILED) {
                selectedTransactionId = null
                selectedApplicationPolicy = null
                selectedApplicationBindings = emptyList()
            }
        } else {
            // Persisted metadata is history/display only.  Without a live
            // same-process owner it cannot recreate a policy capability.
            selectedTransactionId = null
            selectedApplicationPolicy = null
            selectedApplicationBindings = emptyList()
            // A null owner is not authority.  Exact Activity handoff state is
            // restored from savedInstanceState above and checked against the
            // token-bound registry request/receipt; no first-receipt fallback.
        }
    }

    private fun refreshApplications() {
        applicationScan?.cancel()
        applicationScan = lifecycleScope.launch {
            displayApplications = withContext(Dispatchers.IO) { runCatching { applicationPackageCatalog.selectable() }.getOrDefault(emptyList()) }
        }
    }

    override fun onStart() {
        super.onStart()
        BifrostAppVisibility.update(true)
        refreshDisplayAccount()
        refreshApplications()
        if (pendingUpdatePermission && packageManager.canRequestPackageInstalls()) {
            pendingUpdatePermission = false
            launchUpdateCheck(install = true)
        }
        activityVisible = true
        handleQuickConnect()
        probeHandler.removeCallbacks(nodeRefreshTick)
        probeHandler.postDelayed(nodeRefreshTick, 1_000L)
        activityProbeLease?.close()
        activityProbeLease = candidateProbeCoordinator.acquireLease(
            "activity",
            selectedSource.takeIf { it.isNotBlank() && !it.equals("auto", true) },
            listener = { result ->
            runOnUiThread { handleProbeResult(result) }
            },
        )
        candidateProbeCoordinator.refreshNow(selectedSource.takeIf { it.isNotBlank() && !it.equals("auto", true) })
    }

    override fun onStop() {
        BifrostAppVisibility.update(false)
        activityVisible = false
        probeHandler.removeCallbacks(nodeRefreshTick)
        activityProbeLease?.close()
        activityProbeLease = null
        clearSensitiveUi()
        super.onStop()
    }

    override fun onDestroy() {
        activityVisible = false
        probeHandler.removeCallbacks(nodeRefreshTick)
        probeHandler.removeCallbacks(disconnectReconcile)
        pendingConnection?.let { pending ->
            if (cancelLocalPreparation(pending)) {
                // No Service command was ever dispatched for this token.
            } else if (connectionTransactionGate.beginDisconnectExact(pending.token())) {
                probeHandler.removeCallbacks(connectionTimeout)
                cancelPendingCandidateRequest()
                if (pendingConnection?.token() == pending.token()) pendingConnection = null
                sendScopedDisconnect(pending)
            }
        }
        // A blocked failure is deliberately retained for the next Activity;
        // destroying the UI must never release its exact Bifrost boundary.
        clearSensitiveUi()
        activityProbeLease?.close()
        activityProbeLease = null
        cancelPendingCandidateRequest()
        probeHandler.removeCallbacks(disconnectReconcile)
        super.onDestroy()
    }

    private fun enroll(baseUrl: String, invite: String) {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            clearRecoveryUi()
            status.value = BifrostUiText.enrollmentProgress
            val result = runCatching {
                disconnectBeforeAccountChange()
                withContext(Dispatchers.IO) { control.enroll(baseUrl, invite) }
            }
            accountBusy.value = false
            result.onSuccess {
                if (it.recoveryCode.isNotBlank()) {
                    if (!sensitiveValues.publishRecovery(it.recoveryCode)) {
                        clearRecoveryUi()
                        status.value = BifrostUiText.recoveryFormatInvalid
                        return@onSuccess
                    }
                    recoveryCode.value = it.recoveryCode
                    sensitiveEpoch.intValue++
                    recoveryPublicId.value = it.publicId
                    status.value = BifrostUiText.recoveryOnlyOnce
                } else {
                    // Existing-account cross-platform activation intentionally
                    // returns no replacement recovery code.
                    clearRecoveryUi()
                    status.value = if (it.state == "resumed") BifrostUiErrorMapper.success(BifrostUiText.enrollAction, it.state)
                        else BifrostUiText.crossPlatformActivationSuccess
                }
                refreshOptions()
            }.onFailure {
                clearRecoveryUi()
                status.value = BifrostUiErrorMapper.message(BifrostUiText.enrollAction, it)
            }
        }
    }

    private fun recover(baseUrl: String, code: String) {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            status.value = BifrostUiText.recoveryProgress
            val result = withContext(Dispatchers.IO) {
                runCatching { control.recover(baseUrl, code) }
            }
            accountBusy.value = false
            result.onSuccess {
                status.value = BifrostUiText.crossPlatformActivationSuccess
                refreshOptions()
            }
                .onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.recoveryAction, it) }
        }
    }

    private fun rotateRecovery() {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            status.value = BifrostUiText.rotatingRecovery
            val result = withContext(Dispatchers.IO) { runCatching { control.rotateRecoveryCode() } }
            accountBusy.value = false
            result.onSuccess {
                clearRecoveryUi()
                status.value = BifrostUiText.recoveryRenewed
            }.onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.rotateRecovery, it) }
        }
    }

    private fun createPairing() {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            clearPairingUi()
            val result = withContext(Dispatchers.IO) {
                runCatching { control.createPairing("windows") }
            }
            accountBusy.value = false
            result.onSuccess {
                if (!sensitiveValues.publishPairing(it.pairingCode)) {
                    clearPairingUi()
                    status.value = BifrostUiText.pairingInvalid
                    return@onSuccess
                }
                pairingCode.value = it.pairingCode
                sensitiveEpoch.intValue++
                status.value = BifrostUiText.pairingCreated
            }.onFailure {
                clearPairingUi()
                status.value = BifrostUiErrorMapper.message(BifrostUiText.createPairingAction, it)
            }
        }
    }

    private fun redeemPairing(baseUrl: String, code: String) {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            status.value = BifrostUiText.pairingProgress
            val result = withContext(Dispatchers.IO) {
                runCatching { control.redeemPairing(baseUrl, code) }
            }
            accountBusy.value = false
            result.onSuccess {
                status.value = BifrostUiErrorMapper.success(BifrostUiText.pairingAction, it.state)
                refreshOptions()
            }.onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.pairingAction, it) }
        }
    }

    private fun logout() {
        if (accountBusy.value) return
        accountBusy.value = true
        lifecycleScope.launch {
            // Revoke the local data-plane session before deleting control
            // credentials; logout must not leave a live tunnel behind.
            val result = runCatching {
                disconnectBeforeAccountChange()
                withContext(Dispatchers.IO) { control.logout() }
            }
            accountBusy.value = false
            result.onSuccess {
                hasConfig.value = false
                clearSourceAuthority()
                countries.value = listOf("auto")
                clearSensitiveUi()
                refreshOptions()
                status.value = BifrostUiErrorMapper.success(BifrostUiText.logoutAction, it.state)
            }.onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.logoutAction, it) }
        }
    }

    private suspend fun disconnectBeforeAccountChange() {
        stopVpnService()
        kotlinx.coroutines.withTimeout(15_000L) {
            while (pendingConnection != null || pendingDisconnect != null ||
                BifrostRuntimeStatus.current.state != BifrostLeakState.STOPPED) kotlinx.coroutines.delay(100)
        }
    }

    private fun acknowledgeRecovery() {
        if (!sensitiveValues.acknowledgeRecovery()) {
            status.value = BifrostUiText.recoveryExpired
            return
        }
        clearRecoveryUi()
        status.value = BifrostUiText.recoverySaved
    }

    private fun revealRecovery(): Boolean {
        val value = recoveryValueForAction()
        if (value == null) {
            clearRecoveryUi()
            status.value = BifrostUiText.recoveryMissing
            return false
        }
        recoveryCode.value = value
        return true
    }

    private fun revealPairing(): Boolean {
        val value = sensitiveValues.revealPairing()
        if (value == null) {
            clearPairingUi()
            status.value = BifrostUiText.pairingExpired
            return false
        }
        pairingCode.value = value
        return true
    }

    private fun expireRecovery() {
        if (sensitiveValues.revealRecovery() == null) clearRecoveryUi()
    }

    private fun expirePairing() {
        if (sensitiveValues.revealPairing() == null) clearPairingUi()
    }

    private enum class SensitiveSlot { RECOVERY, PAIRING }

    private fun recoveryValueForAction(): String? {
        sensitiveValues.revealRecovery()?.let { return it }
        val saved = runCatching { control.savedRecoveryCode() }.getOrDefault("")
        return if (saved.isNotBlank() && sensitiveValues.publishRecovery(saved)) sensitiveValues.revealRecovery() else null
    }

    private fun copyRecovery() = copySensitive(SensitiveSlot.RECOVERY)

    private fun copyPairing() = copySensitive(SensitiveSlot.PAIRING)

    private fun copySensitive(slot: SensitiveSlot) {
        val label = if (slot == SensitiveSlot.RECOVERY) BifrostUiText.recoveryOneTime else BifrostUiText.pairingOneTime
        // Copy is typed and re-validates the value TTL at the moment of the
        // action.  It must not reveal or mutate the Compose display state.
        val value = when (slot) {
            SensitiveSlot.RECOVERY -> recoveryValueForAction()
            SensitiveSlot.PAIRING -> sensitiveValues.revealPairing()
        }
        if (value == null || !sensitiveClipboard.copy(value)) {
            status.value = BifrostUiText.clipboardFailure(label)
            return
        }
        sensitiveHandler.removeCallbacks(sensitiveClipboardClear)
        sensitiveHandler.postDelayed(sensitiveClipboardClear, BifrostSensitiveValueStore.DISPLAY_TTL_MS)
        status.value = BifrostUiText.clipboardCopy(label)
    }

    private fun clearRecoveryUi() {
        sensitiveClipboard.clearOwned()
        sensitiveValues.clearRecovery()
        recoveryCode.value = ""
        recoveryPublicId.value = ""
        sensitiveEpoch.intValue++
    }

    private fun clearPairingUi() {
        sensitiveClipboard.clearOwned()
        sensitiveValues.clearPairing()
        pairingCode.value = ""
        sensitiveEpoch.intValue++
    }

    private fun clearSensitiveUi() {
        sensitiveHandler.removeCallbacks(sensitiveClipboardClear)
        sensitiveClipboard.onBackground()
        sensitiveValues.clearAll()
        recoveryCode.value = ""
        pairingCode.value = ""
        recoveryPublicId.value = ""
        sensitiveEpoch.intValue++
    }

    private inner class AndroidSensitiveClipboard : BifrostClipboard {
        private fun manager(): ClipboardManager? = getSystemService(ClipboardManager::class.java)

        override fun readText(): String? = runCatching {
            manager()?.primaryClip?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString()
        }.getOrNull()

        override fun writeText(value: String): Boolean = runCatching {
            val clipboard = manager() ?: return@runCatching false
            clipboard.setPrimaryClip(ClipData.newPlainText("Bifrost", value))
            true
        }.getOrDefault(false)

        override fun clearIfMatches(expected: String): Boolean = runCatching {
            val clipboard = manager() ?: return@runCatching false
            if (readText() != expected) return@runCatching false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("Bifrost", ""))
            }
            true
        }.getOrDefault(false)
    }

    private val nodeRefreshTick = object : Runnable {
        override fun run() {
            if (!activityVisible) return
            // Storage reads and session repair run on IO. A read failure is
            // never evidence that the device was logged out.
            if (!accountBusy.value && pendingConnection == null && pendingDisconnect == null) {
                refreshDisplayAccount()
                launchControlRefresh(checkProgramUpdates = false)
            }
            probeHandler.postDelayed(this, BifrostMaintenancePolicy.CONFIG_INTERVAL_MS)
        }
    }

    private fun launchControlRefresh(manual: Boolean = false, checkProgramUpdates: Boolean = true) {
        if (settingsBusy.value) return
        if (!manual && !BifrostMaintenancePolicy.claimConfigRefresh(android.os.SystemClock.elapsedRealtime())) {
            if (checkProgramUpdates) launchUpdateCheck()
            return
        }
        settingsBusy.value = true
        if (manual) settingsFeedback.value = BifrostUiText.checkingConfig
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { control.refresh() } }
            if (manual) result.onFailure {
                android.util.Log.w("BifrostNodeUpdate", "refreshFailed=${BifrostUiErrorMapper.code(it)} type=${it.javaClass.simpleName}")
            }
            settingsBusy.value = false
            if (manual) settingsFeedback.value = result.fold(
                { when (it.state) {
                    "updated" -> "节点已更新 · v${it.configVersion}"
                    "cached" -> "节点已是最新 · v${it.configVersion}"
                    else -> BifrostUiErrorMapper.success(BifrostUiText.refreshAction, it.state)
                } },
                { BifrostUiErrorMapper.message(BifrostUiText.refreshNodesAction, it) },
            )
            result.onSuccess {
                if (manual || it.state == "updated" || checkProgramUpdates) {
                    if (pendingConnection == null && pendingDisconnect == null)
                        status.value = BifrostUiErrorMapper.success(BifrostUiText.refreshAction, it.state)
                    refreshOptions()
                }
            }.onFailure {
                if (it is BifrostDeviceRevokedException) {
                    stopVpnService()
                    hasConfig.value = false
                    clearSourceAuthority()
                    clearSensitiveUi()
                    refreshOptions()
                    status.value = BifrostUiErrorMapper.message(BifrostUiText.refreshNodesAction, it)
                } else if (!hasConfig.value) status.value = BifrostUiErrorMapper.message(BifrostUiText.refreshNodesAction, it)
            }
            refreshDisplayAccount()
            result.onFailure { BifrostDiagnostics.record(this@MainActivity, "config-refresh-failed", it) }
            if (!manual && checkProgramUpdates) launchUpdateCheck()
        }
    }

    private fun handleProbeResult(result: BifrostProbeCoordinatorResult) {
        if (!activityVisible || isFinishing || isDestroyed) return
        if (!result.source.equals(selectedSource, true)) return
        // Admission is generation-bound, but the UI also re-reads the exact
        // verified config/network before publication. This closes the window
        // between lifecycle validation and the dispatcher callback.
        val latest = runCatching { BifrostConfigStore.load(this) }.getOrNull() ?: return
        val latestInput = runCatching {
            BifrostProbeFingerprints.input(latest, result.source, result.key.networkFingerprint)
        }.getOrNull() ?: return
        if (result.key.configVersion != latest.version || result.key.configDigest != latest.digest ||
            result.key.candidateFingerprint != latestInput.candidateFingerprint ||
            result.key.transportFingerprint != latestInput.transportFingerprint ||
            result.key.networkFingerprint != AndroidNetworkBucket.fingerprint(this)) return
        // Keep a local monotonic latch as well so an out-of-order callback
        // cannot repaint this Activity with an older exact generation.
        if (result.key.generation < lastDisplayedProbeGeneration) return
        lastDisplayedProbeGeneration = result.key.generation
        result.label?.let { label ->
            // A background probe must not overwrite a connection failure or
            // the progress of the explicit connect/disconnect transaction.
            return
        }
        result.error?.let { error ->
            status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, error)
        }
    }

    private var lastPromptedUpdate = 0L
    private var updateCheckRunning = false
    private fun launchUpdateCheck(install: Boolean = false) {
        if (updateCheckRunning || settingsBusy.value) return
        updateCheckRunning = true
        settingsBusy.value = true
        settingsFeedback.value = if (install) BifrostUiText.downloadingUpdate else BifrostUiText.checkingUpdate
        lifecycleScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { runCatching { updates.checkAndStage(stageArtifacts = install) { done, total ->
                    runOnUiThread { if (updateCheckRunning) settingsFeedback.value = "正在下载更新 · ${done * 100 / total}%" }
                } } }
            } finally {
                updateCheckRunning = false
                settingsBusy.value = false
            }
            settingsFeedback.value = result.fold(
                { BifrostUiErrorMapper.success(BifrostUiText.updateAction, it.state) },
                {
                    android.util.Log.w("BifrostUpdate", "checkFailed=${BifrostUiErrorMapper.code(it)} type=${it.javaClass.simpleName}")
                    BifrostDiagnostics.record(this@MainActivity, "update-check-failed", it)
                    BifrostUiErrorMapper.message(BifrostUiText.updateAction, it)
                },
            )
            val available = result.getOrNull()
            if (available?.state == "available" && available.sequence != lastPromptedUpdate && !isFinishing) {
                lastPromptedUpdate = available.sequence
                updatePrompt = true
                return@launch
            }
            if (result.getOrNull()?.state == "permission-required") {
                pendingUpdatePermission = true
                runCatching { updates.installPermissionIntent()?.let(::startActivity) }
                    .onFailure { status.value = BifrostUiErrorMapper.message(BifrostUiText.installPermissionAction, it) }
            }
            status.value = result.fold(
                { BifrostUiErrorMapper.success(BifrostUiText.updateAction, it.state) },
                { BifrostUiErrorMapper.message(BifrostUiText.updateAction, it) },
            )
        }
    }

    private fun resumeAfterPackageUpdate() {
        BifrostUpdateResume.start(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra("bifrost.quick.disconnect", false)) stopVpnService()
        handleQuickConnect()
    }

    private fun handleQuickConnect() {
        if (intent.getBooleanExtra(BifrostAutomaticUpdate.EXTRA_UPDATE, false)) {
            intent.removeExtra(BifrostAutomaticUpdate.EXTRA_UPDATE)
            updatePrompt = true
        }
        if (!intent.getBooleanExtra(BifrostQuickTileService.EXTRA_CONNECT, false)) return
        intent.removeExtra(BifrostQuickTileService.EXTRA_CONNECT)
        if (BifrostRuntimeStatus.current.state != BifrostLeakState.STOPPED ||
            BifrostServiceOwnershipRegistry.current() != null || pendingConnection != null) return
        lifecycleScope.launch {
            val account = withContext(Dispatchers.IO) { runCatching { control.accountSnapshot() } }
            if (!account.getOrNull().let { it?.enrolled == true }) {
                refreshDisplayAccount()
                status.value = account.exceptionOrNull()?.let {
                    BifrostUiErrorMapper.message(BifrostUiText.deviceKeys, it)
                } ?: BifrostUiText.needsActivation
                return@launch
            }
            if (isFinishing || isDestroyed || pendingConnection != null ||
                BifrostRuntimeStatus.current.state != BifrostLeakState.STOPPED) return@launch
            connectSelection(selectedMode, selectedCore, selectedSource.ifBlank { sources.value.firstOrNull().orEmpty() },
                selectedCountry, selectedFrontSource, selectedAppPolicy, selectedAppPolicyEnabled,
                includeApplications, excludeApplications, manualCandidateMode, manualCandidate)
        }
    }

    private fun refreshDisplayAccount() {
        val generation = ++displayGeneration
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { control.accountSnapshot() } }
            if (generation != displayGeneration) return@launch
            accountDisplay = accountDisplay.accept(result)
            accountDisplay.snapshot?.let { snapshot ->
                displayEnrolled = snapshot.enrolled
                displayHasRecovery = snapshot.hasRecovery
                displayPublicId = snapshot.publicId
            }
            result.onFailure {
                BifrostDiagnostics.record(this@MainActivity, "account-read-failed", it)
            }
            if (accountDisplay.ready && displayEnrolled && activityVisible) requestNotificationPermission()
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        runCatching {
            val preferences = getSharedPreferences("node-update-notifications", MODE_PRIVATE)
            if (!preferences.getBoolean("permission_requested", false)) {
                preferences.edit().putBoolean("permission_requested", true).apply()
                if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
                    requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1002)
            }
        }.onFailure { BifrostDiagnostics.record(this, "notification-permission-failed", it) }
    }

    private fun shareDiagnostics() {
        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) { BifrostDiagnostics.report(this@MainActivity) }
            runCatching {
                startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, report)
                }, "分享运行诊断"))
            }.onFailure { status.value = "暂时无法打开分享，请稍后重试" }
        }
    }

    private fun refreshOptions() {
        refreshDisplayAccount()
        val loaded = runCatching { BifrostConfigStore.load(this) }.getOrElse {
            clearSourceAuthority()
            status.value = BifrostUiErrorMapper.message(BifrostUiText.configAction, it)
            return
        }
        displayContent = loaded?.content
        hasConfig.value = loaded != null
        if (loaded == null) {
            clearSourceAuthority()
            return
        }
        runCatching {
            val config = JSONObject(loaded.content)
            val authority = BifrostSourceAuthority.fromVerifiedConfig(config.toString())
            val applied = applySourceAuthority(authority)
            if (!applied.accepted && applied.persistenceOk) status.value = BifrostUiText.configSourceInvalidated
            reconcileManualCandidate(loaded.content)
            // Merely re-reading the same signed configuration must not retire
            // a connection receipt captured while the network refresh ran.
            // The coordinator advances its generation when verified inputs
            // actually change; explicit re-tests still force a new round.
            candidateProbeCoordinator.refreshNow(selectedSource.takeIf { it.isNotBlank() && !it.equals("auto", true) }, forceTransition = false)
            val countryArray = config.optJSONArray("countries")
            countries.value = listOf("auto") + (if (countryArray == null) emptyList() else
                (0 until countryArray.length())
                    .mapNotNull { countryArray.optJSONObject(it)?.optString("code") }
                    .distinct())
        }.onFailure {
            clearSourceAuthority()
            status.value = BifrostUiErrorMapper.message(BifrostUiText.configAction, it)
        }
    }

    private fun clearSourceAuthority() {
        displayContent = null
        refreshDisplayAccount()
        applySourceAuthority(null)
    }

    private fun reconcileManualCandidate(content: String) {
        if (manualCandidateMode != "manual" || selectedSource.isBlank()) return
        val stillSigned = BifrostCandidateSelectionContract.candidateOptions(content, selectedSource)
            .any { it.label == manualCandidate }
        if (!stillSigned) {
            manualCandidateMode = "auto"
            manualCandidate = null
            uiPut(mapOf("candidate_mode" to "auto", "candidate_label" to null))
        }
    }

    /** Atomically converges verified options, persisted selection, UI state and owner demand. */
    private fun applySourceAuthority(
        authority: BifrostSourceAuthority?,
        requestedSource: String? = null,
        persistSelection: Boolean = false,
    ): BifrostSourceAuthorityApplyResult {
        val current = BifrostSourceAuthorityState(
            hasConfig = hasConfig.value,
            sources = sources.value,
            frontSources = frontSources.value,
            selectedSource = selectedSource,
            selectedCandidate = observedCandidate,
        )
        val result = sourceAuthorityController.apply(current, authority, requestedSource, persistSelection)
        hasConfig.value = result.state.hasConfig
        sources.value = result.state.sources
        frontSources.value = result.state.frontSources
        selectedSource = result.state.selectedSource
        observedCandidate = result.state.selectedCandidate
        if (!result.accepted) {
            manualCandidateMode = "auto"
            manualCandidate = null
            uiPut(mapOf("candidate_mode" to "auto", "candidate_label" to null))
        }
        return result
    }

    private fun requestVpn(pending: PendingConnection) {
        if (isFinishing || isDestroyed || pendingConnection?.token() != pending.token() ||
            !connectionTransactionGate.isActive(pending.token())) return
        // Another VPN can forbid physical socket binding. Obtain the platform
        // handoff before probing; otherwise every candidate fails before dial.
        val permissionIntent = runCatching {
            if (BifrostFeaturePreferences.rootMode(this)) null else VpnService.prepare(this)
        }.getOrElse {
            discardPending(pending, BifrostUiErrorMapper.code(it))
            status.value = BifrostUiErrorMapper.message(BifrostUiText.vpnPermission, it)
            return
        }
        if (permissionIntent != null) {
            probeHandler.removeCallbacks(connectionTimeout)
            vpnPermissionLauncher.launch(permissionIntent)
            return
        }
        if (pending.selectionReceipt == null) {
            val cached = runCatching { BifrostConfigStore.load(this) }.getOrNull()
            if (cached == null) {
                discardPending(pending, "BF-CONFIG-CACHE-MISSING")
                return
            }
            // Automatic mode already starts the native URLTest group containing
            // every signed candidate. Its data-plane gate proves connectivity.
            // Resolve a signed seed through the same generation-bound receipt
            // path as a manual selection; do not serialize a second full sweep
            // of Java TLS probes before the core can even start.
            val requestedSeed = if (pending.candidateMode == "manual") pending.manualCandidate else {
                val sources = JSONObject(cached.content).getJSONArray("sources")
                (0 until sources.length()).map { sources.getJSONObject(it) }
                    .first { it.getString("code").equals(pending.source, true) }
                    .getJSONArray("candidates").getJSONObject(0).getString("label")
            }
            lifecycleScope.launch {
                val receipt = withContext(Dispatchers.IO) {
                    runCatching {
                        withTimeout(connectionProbeBudget(pending.source)) {
                            awaitCandidateResult(
                                pending.source,
                                requestedSeed,
                            )
                        }
                    }.getOrElse { Result.failure(it) }
                }
                if (pendingConnection?.token() != pending.token() ||
                    !connectionTransactionGate.isActive(pending.token())) return@launch
                receipt.onFailure {
                    if (discardPending(pending, BifrostUiErrorMapper.code(it)))
                        status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, it)
                }.onSuccess { selected ->
                    val resolved = pending.copy(
                        candidate = selected.label,
                        selectionReceipt = selected,
                    )
                    pendingConnection = resolved
                    requestVpn(resolved)
                }
            }
            return
        }
        if (!selectionReceiptCurrent(pending)) {
            discardPending(pending, "BF-PROBE-BINDING-CHANGED")
            return
        }
        pendingConnection = pending
        runCatching {
            val permissionIntent = if (BifrostFeaturePreferences.rootMode(this)) null else VpnService.prepare(this)
            if (permissionIntent != null) {
                vpnPermissionLauncher.launch(permissionIntent)
            } else {
                commitAndStart(pending)
            }
        }.onFailure {
            discardPending(pending, BifrostUiErrorMapper.code(it))
            status.value = BifrostUiErrorMapper.message(BifrostUiText.vpnPermission, it)
        }
    }

    private suspend fun awaitCandidateResult(source: String, requested: String?): Result<BifrostCandidateSelectionReceipt> =
        suspendCancellableCoroutine { continuation ->
            val requestRef = AtomicReference<BifrostConnectionProbeRequest?>(null)
            val request = candidateProbeCoordinator.selectForConnection(source, requested) { result ->
                if (continuation.isActive) continuation.resume(result)
                requestRef.get()?.let { pendingCandidateRequest.compareAndSet(it, null) }
            }
            requestRef.set(request)
            pendingCandidateRequest.set(request)
            if (!continuation.isActive) {
                pendingCandidateRequest.compareAndSet(request, null)
                request.close()
            }
            continuation.invokeOnCancellation {
                requestRef.get()?.close()
                pendingCandidateRequest.compareAndSet(request, null)
            }
        }

    /** Re-read verified authority and network immediately before every
     * permission/service boundary.  A label is accepted only when its exact
     * immutable selector binding and generation are still current. */
    private fun selectionReceiptCurrent(pending: PendingConnection): Boolean {
        val receipt = pending.selectionReceipt ?: return false
        if (receipt.label != pending.candidate ||
            !receipt.binding.source.equals(pending.source, true)) return false
        val cached = runCatching { BifrostConfigStore.load(this) }.getOrNull() ?: return false
        val input = runCatching {
            BifrostProbeFingerprints.input(cached, pending.source, AndroidNetworkBucket.fingerprint(this))
        }.getOrNull() ?: return false
        val generation = candidateProbeCoordinator.captureConnectionGeneration(input)
        if (!receipt.matches(input, generation)) {
            val expected = BifrostProbeConnectionBinding.from(input, generation)
            android.util.Log.w("BifrostConnectionDiagnostic", "receiptMismatch source=${receipt.binding.source == expected.source} network=${receipt.binding.networkFingerprint == expected.networkFingerprint} version=${receipt.binding.configVersion == expected.configVersion} digest=${receipt.binding.configDigest == expected.configDigest} candidates=${receipt.binding.candidateFingerprint == expected.candidateFingerprint} transport=${receipt.binding.transportFingerprint == expected.transportFingerprint} generation=${receipt.binding.generation}/$generation")
            return false
        }
        val sourceObject = runCatching {
            val root = JSONObject(cached.content)
            (0 until (root.optJSONArray("sources")?.length() ?: 0))
                .asSequence()
                .mapNotNull { root.optJSONArray("sources")?.optJSONObject(it) }
                .firstOrNull { it.optString("code").equals(pending.source, true) }
        }.getOrNull() ?: return false
        val candidates = sourceObject.optJSONArray("candidates") ?: return false
        return (0 until candidates.length()).any { index ->
            candidates.optJSONObject(index)?.optString("label") == receipt.label
        }
    }

    private fun cancelPendingCandidateRequest() {
        pendingCandidateRequest.getAndSet(null)?.close()
    }

    /** Commit UI state only after every validation/update/permission gate passed. */
    private fun commitAndStart(pending: PendingConnection) {
        if (pendingConnection?.token() != pending.token() ||
            !connectionTransactionGate.isActive(pending.token())) return
        if (!selectionReceiptCurrent(pending)) {
            discardPending(pending, "BF-PROBE-BINDING-CHANGED")
            return
        }
        // Keep the pending capability until the service has acknowledged the
        // same transaction, digest, generation and package-image bindings.
        val selectedSnapshot = runCatching {
            BifrostApplicationPolicy.verify(pending.snapshot)
        }.getOrElse { error ->
            discardPending(pending, BifrostUiErrorMapper.code(error))
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationPackage, error)
            return
        }
        val selectedBindings = runCatching {
            applicationPolicyCoordinator.validate(selectedSnapshot, pending.bindings)
        }.getOrElse { error ->
            discardPending(pending, BifrostUiErrorMapper.code(error))
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationPackage, error)
            return
        }
        val encodedBindings = runCatching {
            BifrostApplicationPackageBindings.encode(selectedBindings)
        }.getOrElse { error ->
            discardPending(pending, BifrostUiErrorMapper.code(error))
            status.value = BifrostUiErrorMapper.message(BifrostUiText.applicationPackage, error)
            return
        }
        if (pendingConnection?.token() != pending.token()) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.storageAction, IllegalArgumentException("BF-APP-PERSIST"))
            return
        }
        startVpnService(pending, selectedSnapshot, encodedBindings)
    }

    private fun startVpnService(
        pending: PendingConnection,
        selectedSnapshot: BifrostApplicationPolicySnapshot,
        encodedBindings: String,
    ) {
        if (pendingConnection?.token() != pending.token() ||
            !connectionTransactionGate.isActive(pending.token())) return
        val pendingSelection = runCatching {
            BifrostConnectionRouteContract.parse(pending.connectionType, pending.routeMode)
        }.getOrElse {
            discardPending(pending, "BF-CONNECTION-TYPE")
            return
        }
        if (selectedSnapshot.routeMode != pendingSelection.routeMode.wireValue ||
            pendingSelection.connectionType.wireValue != pending.connectionType) {
            discardPending(pending, "BF-APP-POLICY-SNAPSHOT")
            status.value = BifrostUiErrorMapper.message(
                BifrostUiText.applicationRoutingPolicy,
                IllegalArgumentException("BF-APP-POLICY-SNAPSHOT"),
            )
            return
        }
        runCatching {
            // Use only the immutable values captured by this transaction. A
            // later UI edit cannot change the Intent after validation.
            val intent = Intent(this, BifrostVpnService::class.java)
                .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, pending.transactionId)
                .putExtra(BifrostVpnService.EXTRA_CORE, pending.core)
                .putExtra(BifrostVpnService.EXTRA_MODE, selectedSnapshot.routeMode)
                .putExtra(BifrostVpnService.EXTRA_CONNECTION_TYPE, pendingSelection.connectionType.wireValue)
                .putExtra(BifrostVpnService.EXTRA_ROUTE_MODE, pendingSelection.routeMode.wireValue)
                .putExtra(BifrostVpnService.EXTRA_SOURCE, pending.source)
                .putExtra(BifrostVpnService.EXTRA_COUNTRY, pending.country)
                .putExtra(BifrostVpnService.EXTRA_FRONT_SOURCE, pending.frontSource.takeIf { it != "auto" })
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE, pending.candidate)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_MODE, pending.candidateMode)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_NETWORK, pending.selectionReceipt?.binding?.networkFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_CONFIG_VERSION, pending.selectionReceipt?.binding?.configVersion ?: 0L)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_CONFIG_DIGEST, pending.selectionReceipt?.binding?.configDigest)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_FINGERPRINT, pending.selectionReceipt?.binding?.candidateFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_TRANSPORT_FINGERPRINT, pending.selectionReceipt?.binding?.transportFingerprint)
                .putExtra(BifrostVpnService.EXTRA_CANDIDATE_GENERATION, pending.selectionReceipt?.binding?.generation ?: 0L)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, selectedSnapshot.digest)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, selectedSnapshot.generation)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, encodedBindings)
                .putExtra(BifrostVpnService.EXTRA_ACK_RECEIVER, vpnAckReceiver)
            if (!connectionTransactionGate.markServiceDispatched(pending.token())) return
            // Node probing has its own timeout. Give the actual core/TUN
            // startup a full deadline instead of only the probe's remainder.
            probeHandler.removeCallbacks(connectionTimeout)
            probeHandler.postDelayed(connectionTimeout, 315_000L)
            startForegroundService(intent)
        }.onFailure {
            failPendingConnection(pending, BifrostUiErrorMapper.code(it))
            status.value = BifrostUiErrorMapper.message("VPN", it)
        }
    }

    /** Commit preferences and selected state only after the service has
     * established the TUN and returned a matching readback acknowledgement. */
    private fun handleVpnAck(resultCode: Int, data: Bundle?) {
        if (resultCode == BifrostVpnService.RESULT_DISCONNECTED || resultCode == BifrostVpnService.RESULT_STATUS) {
            handleDisconnectOrStatusAck(resultCode, data)
            return
        }
        val pending = pendingConnection ?: return
        handleVpnAckTransaction(resultCode, data, pending)
        return
    }

    private fun handleDisconnectOrStatusAck(resultCode: Int, data: Bundle?) {
        val expected = pendingDisconnect ?: return
        val transactionId = data?.getString(BifrostVpnService.EXTRA_TRANSACTION_ID)
        val generation = data?.getString(BifrostVpnService.EXTRA_ACK_GENERATION)
        val digest = data?.getString(BifrostVpnService.EXTRA_ACK_DIGEST)
        val bindings = data?.getString(BifrostVpnService.EXTRA_ACK_BINDINGS)
        val releaseEpoch = data?.getLong(BifrostVpnService.EXTRA_ACK_RELEASE_EPOCH, -1L) ?: -1L
        if (transactionId != expected.transactionId ||
            generation != expected.generation ||
            digest != expected.digest ||
            bindings != expected.bindings) return

        val idle = data?.getBoolean(BifrostVpnService.EXTRA_ACK_IDLE, false) == true
        val phase = data?.getString(BifrostVpnService.EXTRA_ACK_PHASE)
        val serviceToken = BifrostServiceTransactionToken(
            expected.transactionId,
            expected.generation,
            expected.digest,
            expected.bindings,
        )
        val exactLive = BifrostServiceOwnershipRegistry.current()?.let { live ->
            BifrostConnectionTransactionToken(
                live.token.transactionId,
                live.token.generation,
                live.token.digest,
                live.token.bindings,
            )
        }
        if (resultCode == BifrostVpnService.RESULT_STATUS && !idle) {
            if (exactLive != expected && phase != BifrostServiceOwnershipPhase.IDLE.name) {
                scheduleDisconnectReconciliation(expected)
                return
            }
        }
        if (!idle && resultCode != BifrostVpnService.RESULT_DISCONNECTED) {
            scheduleDisconnectReconciliation(expected)
            return
        }
        if (exactLive != null && exactLive != expected) {
            // Never claim IDLE while another transaction owns the Service.
            scheduleDisconnectReconciliation(expected)
            return
        }
        val receipt = BifrostServiceOwnershipRegistry.releaseReceipt(serviceToken)
        if (!idle || releaseEpoch <= 0L || receipt == null || receipt.epoch != releaseEpoch ||
            !BifrostServiceOwnershipRegistry.consumeReleaseReceipt(serviceToken, releaseEpoch)) {
            scheduleDisconnectReconciliation(expected)
            return
        }
        if (connectionTransactionGate.releaseDisconnectExact(expected) ||
            connectionTransactionGate.completeDiscoveredRelease(expected)) {
            pendingDisconnect = null
            disconnectAttempts = 0
            probeHandler.removeCallbacks(disconnectReconcile)
            BifrostServiceOwnershipRegistry.clearDisconnect(serviceToken)
            BifrostApplicationPolicySnapshotRegistry.remove(expected.transactionId)
            if (pendingConnection?.token() == expected) pendingConnection = null
            blockedConnection = blockedConnection?.takeUnless { it.token() == expected }
            selectedTransactionId = selectedTransactionId.takeUnless { it == expected.transactionId }
            status.value = connectionFailure?.takeIf { it.first == expected }?.second?.let {
                BifrostUiErrorMapper.message(BifrostUiText.vpnAction, IllegalArgumentException(it))
            } ?: BifrostUiText.vpnDisconnected
        }
    }

    private fun handleVpnAckTransaction(
        resultCode: Int,
        data: Bundle?,
        pending: PendingConnection,
    ) {
        val code = data?.getString(BifrostVpnService.EXTRA_ACK_CODE) ?: "BF-SERVICE-ACK"
        val decision = connectionTransactionGate.acknowledge(
            transactionId = data?.getString(BifrostVpnService.EXTRA_TRANSACTION_ID).orEmpty(),
            ready = resultCode == BifrostVpnService.RESULT_READY,
            digest = data?.getString(BifrostVpnService.EXTRA_ACK_DIGEST),
            generation = data?.getString(BifrostVpnService.EXTRA_ACK_GENERATION),
            bindings = data?.getString(BifrostVpnService.EXTRA_ACK_BINDINGS),
            failureCode = code,
            blockedFailure = data?.getBoolean(BifrostVpnService.EXTRA_ACK_BLOCKED, false) == true,
        )
        when (decision) {
            BifrostConnectionAckDecision.Ignored -> return
            is BifrostConnectionAckDecision.Failed -> {
                connectionFailure = pending.token() to decision.code
                probeHandler.removeCallbacks(connectionTimeout)
                cancelPendingCandidateRequest()
                BifrostApplicationPolicySnapshotRegistry.remove(pending.transactionId)
                if (decision.blocked && decision.token == pending.token()) {
                    blockedConnection = pending
                    if (pendingConnection?.token() == pending.token()) pendingConnection = null
                } else {
                    if (pendingConnection?.token() == pending.token()) pendingConnection = null
                    if (decision.compensate) sendScopedDisconnect(pending)
                }
                status.value = BifrostUiErrorMapper.message("VPN", IllegalArgumentException(decision.code))
                return
            }
            is BifrostConnectionAckDecision.Ready -> Unit
        }

        val expectedBindings = decision.let { (it as BifrostConnectionAckDecision.Ready).token.bindings }
        val decoded = runCatching { BifrostApplicationPackageBindings.decode(expectedBindings) }.getOrElse {
            failPendingConnection(pending, "BF-APP-PACKAGE-INVALID")
            return
        }
        if (decoded != pending.bindings) {
            failPendingConnection(pending, "BF-APP-PACKAGE-INVALID")
            return
        }
        val live = BifrostServiceOwnershipRegistry.current()
        val liveToken = live?.let {
            BifrostConnectionTransactionToken(it.token.transactionId, it.token.generation, it.token.digest, it.token.bindings)
        }
        val descriptionKeys = listOf(
            BifrostVpnService.EXTRA_ACK_CORE,
            BifrostVpnService.EXTRA_ACK_MODE,
            BifrostVpnService.EXTRA_ACK_SOURCE,
            BifrostVpnService.EXTRA_ACK_COUNTRY,
            BifrostVpnService.EXTRA_ACK_FRONT_SOURCE,
            BifrostVpnService.EXTRA_ACK_CANDIDATE,
            BifrostVpnService.EXTRA_ACK_CONNECTION_TYPE,
        )
        val completeAckDescription = data != null && descriptionKeys.all(data::containsKey)
        val ackDescription = if (completeAckDescription) {
            BifrostServiceConnectionDescription(
                core = data?.getString(BifrostVpnService.EXTRA_ACK_CORE).orEmpty(),
                mode = data?.getString(BifrostVpnService.EXTRA_ACK_MODE).orEmpty(),
                source = data?.getString(BifrostVpnService.EXTRA_ACK_SOURCE).orEmpty(),
                country = data?.getString(BifrostVpnService.EXTRA_ACK_COUNTRY).orEmpty(),
                frontSource = data?.getString(BifrostVpnService.EXTRA_ACK_FRONT_SOURCE).orEmpty(),
                candidate = data?.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE),
                connectionType = data?.getString(BifrostVpnService.EXTRA_ACK_CONNECTION_TYPE).orEmpty(),
            )
        } else null
        val expectedDescription = BifrostServiceConnectionDescription(
            core = pending.core,
            mode = pending.mode,
            source = pending.source,
            country = pending.country,
            frontSource = pending.frontSource,
            candidate = pending.candidate,
            connectionType = pending.connectionType,
        )
        val liveDescriptionMatches = live != null && BifrostServiceConnectionMetadata.matches(expectedDescription, live.description)
        val receipt = pending.selectionReceipt
        val receiptAckMatches = receipt != null && data != null &&
            data.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE_NETWORK) == receipt.binding.networkFingerprint &&
            data.getLong(BifrostVpnService.EXTRA_ACK_CANDIDATE_CONFIG_VERSION, 0L) == receipt.binding.configVersion &&
            data.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE_CONFIG_DIGEST) == receipt.binding.configDigest &&
            data.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE_FINGERPRINT) == receipt.binding.candidateFingerprint &&
            data.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE_TRANSPORT_FINGERPRINT) == receipt.binding.transportFingerprint &&
            data.getLong(BifrostVpnService.EXTRA_ACK_CANDIDATE_GENERATION, 0L) == receipt.binding.generation
        if (liveToken != pending.token() || live?.phase != BifrostServiceOwnershipPhase.COMMITTED ||
            !completeAckDescription || !BifrostServiceConnectionMetadata.complete(ackDescription,
                BifrostServiceConnectionMetadata.REQUIRED_FIELDS) ||
            !BifrostServiceConnectionMetadata.matches(live?.description, ackDescription) || !liveDescriptionMatches ||
            !receiptAckMatches) {
            failPendingConnection(pending, "BF-CONNECTION-ACK")
            return
        }
        val values = mapOf(
            "mode" to pending.uiMode,
            "connection_type" to pending.connectionType,
            "route_mode" to pending.routeMode,
            "app_policy_enabled" to pending.appPolicyEnabled.toString(),
            "core" to pending.core,
            "source" to pending.source,
            "country" to pending.country,
            "front_source" to pending.frontSource,
            "candidate_mode" to pending.candidateMode,
            "candidate_label" to pending.manualCandidate,
            "app_policy" to pending.snapshot.policyMode,
            "include_apps" to pending.snapshot.includePackages.joinToString("\n"),
            "exclude_apps" to pending.snapshot.excludePackages.joinToString("\n"),
            "application_policy_snapshot" to pending.snapshot.canonicalJson,
            "application_policy_bindings" to expectedBindings,
            "connection_transaction_id" to pending.transactionId,
        )
        val prior = runCatching { BifrostSecureStore.readBatch(this, uiKeys) }.getOrElse {
            failPendingConnection(pending, "BF-APP-PERSIST")
            return
        }
        if (!uiPutAtomic(values, prior)) {
            failPendingConnection(pending, "BF-APP-PERSIST")
            return
        }
        if (!connectionTransactionGate.commit(pending.token())) {
            restoreUiState(prior)
            // The Service may already own a committed runtime even when this
            // Activity's local commit fence lost a race; compensate only the
            // exact four-field token, never an unscoped service.
            sendScopedDisconnect(pending)
            failPendingConnection(pending, "BF-CONNECTION-ACK")
            return
        }
        selectedMode = pending.uiMode
        selectedConnectionType = pending.connectionType
        selectedRouteMode = pending.routeMode
        selectedAppPolicyEnabled = pending.appPolicyEnabled
        selectedCore = pending.core
        selectedSource = pending.source
        selectedCountry = pending.country
        selectedFrontSource = pending.frontSource
        selectedAppPolicy = pending.snapshot.policyMode
        includeApplications = pending.snapshot.includePackages
        excludeApplications = pending.snapshot.excludePackages
        selectedApplicationPolicy = pending.snapshot
        selectedApplicationBindings = pending.bindings
        manualCandidateMode = pending.candidateMode
        manualCandidate = pending.manualCandidate
        observedCandidate = data?.getString(BifrostVpnService.EXTRA_ACK_CANDIDATE)
            ?: live?.description?.candidate
        selectedTransactionId = pending.transactionId
        probeHandler.removeCallbacks(connectionTimeout)
        pendingConnection = null
        status.value = BifrostUiText.vpnConnected
    }

    private fun onSourceSelected(source: String): Boolean {
        val normalized = source.trim()
        val loaded = runCatching { BifrostConfigStore.load(this) }.getOrElse {
            clearSourceAuthority()
            status.value = BifrostUiErrorMapper.message(BifrostUiText.configAction, it)
            return false
        }
        val authority = loaded?.let {
            runCatching { BifrostSourceAuthority.fromVerifiedConfig(it.content) }.getOrElse { error ->
                clearSourceAuthority()
                status.value = BifrostUiErrorMapper.message(BifrostUiText.configAction, error)
                return false
            }
        }
        if (authority == null) {
            clearSourceAuthority()
            status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, IllegalArgumentException("BF-SOURCE-NOT-READY"))
            return false
        }
        val applied = applySourceAuthority(authority, normalized, persistSelection = true)
        if (!applied.accepted) {
            if (applied.persistenceOk) {
                status.value = BifrostUiErrorMapper.message(BifrostUiText.routeProbeAction, IllegalArgumentException("BF-SOURCE-NOT-READY"))
            }
            return false
        }
        if (manualCandidateMode == "manual" &&
            (manualCandidate.isNullOrBlank() ||
                BifrostCandidateSelectionContract.candidateOptions(loaded!!.content, applied.state.selectedSource)
                    .none { it.label == manualCandidate })) {
            manualCandidateMode = "auto"
            manualCandidate = null
            uiPut(mapOf("candidate_mode" to "auto", "candidate_label" to null))
        }
        status.value = BifrostUiText.routeProbeAction
        return true
    }

    private fun uiPutAtomic(
        values: Map<String, String?>,
        prior: Map<String, String?>? = null,
    ): Boolean {
        val previous = prior ?: runCatching { BifrostSecureStore.readBatch(this, uiKeys) }.getOrElse {
            status.value = BifrostUiText.storageUnavailable
            return false
        }
        return try {
            BifrostSecureStore.putBatch(this, values)
            val after = BifrostSecureStore.readBatch(this, uiKeys)
            if (values.any { (key, value) -> after[key] != value }) {
                throw IllegalStateException("BF-APP-PERSIST")
            }
            refreshDisplayAccount()
            true
        } catch (_: Throwable) {
            restoreUiState(previous)
            status.value = BifrostUiText.storageWriteFailed
            false
        }
    }

    private fun restoreUiState(previous: Map<String, String?>) {
        runCatching {
            BifrostSecureStore.putBatch(this, previous)
            if (BifrostSecureStore.readBatch(this, uiKeys) != previous) {
                throw IllegalStateException("BF-APP-PERSIST")
            }
        }.onFailure { status.value = BifrostUiText.storageRollbackFailed }
    }

    private fun failPendingConnection(pending: PendingConnection, code: String) {
        android.util.Log.w("BifrostConnectionDiagnostic", "pendingFailure=$code")
        if (pendingConnection?.token() == pending.token()) connectionFailure = pending.token() to code
        if (cancelLocalPreparation(pending)) {
            status.value = BifrostUiErrorMapper.message(BifrostUiText.vpnAction, IllegalArgumentException(code))
            return
        }
        val alreadyDisconnecting = connectionTransactionGate.disconnectingToken() == pending.token()
        val matched = connectionTransactionGate.beginDisconnectExact(pending.token())
        probeHandler.removeCallbacks(connectionTimeout)
        cancelPendingCandidateRequest()
        if (pendingConnection?.token() == pending.token()) pendingConnection = null
        // A dispatched start may still be queued on the Service worker. Keep
        // its snapshot until the exact teardown acknowledgement consumes it.
        // A timeout or synchronous launch failure can race a service that has
        // already established the core but whose acknowledgement has not yet
        // reached this Activity.  The exact token is safe to send even before
        // ownership is visible: the service ignores it unless the complete
        // transaction identity matches, while an established matching VPN is
        // always compensated.  Never send for a stale/duplicate callback.
        if (matched && !alreadyDisconnecting) {
            sendScopedDisconnect(pending)
        }
            status.value = BifrostUiErrorMapper.message(BifrostUiText.vpnAction, IllegalArgumentException(code))
    }

    private fun stopVpnService() {
        BifrostRootConnectionIntent.stop(this)
        BifrostSecureStore.put(this, "update_resume_intent", "")
        val pending = pendingConnection
        if (pending != null) {
            if (cancelLocalPreparation(pending)) {
                status.value = BifrostUiText.vpnDisconnected
                return
            }
            if (connectionTransactionGate.beginDisconnectExact(pending.token())) {
                probeHandler.removeCallbacks(connectionTimeout)
                cancelPendingCandidateRequest()
                pendingConnection = null
                sendScopedDisconnect(pending)
            }
            status.value = BifrostUiText.cancellingVpn
            return
        }
        val blocked = blockedConnection
        if (blocked != null && connectionTransactionGate.blockedToken() == blocked.token()) {
            if (connectionTransactionGate.beginDisconnectExact(blocked.token())) {
                sendScopedDisconnect(blocked)
            }
            status.value = BifrostUiText.releasingBlackhole
            return
        }
        val snapshot = selectedApplicationPolicy
        val id = selectedTransactionId
        if (snapshot == null || id.isNullOrBlank()) {
            status.value = BifrostUiText.unsafeSession
            return
        }
        val committedToken = BifrostConnectionTransactionToken(
            id,
            snapshot.generation,
            snapshot.digest,
            BifrostApplicationPackageBindings.encode(selectedApplicationBindings),
        )
        if (connectionTransactionGate.beginDisconnectExact(committedToken)) {
            sendScopedDisconnect(committedToken)
            status.value = BifrostUiText.disconnectingTunnel
        } else {
            status.value = BifrostUiText.unsafeSession
        }
    }

    private fun sendScopedDisconnect(pending: PendingConnection) = sendScopedDisconnect(pending.token())

    private fun cancelLocalPreparation(pending: PendingConnection): Boolean {
        if (!connectionTransactionGate.cancelBeforeServiceDispatch(pending.token())) return false
        probeHandler.removeCallbacks(connectionTimeout)
        cancelPendingCandidateRequest()
        if (pendingConnection?.token() == pending.token()) pendingConnection = null
        BifrostApplicationPolicySnapshotRegistry.remove(pending.transactionId)
        return true
    }

    private fun sendScopedDisconnect(token: BifrostConnectionTransactionToken) {
        if (!token.transactionId.matches(Regex("[0-9a-f]{32}")) ||
            !token.generation.matches(Regex("[0-9a-f]{32}")) ||
            !token.digest.matches(Regex("[0-9a-f]{64}")) ||
            token.bindings.length > 16 * 1024) return
        // If this is a compensation path, move the local owner into the same
        // fenced handshake before delivery.  Restoration may have no local
        // gate yet; in that case the Service registry remains authoritative.
        connectionTransactionGate.beginDisconnectExact(token)
        pendingDisconnect = token
        disconnectAttempts = 0
        BifrostServiceOwnershipRegistry.requestDisconnect(
            BifrostServiceTransactionToken(token.transactionId, token.generation, token.digest, token.bindings),
        )
        sendDisconnectIntent(token)
        scheduleDisconnectReconciliation(token)
    }

    private fun sendDisconnectIntent(token: BifrostConnectionTransactionToken): Boolean = runCatching {
            val intent = Intent(this, BifrostVpnService::class.java)
                .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_DISCONNECT)
                .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, token.transactionId)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, token.generation)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, token.digest)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, token.bindings)
                .putExtra(BifrostVpnService.EXTRA_ACK_RECEIVER, vpnAckReceiver)
            startForegroundService(intent)
        }.isSuccess

    private fun sendStatusIntent(token: BifrostConnectionTransactionToken): Boolean = runCatching {
        val intent = Intent(this, BifrostVpnService::class.java)
            .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_STATUS)
            .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, token.transactionId)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, token.generation)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, token.digest)
            .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, token.bindings)
            .putExtra(BifrostVpnService.EXTRA_ACK_RECEIVER, vpnAckReceiver)
        startForegroundService(intent)
    }.isSuccess

    private fun scheduleDisconnectReconciliation(token: BifrostConnectionTransactionToken) {
        if (pendingDisconnect != token) return
        probeHandler.removeCallbacks(disconnectReconcile)
        probeHandler.postDelayed(disconnectReconcile, 250L)
    }

    private fun reconcileDisconnect(token: BifrostConnectionTransactionToken) {
        if (pendingDisconnect != token) return
        val serviceToken = BifrostServiceTransactionToken(token.transactionId, token.generation, token.digest, token.bindings)
        // A release receipt is the only local proof that may complete a lost
        // acknowledgement.  It is read atomically from the Service registry;
        // a null current owner is never treated as authority.
        BifrostServiceOwnershipRegistry.releaseReceipt(serviceToken)?.let { receipt ->
            handleDisconnectOrStatusAck(
                BifrostVpnService.RESULT_DISCONNECTED,
                Bundle().apply {
                    putString(BifrostVpnService.EXTRA_TRANSACTION_ID, token.transactionId)
                    putString(BifrostVpnService.EXTRA_ACK_GENERATION, token.generation)
                    putString(BifrostVpnService.EXTRA_ACK_DIGEST, token.digest)
                    putString(BifrostVpnService.EXTRA_ACK_BINDINGS, token.bindings)
                    putBoolean(BifrostVpnService.EXTRA_ACK_IDLE, true)
                    putLong(BifrostVpnService.EXTRA_ACK_RELEASE_EPOCH, receipt.epoch)
                },
            )
            return
        }
        val live = BifrostServiceOwnershipRegistry.current()
        if (live != null && live.token == serviceToken) {
            disconnectAttempts++
            sendDisconnectIntent(token)
        } else {
            // A newer/different owner or an absent owner is not proof of
            // release. Query the Service, then keep the exact gate fenced.
            disconnectAttempts++
            sendStatusIntent(token)
        }
        if (disconnectAttempts >= 3) {
            probeHandler.removeCallbacks(disconnectReconcile)
            status.value = BifrostUiText.disconnectUnknown
            return
        }
        scheduleDisconnectReconciliation(token)
    }

    private fun uiGet(key: String, default: String = ""): String = try {
        BifrostSecureStore.get(this, key, default)
    } catch (_: Throwable) {
        status.value = BifrostUiText.storageUnavailable
        default
    }

    private fun uiPut(values: Map<String, String?>): Boolean = uiPutAtomic(values)
}
