package com.bifrost.client

import com.bifrost.client.ui.model.BifrostUiText

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.provider.Settings
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Foreground owner for the libbox-controlled Android TUN lifecycle. */
class BifrostVpnService : VpnService() {
    internal var rootTunnel: BifrostRootBoundary? = null
        private set
    private lateinit var core: BifrostCoreRuntime
    private val candidateProbeCoordinator by lazy {
        (application as BifrostApplication).candidateProbeCoordinator
    }
    private var serviceProbeLease: java.io.Closeable? = null
    @Volatile private var serviceAlive = false
    private val commandExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "bifrost-vpn-commands").apply { isDaemon = true }
    }
    private var runtimeStatusListener: AutoCloseable? = null
    private var notificationRefresh: ScheduledFuture<*>? = null
    @Volatile private var notificationStatus = BifrostUiText.notificationPreparing
    @Volatile private var lastNotificationText = ""
    @Volatile private var lastNotificationAt = 0L
    private var rootRecovery: ScheduledFuture<*>? = null
    // Legacy helpers below are retained for binary/source compatibility; the
    // injected coordinator watchdog is the only active health monitor.
    private var healthRefresh: ScheduledFuture<*>? = null
    private lateinit var blackhole: BifrostBlackholeController
    private lateinit var boundary: BifrostLeakBoundary
    private lateinit var runtime: BifrostRuntimeCoordinator
    @Volatile private var leakSnapshot = BifrostLeakGuard.stopped()
    private val transactionOwnership = BifrostServiceTransactionOwnership()
    private val coreFailureHandling = AtomicBoolean(false)
    private val healthExecutor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "bifrost-core-watchdog").apply { isDaemon = true }
    }
    private val runtimeWatchdog = object : BifrostRuntimeWatchdog {
        @Volatile private var task: ScheduledFuture<*>? = null

        override fun start(onCoreFailure: () -> Unit) {
            stop()
            var healthFailures = 0
            var lastCheck = android.os.SystemClock.elapsedRealtime()
            task = healthExecutor.scheduleWithFixedDelay({
                if (::core.isInitialized && ::runtime.isInitialized &&
                    runtime.snapshot.state == BifrostLeakState.HEALTHY) {
                    val rootRemote = rootTunnel as? BifrostRootRemote
                    if (rootRemote != null) {
                        when (rootRemote.sessionState()) {
                            BifrostRootSessionState.READY -> Unit
                            BifrostRootSessionState.OWNER_NOT_READY,
                            BifrostRootSessionState.UNREACHABLE ->
                                runCatching { startForeground(1001, notification("正在恢复后台连接")) }
                            BifrostRootSessionState.EMPTY,
                            BifrostRootSessionState.STALE_EPOCH ->
                                handleMissingRootRuntime(rootRemote)
                        }
                    } else if (!core.isReady()) {
                        onCoreFailure()
                    }
                    else if (BifrostMaintenancePolicy.shouldProbe(
                        android.os.SystemClock.elapsedRealtime(), lastCheck, BifrostAppVisibility.visible,
                        getSystemService(android.os.PowerManager::class.java).isInteractive,
                        BifrostTrafficTelemetry.lastReceiveAt, BifrostTrafficTelemetry.lastSendAt, healthFailures,
                        BifrostTrafficTelemetry.lastTransportFailureAt)) {
                        lastCheck = android.os.SystemClock.elapsedRealtime()
                        if (core.isDataPlaneHealthy()) healthFailures = 0
                        else {
                            healthFailures++
                            core.refreshOutboundHealth()
                            // A remote health URL cannot prove the core died.
                            // Keep its verified TUN/routing boundary installed
                            // so native URLTest can recover after an outage.
                            // Actual core death still takes onCoreFailure above.
                            if (healthFailures == 3) runCatching {
                                startForeground(1001, notification("线路暂不可达，正在自动重试"))
                            }
                        }
                    }
                }
            }, 5, 5, TimeUnit.SECONDS)
        }

        override fun stop() {
            task?.cancel(false)
            task = null
        }
    }

    /** Recover only after the Root service itself proves this epoch has no
     * owner.  A normal Binder/network timeout never reaches this path. */
    private fun handleMissingRootRuntime(remote: BifrostRootRemote) {
        if (!coreFailureHandling.compareAndSet(false, true)) return
        val epoch = remote.epoch
        if (!BifrostRootConnectionIntent.matches(this, epoch)) return
        val owner = BifrostServiceOwnershipRegistry.current()
        val token = owner?.token ?: transactionOwnership.committedToken()
            ?: transactionOwnership.pendingToken()
            ?: transactionOwnership.blockedToken()
            ?: transactionOwnership.unprotectedToken()
        if (token != null) {
            transactionOwnership.abandonMissingRuntime(token)
            BifrostServiceOwnershipRegistry.retireMissingRuntimeInternal(token)
            BifrostApplicationPolicySnapshotRegistry.remove(token.transactionId)
        }
        stopCandidateRefresh()
        leakSnapshot = runtime.ownerLost().let { runtime.snapshot }
        BifrostDiagnostics.record(this, "root-owner-lost")
        runCatching { startForeground(1001, notification(BifrostUiText.unprotectedState)) }
        runCatching {
            startForegroundService(Intent(this, BifrostQuickConnectService::class.java)
                .putExtra(EXTRA_RECOVERY_EPOCH, epoch))
        }.onFailure { BifrostDiagnostics.record(this, "root-owner-recovery-dispatch", it) }
    }

    override fun onCreate() {
        super.onCreate()
        serviceAlive = true
        core = BifrostCoreAdapter(this, this)
        blackhole = AndroidBlackholeController()
        boundary = BifrostLeakBoundary(blackhole)
        runtime = BifrostRuntimeCoordinator(boundary, { core.stop() }, ::lockdownEvidence, runtimeWatchdog)
        leakSnapshot = runtime.snapshot
        createNotificationChannel()
        startForeground(1001, notification(BifrostUiText.notificationPreparing))
        notificationRefresh = nodeConfigurationRefresh.scheduleWithFixedDelay({
            if (serviceAlive && BifrostServiceOwnershipRegistry.current() != null) {
                val now = android.os.SystemClock.elapsedRealtime()
                val interactive = getSystemService(android.os.PowerManager::class.java).isInteractive
                if (interactive || now - lastNotificationAt >= 30_000L) runCatching {
                    (core as? BifrostRootRemote)?.refreshTelemetry()
                    val text = liveNotificationText(notificationStatus)
                    if (text != lastNotificationText) {
                        getSystemService(NotificationManager::class.java).notify(1001, notification(notificationStatus))
                    }
                }
            }
        }, 2, 2, TimeUnit.SECONDS)
        nodeConfigurationRefresh.scheduleWithFixedDelay({
            // Update signed configuration for the next connection. The live
            // tunnel remains pinned to its verified connection transaction.
            if (BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY &&
                (rootTunnel != null || BifrostAppVisibility.visible) && getSystemService(android.os.PowerManager::class.java).isInteractive &&
                BifrostMaintenancePolicy.claimConfigRefresh(android.os.SystemClock.elapsedRealtime())) runCatching {
                val control = BifrostControlClient(applicationContext)
                if (control.isEnrolled()) control.refresh()
            }.onFailure { error ->
                if (error is BifrostDeviceRevokedException) {
                    BifrostRootConnectionIntent.stop(this)
                    onCoreServiceStop()
                }
            }
        }, 15, 15, java.util.concurrent.TimeUnit.MINUTES)
        runtimeStatusListener = BifrostRuntimeStatus.addListener { snapshot ->
            BifrostQuickTileService.refresh(this)
            // The coordinator is the source of truth for both the Activity
            // and the foreground notification. A watchdog failure must turn
            // the notification red even without a libbox serviceStop callback.
            leakSnapshot = snapshot
            if (snapshot.state == BifrostLeakState.BLOCKING ||
                snapshot.state == BifrostLeakState.UNPROTECTED ||
                snapshot.state == BifrostLeakState.ERROR) {
                coreFailureHandling.set(true)
                stopCandidateRefresh()
                runCatching {
                    startForeground(1001, notification(
                        if (snapshot.state == BifrostLeakState.BLOCKING)
                            BifrostUiText.coreBlocked
                        else
                            BifrostUiText.coreUnprotected,
                    ))
                }
                if (rootTunnel != null) scheduleRootRecovery()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Android invokes this on the main thread. Native startup, TLS and
        // teardown must not block input or foreground-service callbacks.
        if (intent?.getStringExtra(EXTRA_ACTION) == ACTION_DISCONNECT) {
            val token = serviceToken(intent)
            val epoch = intent.getStringExtra(EXTRA_RECOVERY_EPOCH)
            if (token != null && BifrostServiceOwnershipRegistry.current()?.token == token &&
                (epoch == null || !BifrostRootConnectionIntent.matches(this, epoch))) {
                BifrostRootConnectionIntent.stop(this)
                rootRecovery?.cancel(false)
            }
        }
        if (intent == null) {
            val epoch = BifrostRootConnectionIntent.current(this)
            if (epoch != null) {
                BifrostDiagnostics.record(this, "root-service-restoring")
                runCatching { startForegroundService(Intent(this, BifrostQuickConnectService::class.java)
                    .putExtra(EXTRA_RECOVERY_EPOCH, epoch)) }
                    .onFailure { BifrostDiagnostics.record(this, "root-restore-dispatch", it) }
            } else cleanupOwnService(startId)
            return if (epoch != null) START_STICKY else START_NOT_STICKY
        }
        commandExecutor.execute { if (serviceAlive) handleCommand(intent, startId) }
        return START_STICKY
    }

    private fun handleCommand(intent: Intent?, startId: Int): Int {
        if (intent?.getStringExtra(EXTRA_ACTION) == ACTION_ROOT_ATTACH) {
            val epoch = intent.getStringExtra(EXTRA_RECOVERY_EPOCH)
            if (epoch != null) runCatching { attachRoot(epoch) }
                .onFailure { BifrostDiagnostics.record(this, "root-reattach-failed", it) }
            return START_STICKY
        }
        val hadOwnerAtEntry = transactionOwnership.hasOwner() || BifrostServiceOwnershipRegistry.current() != null
        val action = intent?.getStringExtra(EXTRA_ACTION)
        if (action == ACTION_STATUS) {
            val requested = serviceToken(intent)
            val status = requested?.let { BifrostServiceCommandCoordinator(transactionOwnership) {
                if (::runtime.isInitialized) runtime.disconnect()
                else BifrostRuntimeDisconnectOutcome(false, false, "BF-RUNTIME-MISSING")
            }.status(it) }
            val live = status?.exactLive
            when {
                requested != null && live != null -> {
                    val bindings = runCatching { BifrostApplicationPackageBindings.decode(requested.bindings) }.getOrNull()
                    sendAck(
                        intent,
                        RESULT_STATUS,
                        requested.transactionId,
                        live.snapshot,
                        bindings,
                        "BF-CONNECTION-STATUS",
                        description = live.description,
                        phase = live.phase.name,
                        idle = false,
                    )
                }
                requested != null && status?.receipt != null -> {
                    sendAck(
                        intent,
                        RESULT_DISCONNECTED,
                        requested.transactionId,
                        null,
                        null,
                        "BF-CONNECTION-IDLE",
                        idle = true,
                        receipt = status.receipt,
                        phase = BifrostServiceOwnershipPhase.IDLE.name,
                    )
                }
                else -> {
                    sendAck(
                        intent,
                        RESULT_FAILED,
                        requested?.transactionId ?: intent?.getStringExtra(EXTRA_TRANSACTION_ID).orEmpty(),
                        null,
                        null,
                        "BF-CONNECTION-TOKEN",
                        idle = status?.globalOwner == null,
                    )
                }
            }
            val cleanupStatusInstance = status?.cleanupOwnService
                ?: (BifrostServiceOwnershipRegistry.current() == null && !transactionOwnership.hasOwner())
            if (cleanupStatusInstance) {
                // A status-only foreground start owns no runtime.  Respond
                // first, then remove only this Service instance's state.
                cleanupOwnService(startId)
                return START_NOT_STICKY
            }
            return START_STICKY
        }
        if (action == ACTION_DISCONNECT) {
            val requested = serviceToken(intent)
            if (requested == null) {
                sendAck(intent, RESULT_FAILED, intent?.getStringExtra(EXTRA_TRANSACTION_ID).orEmpty(), null, null,
                    "BF-CONNECTION-TOKEN", idle = false)
                if (!hadOwnerAtEntry) cleanupOwnService(startId)
                return if (hadOwnerAtEntry) START_STICKY else START_NOT_STICKY
            }
            val liveAtEntry = BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == requested }
            if (!transactionOwnership.hasOwner() && liveAtEntry != null) {
                transactionOwnership.adoptExisting(requested, liveAtEntry.phase)
            }
            val coordinator = BifrostServiceCommandCoordinator(transactionOwnership) { runtime.disconnect() }
            val result = coordinator.disconnect(
                requested,
                onAcknowledgement = { decision ->
                    val liveAfter = BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == requested }
                    when {
                        decision.released -> sendAck(
                            intent,
                            RESULT_DISCONNECTED,
                            requested.transactionId,
                            null,
                            null,
                            decision.code,
                            idle = true,
                            receipt = decision.receipt,
                            phase = BifrostServiceOwnershipPhase.IDLE.name,
                            description = liveAtEntry?.description,
                        )
                        decision.blocked -> sendAck(
                            intent,
                            RESULT_FAILED,
                            requested.transactionId,
                            liveAfter?.snapshot,
                            runCatching { BifrostApplicationPackageBindings.decode(requested.bindings) }.getOrNull(),
                            decision.code,
                            blocked = true,
                            description = liveAfter?.description,
                            phase = BifrostServiceOwnershipPhase.BLOCKED_FAILED.name,
                        )
                        else -> sendAck(intent, RESULT_FAILED, requested.transactionId, null, null, decision.code, blocked = false)
                    }
                },
                onCleanup = {
                    coreFailureHandling.set(false)
                    leakSnapshot = runCatching { runtime.snapshot }.getOrElse { BifrostLeakGuard.stopped() }
                    BifrostApplicationPolicySnapshotRegistry.remove(requested.transactionId)
                    stopCandidateRefresh()
                    val epoch = intent?.getStringExtra(EXTRA_RECOVERY_EPOCH)
                    if (epoch == null || !BifrostRootConnectionIntent.matches(this, epoch)) cleanupOwnService(startId)
                },
            )
            when {
                result.released -> {
                    return if (result.cleanupOwnService && BifrostServiceOwnershipRegistry.current() == null) {
                        START_NOT_STICKY
                    } else {
                        START_STICKY
                    }
                }
                result.blocked -> {
                    runCatching { startForeground(1001, notification(BifrostUiText.coreBlockedEstablished)) }
                    return START_STICKY
                }
                else -> {
                    if (!transactionOwnership.hasOwner() && BifrostServiceOwnershipRegistry.current() == null) {
                        cleanupOwnService(startId)
                        return START_NOT_STICKY
                    }
                    return START_STICKY
                }
            }
        }
        val transactionId = intent?.getStringExtra(EXTRA_TRANSACTION_ID).orEmpty()
        var startedTransaction: BifrostServiceTransactionToken? = null
        var runtimeAttempted = false
        var issuedPolicy: BifrostApplicationPolicySnapshot? = null
        var connectionDescription: BifrostServiceConnectionDescription? = null
        return try {
            check(!BifrostUpdateInstallGate.pending) { "BF-CONNECTION-IN-FLIGHT" }
            if (!transactionId.matches(Regex("[0-9a-f]{32}"))) error("BF-CONNECTION-ID")
            if (ackReceiver(intent) == null) error("BF-CONNECTION-ACK-REQUIRED")
            val cached = BifrostConfigStore.load(this) ?: error("BF-CONFIG-CACHE-MISSING")
            val requestedCore = intent?.getStringExtra(EXTRA_CORE)?.takeIf { it.isNotBlank() } ?: cached.core
            val source = intent?.getStringExtra(EXTRA_SOURCE).orEmpty()
            if (source.isBlank() || source.equals("auto", true)) error("BF-SOURCE-SELECTION-REQUIRED")
            val country = intent?.getStringExtra(EXTRA_COUNTRY) ?: "auto"
            val frontSource = intent?.getStringExtra(EXTRA_FRONT_SOURCE)?.takeIf { it.isNotBlank() }
            val mode = intent?.getStringExtra(EXTRA_MODE) ?: "smart"
            val connectionSelection = BifrostConnectionRouteContract.parse(
                intent?.getStringExtra(EXTRA_CONNECTION_TYPE),
                intent?.getStringExtra(EXTRA_ROUTE_MODE),
            )
            if (connectionSelection.routeMode.wireValue != mode) error("BF-ROUTE-MODE")
            val candidateMode = intent?.getStringExtra(EXTRA_CANDIDATE_MODE)
                ?.takeIf { it == "auto" || it == "manual" }
                ?: error("BF-CANDIDATE-MODE")
            val applicationPolicy = BifrostApplicationPolicySnapshotRegistry.lookup(transactionId)
                ?.let(BifrostApplicationPolicy::verify)
                ?: error("BF-APP-POLICY-HANDOFF")
            issuedPolicy = applicationPolicy
            if (intent?.getStringExtra(EXTRA_APPLICATION_POLICY_DIGEST) != applicationPolicy.digest) {
                error("BF-APP-POLICY-DIGEST")
            }
            if (intent?.getStringExtra(EXTRA_APPLICATION_POLICY_GENERATION) != applicationPolicy.generation) {
                error("BF-APP-POLICY-GENERATION")
            }
            val expectedApplicationBindings = BifrostApplicationPackageBindings.decode(
                intent?.getStringExtra(EXTRA_APPLICATION_POLICY_BINDINGS)
                    ?: error("BF-APP-PACKAGE-INVALID"),
            )
            val encodedBindings = BifrostApplicationPackageBindings.encode(expectedApplicationBindings)
            if (intent?.getStringExtra(EXTRA_APPLICATION_POLICY_BINDINGS) != encodedBindings) {
                error("BF-APP-PACKAGE-INVALID")
            }
            val applicationPackageValidator = BifrostApplicationPolicyPackageValidator(
                AndroidApplicationPackageCatalog(this), packageName,
            )
            applicationPackageValidator.validate(applicationPolicy, expectedApplicationBindings)
            if (applicationPolicy.routeMode != mode) error("BF-APP-POLICY")
            val transaction = BifrostServiceTransactionToken(
                transactionId,
                applicationPolicy.generation,
                applicationPolicy.digest,
                encodedBindings,
            )
            if (BifrostServiceOwnershipRegistry.isRetired(transaction)) {
                error("BF-CONNECTION-RELEASED")
            }
            if (!transactionOwnership.begin(transaction)) {
                error("BF-CONNECTION-ACTIVE")
            }
            startedTransaction = transaction
            check(!BifrostServiceOwnershipRegistry.isDisconnectRequested(transaction)) { "BF-CONNECTION-RELEASED" }
            // Android may reuse a stopped Service before onDestroy runs. Read
            // the mode for each newly admitted transaction, never just once
            // in onCreate; otherwise a rapid reconnect can use the old mode.
            val useRoot = BifrostFeaturePreferences.rootMode(this)
            val recoveryEpoch = intent?.getStringExtra(EXTRA_RECOVERY_EPOCH)
            if (useRoot) {
                if (recoveryEpoch != null) check(BifrostRootConnectionIntent.matches(this, recoveryEpoch)) { "BF-CONNECTION-RELEASED" }
                else BifrostRootConnectionIntent.begin(this)
            }
            val rootEpoch = if (useRoot) BifrostRootConnectionIntent.current(this) else null
            if (useRoot != (rootTunnel != null)) {
                check(runtime.snapshot.state == BifrostLeakState.STOPPED && !core.isReady()) { "BF-CONNECTION-IN-FLIGHT" }
                rootTunnel?.close()
                rootTunnel = if (useRoot) BifrostRootRemote(this, rootEpoch!!) else null
                core = (rootTunnel as? BifrostRootRemote) ?: BifrostCoreAdapter(this, this)
            } else if (useRoot && (rootTunnel as? BifrostRootRemote)?.epoch != rootEpoch) {
                check(runtime.snapshot.state == BifrostLeakState.STOPPED && !core.isReady()) { "BF-CONNECTION-IN-FLIGHT" }
                rootTunnel = BifrostRootRemote(this, rootEpoch!!)
                core = rootTunnel as BifrostRootRemote
            }
            rootTunnel?.configure(applicationPolicy)
            val candidate = intent?.getStringExtra(EXTRA_CANDIDATE)?.takeIf { it.isNotBlank() }
                ?: error("BF-CANDIDATE-MISSING")
            val currentInput = BifrostProbeFingerprints.input(
                cached,
                source,
                AndroidNetworkBucket.fingerprint(this),
            ) ?: error("BF-SOURCE-NOT-READY")
            val receiptNetwork = intent?.getStringExtra(EXTRA_CANDIDATE_NETWORK)
            val receiptConfigVersion = intent?.getLongExtra(EXTRA_CANDIDATE_CONFIG_VERSION, 0L) ?: 0L
            val receiptConfigDigest = intent?.getStringExtra(EXTRA_CANDIDATE_CONFIG_DIGEST)
            val receiptCandidateFingerprint = intent?.getStringExtra(EXTRA_CANDIDATE_FINGERPRINT)
            val receiptTransportFingerprint = intent?.getStringExtra(EXTRA_CANDIDATE_TRANSPORT_FINGERPRINT)
            val receiptGeneration = intent?.getLongExtra(EXTRA_CANDIDATE_GENERATION, 0L) ?: 0L
            val currentGeneration = candidateProbeCoordinator.captureConnectionGeneration(currentInput)
            if (receiptNetwork != currentInput.networkFingerprint ||
                receiptConfigVersion != currentInput.configVersion ||
                receiptConfigDigest != currentInput.configDigest ||
                receiptCandidateFingerprint != currentInput.candidateFingerprint ||
                receiptTransportFingerprint != currentInput.transportFingerprint ||
                receiptGeneration <= 0L || receiptGeneration != currentGeneration) {
                error("BF-PROBE-BINDING-CHANGED")
            }
            val sourceObject = JSONObject(cached.content).optJSONArray("sources")?.let { array ->
                (0 until array.length()).asSequence()
                    .mapNotNull { array.optJSONObject(it) }
                    .firstOrNull { it.optString("code").equals(source, true) }
            } ?: error("BF-SOURCE-NOT-READY")
            val configuredLabel = sourceObject.optJSONArray("candidates")?.let { array ->
                (0 until array.length()).asSequence()
                    .mapNotNull { array.optJSONObject(it)?.optString("label") }
                    .firstOrNull { it == candidate }
            }
            if (configuredLabel == null) error("BF-CANDIDATE-NOT-READY")
            connectionDescription = BifrostServiceConnectionDescription(
                core = requestedCore,
                mode = mode,
                source = source,
                country = country,
                frontSource = frontSource ?: "auto",
                candidate = candidate,
                connectionType = connectionSelection.connectionType.wireValue,
            )
            // Acquire exact service ownership before touching the runtime
            // boundary. A duplicate request must be rejected without fencing,
            // stopping, or otherwise disturbing an existing/newer VPN.
            coreFailureHandling.set(false)
            runtimeAttempted = true
            if (!transactionOwnership.markFenceEstablished(transaction)) error("BF-CONNECTION-ACTIVE")
            leakSnapshot = runtime.snapshot
            check(serviceAlive) { "BF-CONNECTION-RELEASED" }
            // Publish only the complete immutable description.  A pending
            // owner with a null/placeholder candidate is not a valid handoff.
            BifrostServiceOwnershipRegistry.publish(
                BifrostServiceOwnershipPhase.PENDING,
                transaction,
                applicationPolicy,
                connectionDescription!!,
            )
            val xrayPort = if (requestedCore.equals("xray", true)) {
                core.prepareXray(BifrostXrayConfigCompiler.compile(
                    content = cached.content,
                    sourceCode = source,
                    countryCode = country,
                    selectedCandidate = candidate,
                    frontSourceCode = frontSource,
                    mode = mode,
                    includePackages = applicationPolicy.includePackages,
                    excludePackages = applicationPolicy.excludePackages,
                    appPolicyMode = applicationPolicy.policyMode,
                    applicationPolicy = applicationPolicy,
                ), applicationPolicy, expectedApplicationBindings)
            } else 0
            val candidateLabels = mutableMapOf<String, String>()
            val compiled = BifrostConfigCompiler.compile(
                candidateLabels = candidateLabels,
                routingRulesDirectory = if (mode == "smart") BifrostRoutingRules.prepare(this) else "routing",
                content = cached.content,
                sourceCode = source,
                countryCode = country,
                mode = mode,
                core = requestedCore,
                includePackages = applicationPolicy.includePackages,
                excludePackages = applicationPolicy.excludePackages,
                selectedCandidate = candidate,
                xrayPort = xrayPort,
                candidateMode = candidateMode,
                frontSourceCode = frontSource,
                appPolicyMode = applicationPolicy.policyMode,
                applicationPolicy = applicationPolicy,
            )
            // transactionOwnership.begin(transaction) precedes runtime.starting()
            // inside BifrostConnectionTransaction. It owns core.start and the
            // applicationPolicyReadback gate; the service only supplies the
            // production adapter and keeps the transaction result.
            val readback = BifrostConnectionTransaction(runtime, ProductionBifrostCorePort(core)).connect(
                BifrostCompiledConnection(compiled, requestedCore, applicationPolicy, expectedApplicationBindings, candidateLabels.toMap(),
                    cancelled = { !serviceAlive || BifrostUpdateInstallGate.pending || BifrostServiceOwnershipRegistry.isDisconnectRequested(transaction) ||
                        (rootEpoch != null && !BifrostRootConnectionIntent.matches(this, rootEpoch)) }),
            )
            leakSnapshot = runtime.snapshot
            check(serviceAlive) { "BF-CONNECTION-RELEASED" }
            check(!BifrostServiceOwnershipRegistry.isDisconnectRequested(transaction)) { "BF-CONNECTION-RELEASED" }
            // All throwable success-tail operations happen while ownership is
            // still PENDING and fenced.  A notification failure therefore
            // follows the deterministic blocked/abort path and can never
            // strand a COMMITTED owner.
            startForeground(1001, notification(BifrostUiText.vpnConnectedNotification))
            if (!transactionOwnership.ready(transaction)) error("BF-CONNECTION-ACTIVE")
            BifrostServiceOwnershipRegistry.publish(
                BifrostServiceOwnershipPhase.COMMITTED,
                transaction,
                applicationPolicy,
                connectionDescription!!,
            )
            (rootTunnel as? BifrostRootRemote)?.commit(BifrostServiceOwnershipRegistry.current()!!)
            sendAck(
                intent,
                RESULT_READY,
                transactionId,
                applicationPolicy,
                expectedApplicationBindings,
                "BF-CONNECTION-READY",
                description = connectionDescription,
                phase = BifrostServiceOwnershipPhase.COMMITTED.name,
            )
            // The connected lease is acquired only after the complete
            // COMMITTED owner and READY acknowledgement are published.  A
            // failed readiness/ack path therefore cannot keep cadence alive.
            startCandidateRefresh(source, transaction.transactionId)
            BifrostDiagnostics.record(this, if (useRoot) "root-connection-ready" else "vpn-connection-ready")
            BifrostApplicationPolicySnapshotRegistry.remove(transactionId)
            START_STICKY
        } catch (error: Exception) {
            BifrostDiagnostics.record(this, "connection-start-failed", error)
            val token = startedTransaction
            val fenced = token != null && transactionOwnership.fenceEstablishedFor(token)
            val failureDecision = if (token != null && fenced) {
                val outcome = if (runtimeAttempted && ::runtime.isInitialized) {
                    runCatching { handleCoreFailureOutcome() }
                        .getOrElse { BifrostRuntimeCoreFailureOutcome(false, false, "BF-CORE-FAILURE") }
                } else BifrostRuntimeCoreFailureOutcome(false, false, "BF-CORE-FAILURE")
                BifrostServiceFailureCoordinator(transactionOwnership).apply(token, outcome)
            } else {
                token?.let {
                    runCatching { transactionOwnership.failBeforeFence(it) }
                    BifrostServiceOwnershipRegistry.clearExactInternal(it)
                }
                if (runtimeAttempted && ::runtime.isInitialized) runCatching { runtime.abortStart() }
                BifrostServiceFailureResult(false, false, false, transactionOwnership.phase())
            }
            val blocked = failureDecision.blocked
            val unprotected = failureDecision.unprotected
            if (failureDecision.retained && token != null && (blocked || unprotected)) {
                val policy = issuedPolicy
                val description = connectionDescription
                if (policy != null && description != null) {
                    runCatching {
                        BifrostServiceOwnershipRegistry.publish(
                            failureDecision.phase,
                            token,
                            policy,
                            description,
                        )
                    }
                }
            }
            if (token != null && !failureDecision.retained && transactionOwnership.phase() != BifrostServiceOwnershipPhase.COMMITTED) {
                BifrostServiceOwnershipRegistry.clearExactInternal(token)
            }
            val requestedToken = serviceToken(intent)
            val registryOwner = BifrostServiceOwnershipRegistry.current()
            val duplicateOwner = token == null && registryOwner != null && requestedToken != null && registryOwner.token == requestedToken
            val retainedUnprotected = transactionOwnership.phase() == BifrostServiceOwnershipPhase.COMMITTED ||
                transactionOwnership.phase() == BifrostServiceOwnershipPhase.UNPROTECTED_FAILED
            val retainsOwner = failureDecision.retained || blocked || unprotected || retainedUnprotected || duplicateOwner
            // A malformed/different duplicate may share the legitimate
            // owner's transaction id.  Never remove that owner's capability
            // merely because the duplicate could not form a complete token.
            val preserveExistingCapability = hadOwnerAtEntry &&
                registryOwner?.token?.transactionId == transactionId
            val freshFailure = !retainsOwner && !transactionOwnership.hasOwner()
            if (freshFailure) {
                runCatching { if (::core.isInitialized) core.stop() }
                cleanupOwnService(startId)
                (token ?: requestedToken)?.let(BifrostServiceOwnershipRegistry::clearExactInternal)
            } else if (blocked) {
                runCatching { startForeground(1001, notification(BifrostUiText.coreBlockedEstablished)) }
            } else if (unprotected) {
                runCatching { startForeground(1001, notification(BifrostUiText.coreUnprotectedRetry)) }
            }
            if (!retainsOwner && !preserveExistingCapability) BifrostApplicationPolicySnapshotRegistry.remove(transactionId)
            val retainedSnapshot = BifrostServiceOwnershipRegistry.current()?.takeIf { it.token.transactionId == transactionId }
            val retainedBindings = retainedSnapshot?.let { runCatching { BifrostApplicationPackageBindings.decode(it.token.bindings) }.getOrNull() }
            sendAck(
                intent,
                RESULT_FAILED,
                transactionId,
                retainedSnapshot?.snapshot,
                retainedBindings,
                BifrostUiErrorMapper.code(error),
                blocked,
                description = retainedSnapshot?.description,
                phase = retainedSnapshot?.phase?.name,
            )
            if (freshFailure) START_NOT_STICKY else START_STICKY
        }
    }

    override fun onRevoke() {
        // Root owns no Android VPN slot. Revocation of an older ordinary VPN
        // authorization must not tear down the independent Root connection.
        if (rootTunnel != null && BifrostFeaturePreferences.rootMode(this)) return
        BifrostRootConnectionIntent.stop(this)
        serviceAlive = false
        commandExecutor.execute { revokeOwnedLifecycle() }
        super.onRevoke()
    }

    private fun revokeOwnedLifecycle() {
        coreFailureHandling.set(false)
        teardownOwnedLifecycle()
        if (BifrostServiceOwnershipRegistry.current() == null) runCatching { runtime.revoke() }
        leakSnapshot = runCatching { runtime.snapshot }.getOrElse { BifrostLeakGuard.stopped() }
        BifrostServiceOwnershipRegistry.current()?.token?.let { owner ->
            BifrostApplicationPolicySnapshotRegistry.remove(owner.transactionId)
        }
        if (BifrostServiceOwnershipRegistry.current() == null) transactionOwnership.clear()
        stopCandidateRefresh()
        stopSelf()
    }

    override fun onDestroy() {
        rootRecovery?.cancel(false)
        BifrostDiagnostics.record(this, if (rootTunnel != null) "root-service-destroyed" else "vpn-service-destroyed")
        notificationRefresh?.cancel(false)
        notificationRefresh = null
        nodeConfigurationRefresh.shutdownNow()
        serviceAlive = false
        commandExecutor.execute { destroyOwnedLifecycle() }
        commandExecutor.shutdown()
        super.onDestroy()
    }

    private val nodeConfigurationRefresh = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "bifrost-node-config").apply { isDaemon = true }
    }

    private fun destroyOwnedLifecycle() {
        coreFailureHandling.set(false)
        val root = rootTunnel as? BifrostRootRemote
        if (root != null && BifrostRootConnectionIntent.matches(this, root.epoch) && core.isReady()) {
            // Service/UI destruction is a detach. Only explicit disconnect,
            // logout, expiry or authoritative revocation stops the Root core.
            runtimeWatchdog.stop()
            runtimeStatusListener?.close(); runtimeStatusListener = null
            stopCandidateRefresh(); healthExecutor.shutdownNow()
            return
        }
        teardownOwnedLifecycle()
        if (BifrostServiceOwnershipRegistry.current() == null) {
            transactionOwnership.clear()
            if (::runtime.isInitialized) runtime.destroy()
        }
        leakSnapshot = if (::runtime.isInitialized) runtime.snapshot else BifrostLeakGuard.stopped()
        runtimeStatusListener?.close()
        runtimeStatusListener = null
        stopCandidateRefresh()
        healthExecutor.shutdownNow()
    }

    /** Service destruction is itself an exact teardown attempt.  If native
     * close/deactivate fails, retain the registry owner for a recreated
     * Service instead of erasing it and pretending IDLE. */
    private fun teardownOwnedLifecycle() {
        val owner = BifrostServiceOwnershipRegistry.current() ?: return
        if (!::runtime.isInitialized) return
        if (!transactionOwnership.hasOwner()) transactionOwnership.adoptExisting(owner.token, owner.phase)
        val result = BifrostServiceCommandCoordinator(transactionOwnership) { runtime.disconnect() }
            .disconnect(owner.token)
        if (result.released) {
            BifrostApplicationPolicySnapshotRegistry.remove(owner.token.transactionId)
            stopCandidateRefresh()
        }
    }

    /** Refresh is owned by the process coordinator.  Each round reloads the
     * latest verified cache before probing; a connected Service only holds a
     * lease and never captures stale config content. */
    private fun startCandidateRefresh(source: String, transactionId: String) {
        serviceProbeLease?.close()
        serviceProbeLease = candidateProbeCoordinator.acquireLease("service:$transactionId", source, listener = { result ->
            if (!serviceAlive) return@acquireLease
            val current = BifrostServiceOwnershipRegistry.current()
            if (current?.token?.transactionId != transactionId || !result.source.equals(source, true)) return@acquireLease
            // A notification is valid only for the current committed owner
            // and the exact verified config/source binding that produced the
            // result.  Config refresh/network rollover makes an older result
            // display-only and it is discarded.
            val latest = runCatching { BifrostConfigStore.load(this) }.getOrNull()
            val latestInput = latest?.let {
                runCatching { BifrostProbeFingerprints.input(it, source, result.key.networkFingerprint) }.getOrNull()
            }
            if (latest == null || latestInput == null ||
                result.key.configVersion != latest.version || result.key.configDigest != latest.digest ||
                result.key.candidateFingerprint != latestInput.candidateFingerprint ||
                result.key.transportFingerprint != latestInput.transportFingerprint ||
                result.key.networkFingerprint != AndroidNetworkBucket.fingerprint(this)) return@acquireLease
            result.label?.let { candidate ->
                runCatching { startForeground(1001, notification("线路探测已完成")) }
                return@acquireLease
            }
            result.error?.let { error ->
                runCatching {
                    startForeground(1001, notification(BifrostUiErrorMapper.message(BifrostUiText.candidateRefreshAction, error)))
                }
            }
        })
    }

    private fun stopCandidateRefresh() {
        serviceProbeLease?.close()
        serviceProbeLease = null
    }

    private fun scheduleHealthMonitor() {
        healthRefresh?.cancel(false)
        healthRefresh = healthExecutor.scheduleWithFixedDelay({
            if (::core.isInitialized && leakSnapshot.state == BifrostLeakState.HEALTHY && !core.isReady()) {
                val blocked = handleCoreFailure()
                startForeground(1001, notification(if (blocked) BifrostUiText.coreStoppedBlocked else BifrostUiText.coreStoppedUnprotected))
            }
        }, 1, 1, TimeUnit.SECONDS)
    }

    /** Called by libbox's serviceStop callback and by the health watchdog. */
    internal fun onCoreServiceStop() {
        if (!::runtime.isInitialized || leakSnapshot.state !in setOf(BifrostLeakState.STARTING, BifrostLeakState.HEALTHY)) return
        handleCoreFailure()
    }

    // The legacy boolean contract is equivalent to runtime.coreFailure(); the
    // active path keeps the richer evidence outcome for ownership decisions.
    private fun handleCoreFailure(): Boolean = handleCoreFailureOutcome().blocked

    private fun handleCoreFailureOutcome(): BifrostRuntimeCoreFailureOutcome {
        if (!coreFailureHandling.compareAndSet(false, true)) return runtime.lastCoreFailureOutcome
        val outcome = runCatching { runtime.coreFailureOutcome() }
            .getOrElse { BifrostRuntimeCoreFailureOutcome(false, false, "BF-CORE-FAILURE") }
        applyCoreFailureOwnership(outcome)
        leakSnapshot = runCatching { runtime.snapshot }.getOrElse { BifrostLeakGuard.stopped() }
        runCatching { stopCandidateRefresh() }
        // Notification failure must never escape the ownership catch path.
        runCatching { startForeground(1001, notification(if (outcome.blocked) BifrostUiText.blackholeState else BifrostUiText.unprotectedState)) }
        return outcome
    }

    /** Watchdog/libbox callbacks use the same failure coordinator as the
     * synchronous onStartCommand catch path.  This keeps a committed owner
     * exact and retryable instead of leaving a healthy-looking registry entry. */
    private fun applyCoreFailureOwnership(outcome: BifrostRuntimeCoreFailureOutcome) {
        val token = transactionOwnership.pendingToken() ?: transactionOwnership.committedToken() ?: return
        val decision = BifrostServiceFailureCoordinator(transactionOwnership).apply(token, outcome)
        val live = BifrostServiceOwnershipRegistry.current()?.takeIf { it.token == token }
        val policy = live?.snapshot
        val description = live?.description
        if (decision.retained && policy != null && description != null &&
            decision.phase in setOf(
                BifrostServiceOwnershipPhase.BLOCKED_FAILED,
                BifrostServiceOwnershipPhase.UNPROTECTED_FAILED,
            )) {
            runCatching {
                BifrostServiceOwnershipRegistry.publish(decision.phase, token, policy, description)
            }
        } else if (!decision.retained) {
            BifrostServiceOwnershipRegistry.clearExactInternal(token)
        }
    }

    private fun stopHealthMonitor() {
        healthRefresh?.cancel(false)
        healthRefresh = null
    }

    /** Android 9 has no reliable public lockdown API; strings are checked
     * conservatively and any exception means false. */
    private fun lockdownEvidence(): Boolean = runCatching {
        val alwaysOn = Settings.Secure.getString(contentResolver, "always_on_vpn_app")
        val lockdown = Settings.Secure.getInt(contentResolver, "always_on_vpn_lockdown", 0) == 1
        alwaysOn == packageName && lockdown
    }.getOrDefault(false)

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("bifrost-connection", BifrostUiText.notificationChannel, NotificationManager.IMPORTANCE_LOW),
        )
    }

    @Suppress("DEPRECATION")
    private fun notification(text: String): Notification {
        notificationStatus = text
        val content = liveNotificationText(text)
        lastNotificationText = content
        lastNotificationAt = android.os.SystemClock.elapsedRealtime()
        val builder = Notification.Builder(this, "bifrost-connection")
        val open = android.app.PendingIntent.getActivity(this, 1,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE)
        val disconnect = android.app.PendingIntent.getActivity(this, 2,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP).putExtra("bifrost.quick.disconnect", true),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE)
        if (BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY) {
            val lines = BifrostTrafficTelemetry.notificationTraffic.lines(android.os.SystemClock.elapsedRealtime())
            val rows = android.widget.RemoteViews(packageName, R.layout.notification_traffic).apply {
                setTextViewText(R.id.traffic_upload, lines[0])
                setTextViewText(R.id.traffic_download, lines[1])
            }
            builder.setStyle(Notification.DecoratedCustomViewStyle())
                .setCustomContentView(rows).setCustomBigContentView(rows)
                .setSubText(BifrostUiText.vpnConnectedNotification)
        } else builder.setStyle(Notification.BigTextStyle().bigText(content))
        return builder.setContentTitle("Bifrost").setContentText(content)
            .setOnlyAlertOnce(true).setShowWhen(false)
            .setContentIntent(open).addAction(Notification.Action.Builder(null, BifrostUiText.quickOpen, open).build())
            .addAction(Notification.Action.Builder(null, BifrostUiText.quickDisconnect, disconnect).build())
            .setSmallIcon(R.drawable.bifrost_direction_a_monochrome).setOngoing(true).build()
    }

    /** Re-issue local ownership after authenticating the existing Root runtime.
     * No core reload, TUN replacement, account mutation or selector reset. */
    private fun attachRoot(epoch: String) {
        val existing = BifrostServiceOwnershipRegistry.current()
        if (existing != null && rootTunnel is BifrostRootRemote && transactionOwnership.hasOwner()) return
        check(existing == null || existing.phase == BifrostServiceOwnershipPhase.COMMITTED) { "BF-CONNECTION-IN-FLIGHT" }
        check(BifrostRootConnectionIntent.matches(this, epoch)) { "BF-CONNECTION-RELEASED" }
        val remote = BifrostRootRemote(this, epoch)
        val saved = remote.snapshot() ?: return
        check(remote.isReady()) { "BF-ROOT-NOT-READY" }
        val raw = saved.getJSONObject("policy")
        val identities = raw.getJSONArray("identities").let { values -> (0 until values.length()).map(values::getString) }
        val snapshot = existing?.snapshot ?: BifrostApplicationPolicy.normalize(raw.getString("route_mode"), raw.getString("policy_mode"),
            if (raw.getString("policy_mode") == "allow") identities else emptyList(),
            if (raw.getString("policy_mode") == "exclude") identities else emptyList())
        val bindings = BifrostApplicationPackageBindings.decode(saved.getString("bindings"))
        BifrostApplicationPolicyPackageValidator(AndroidApplicationPackageCatalog(this), packageName).validate(snapshot, bindings)
        remote.configure(snapshot)
        remote.applicationPolicyReadback(bindings)
        val description = saved.getJSONObject("description").let { row -> BifrostServiceConnectionDescription(
            row.getString("core"), row.getString("mode"), row.getString("source"), row.getString("country"),
            row.getString("frontSource"), row.getString("candidate"), row.getString("connectionType")) }
        val token = existing?.token ?: BifrostServiceTransactionToken(java.util.UUID.randomUUID().toString().replace("-", ""),
            snapshot.generation, snapshot.digest, saved.getString("bindings"))
        synchronized(BifrostFeaturePreferences.transitionGate) {
            check(BifrostRootConnectionIntent.matches(this, epoch) && !BifrostFeaturePreferences.changing) { "BF-CONNECTION-IN-FLIGHT" }
            if (existing == null) check(BifrostApplicationPolicySnapshotRegistry.register(token.transactionId, snapshot)) { "BF-CONNECTION-ACTIVE" }
            rootTunnel = remote; core = remote
            check(transactionOwnership.adoptExisting(token, BifrostServiceOwnershipPhase.COMMITTED)) { "BF-CONNECTION-ACTIVE" }
            BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.COMMITTED, token, snapshot, description)
            check(runtime.adoptHealthy { remote.isReady() && remote.alive() }) { "BF-ROOT-READBACK" }
        }
        remote.commit(BifrostServiceOwnershipRegistry.current()!!)
        startForeground(1001, notification(BifrostUiText.vpnConnectedNotification))
        BifrostQuickTileService.refresh(this)
        BifrostDiagnostics.record(this, "root-existing-connection-adopted")
    }

    private fun scheduleRootRecovery() {
        if (rootRecovery?.isDone == false || BifrostQuickConnectService.preparing) return
        val epoch = BifrostRootConnectionIntent.current(this) ?: return
        rootRecovery = nodeConfigurationRefresh.schedule({
            if (!serviceAlive || BifrostUpdateInstallGate.pending || !BifrostRootConnectionIntent.matches(this, epoch)) return@schedule
            val phase = BifrostServiceOwnershipRegistry.current()?.phase
            if (phase !in setOf(BifrostServiceOwnershipPhase.BLOCKED_FAILED, BifrostServiceOwnershipPhase.UNPROTECTED_FAILED)) return@schedule
            BifrostDiagnostics.record(this, "root-recovery-start")
            runCatching { startForegroundService(Intent(this, BifrostQuickConnectService::class.java)
                .putExtra(EXTRA_RECOVERY_EPOCH, epoch)) }
                .onFailure { BifrostDiagnostics.record(this, "root-recovery-dispatch", it) }
        }, 2, TimeUnit.SECONDS)
    }

    private fun liveNotificationText(status: String): String =
        if (BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY)
            (if (status == "线路探测已完成" || status == BifrostUiText.notificationPreparing)
                BifrostUiText.vpnConnectedNotification else status) + "\n" +
                BifrostTrafficTelemetry.notificationTraffic.text(android.os.SystemClock.elapsedRealtime())
        else status

    private fun ackReceiver(intent: Intent?): ResultReceiver? {
        return if (Build.VERSION.SDK_INT >= 33) {
            intent?.getParcelableExtra(EXTRA_ACK_RECEIVER, ResultReceiver::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent?.getParcelableExtra(EXTRA_ACK_RECEIVER) as? ResultReceiver
        }
    }

    private fun cleanupOwnService(startId: Int) {
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        runCatching { stopSelfResult(startId) }
    }

    /** Bounded raw correlation values; never used to construct a snapshot. */
    private fun serviceToken(intent: Intent?): BifrostServiceTransactionToken? {
        val id = intent?.getStringExtra(EXTRA_TRANSACTION_ID).orEmpty()
        val generation = intent?.getStringExtra(EXTRA_APPLICATION_POLICY_GENERATION).orEmpty()
        val digest = intent?.getStringExtra(EXTRA_APPLICATION_POLICY_DIGEST).orEmpty()
        val bindings = intent?.getStringExtra(EXTRA_APPLICATION_POLICY_BINDINGS)
        if (!id.matches(Regex("[0-9a-f]{32}")) ||
            !generation.matches(Regex("[0-9a-f]{32}")) ||
            !digest.matches(Regex("[0-9a-f]{64}")) ||
            bindings == null || bindings.length > 16 * 1024) return null
        return BifrostServiceTransactionToken(id, generation, digest, bindings)
    }

    private fun sendAck(
        intent: Intent?,
        resultCode: Int,
        transactionId: String,
        snapshot: BifrostApplicationPolicySnapshot?,
        bindings: List<BifrostApplicationPackageBinding>?,
        code: String,
        blocked: Boolean = false,
        description: BifrostServiceConnectionDescription? = null,
        phase: String? = null,
        idle: Boolean = false,
        receipt: BifrostServiceReleaseReceipt? = null,
    ) {
        val receiver = ackReceiver(intent) ?: return
        android.util.Log.i("BifrostConnectionDiagnostic", "ack=$resultCode code=$code blocked=$blocked")
        val raw = serviceToken(intent)
        val ackTransactionId = snapshot?.let { transactionId }
            ?: raw?.transactionId
            ?: transactionId.takeIf { it.matches(Regex("[0-9a-f]{32}")) }.orEmpty()
        val data = Bundle().apply {
            putString(EXTRA_TRANSACTION_ID, ackTransactionId)
            putString(EXTRA_ACK_CODE, code)
            putString(EXTRA_ACK_DIGEST, snapshot?.digest ?: raw?.digest)
            putString(EXTRA_ACK_GENERATION, snapshot?.generation ?: raw?.generation)
            putString(
                EXTRA_ACK_BINDINGS,
                snapshot?.let { BifrostApplicationPackageBindings.encode(bindings.orEmpty()) } ?: raw?.bindings,
            )
            putBoolean(EXTRA_ACK_BLOCKED, blocked)
            putBoolean(EXTRA_ACK_IDLE, idle)
            putLong(EXTRA_ACK_RELEASE_EPOCH, receipt?.epoch ?: -1L)
            putString(EXTRA_ACK_PHASE, phase)
            putString(EXTRA_ACK_CORE, description?.core)
            putString(EXTRA_ACK_MODE, description?.mode)
            putString(EXTRA_ACK_SOURCE, description?.source)
            putString(EXTRA_ACK_COUNTRY, description?.country)
            putString(EXTRA_ACK_FRONT_SOURCE, description?.frontSource)
            putString(EXTRA_ACK_CANDIDATE, description?.candidate)
            putString(EXTRA_ACK_CONNECTION_TYPE, description?.connectionType)
            putString(EXTRA_ACK_CANDIDATE_NETWORK, intent?.getStringExtra(EXTRA_CANDIDATE_NETWORK))
            putLong(EXTRA_ACK_CANDIDATE_CONFIG_VERSION, intent?.getLongExtra(EXTRA_CANDIDATE_CONFIG_VERSION, 0L) ?: 0L)
            putString(EXTRA_ACK_CANDIDATE_CONFIG_DIGEST, intent?.getStringExtra(EXTRA_CANDIDATE_CONFIG_DIGEST))
            putString(EXTRA_ACK_CANDIDATE_FINGERPRINT, intent?.getStringExtra(EXTRA_CANDIDATE_FINGERPRINT))
            putString(EXTRA_ACK_CANDIDATE_TRANSPORT_FINGERPRINT, intent?.getStringExtra(EXTRA_CANDIDATE_TRANSPORT_FINGERPRINT))
            putLong(EXTRA_ACK_CANDIDATE_GENERATION, intent?.getLongExtra(EXTRA_CANDIDATE_GENERATION, 0L) ?: 0L)
        }
        runCatching { receiver.send(resultCode, data) }
    }

    companion object {
        const val RESULT_FAILED = 0
        const val RESULT_READY = 1
        const val RESULT_DISCONNECTED = 2
        const val RESULT_STATUS = 3
        const val EXTRA_TRANSACTION_ID = "bifrost.connection.transaction_id.v1"
        const val EXTRA_ACK_RECEIVER = "bifrost.connection.ack_receiver.v1"
        const val EXTRA_ACK_CODE = "bifrost.connection.ack_code.v1"
        const val EXTRA_ACK_DIGEST = "bifrost.connection.ack_digest.v1"
        const val EXTRA_ACK_GENERATION = "bifrost.connection.ack_generation.v1"
        const val EXTRA_ACK_BINDINGS = "bifrost.connection.ack_bindings.v1"
        const val EXTRA_ACK_BLOCKED = "bifrost.connection.ack_blocked.v1"
        const val EXTRA_ACK_IDLE = "bifrost.connection.ack_idle.v1"
        const val EXTRA_ACK_RELEASE_EPOCH = "bifrost.connection.ack_release_epoch.v1"
        const val EXTRA_ACK_PHASE = "bifrost.connection.ack_phase.v1"
        const val EXTRA_ACK_CORE = "bifrost.connection.ack_core.v1"
        const val EXTRA_ACK_MODE = "bifrost.connection.ack_mode.v1"
        const val EXTRA_ACK_SOURCE = "bifrost.connection.ack_source.v1"
        const val EXTRA_ACK_COUNTRY = "bifrost.connection.ack_country.v1"
        const val EXTRA_ACK_FRONT_SOURCE = "bifrost.connection.ack_front_source.v1"
        const val EXTRA_ACK_CANDIDATE = "bifrost.connection.ack_candidate.v1"
        const val EXTRA_ACK_CONNECTION_TYPE = "bifrost.connection.ack_connection_type.v1"
        const val EXTRA_ACK_CANDIDATE_NETWORK = "bifrost.connection.ack_candidate_network.v1"
        const val EXTRA_ACK_CANDIDATE_CONFIG_VERSION = "bifrost.connection.ack_candidate_config_version.v1"
        const val EXTRA_ACK_CANDIDATE_CONFIG_DIGEST = "bifrost.connection.ack_candidate_config_digest.v1"
        const val EXTRA_ACK_CANDIDATE_FINGERPRINT = "bifrost.connection.ack_candidate_fingerprint.v1"
        const val EXTRA_ACK_CANDIDATE_TRANSPORT_FINGERPRINT = "bifrost.connection.ack_candidate_transport_fingerprint.v1"
        const val EXTRA_ACK_CANDIDATE_GENERATION = "bifrost.connection.ack_candidate_generation.v1"
        const val EXTRA_CORE = "bifrost.core"
        const val EXTRA_SOURCE = "bifrost.source"
        const val EXTRA_COUNTRY = "bifrost.country"
        const val EXTRA_FRONT_SOURCE = "bifrost.front_source"
        const val EXTRA_MODE = "bifrost.mode"
        const val EXTRA_CONNECTION_TYPE = "bifrost.connection_type.v1"
        const val EXTRA_ROUTE_MODE = "bifrost.route_mode.v1"
        const val EXTRA_CANDIDATE = "bifrost.candidate"
        const val EXTRA_CANDIDATE_MODE = "bifrost.candidate_mode.v1"
        const val EXTRA_CANDIDATE_NETWORK = "bifrost.candidate_network.v1"
        const val EXTRA_CANDIDATE_CONFIG_VERSION = "bifrost.candidate_config_version.v1"
        const val EXTRA_CANDIDATE_CONFIG_DIGEST = "bifrost.candidate_config_digest.v1"
        const val EXTRA_CANDIDATE_FINGERPRINT = "bifrost.candidate_fingerprint.v1"
        const val EXTRA_CANDIDATE_TRANSPORT_FINGERPRINT = "bifrost.candidate_transport_fingerprint.v1"
        const val EXTRA_CANDIDATE_GENERATION = "bifrost.candidate_generation.v1"
        const val EXTRA_APPLICATION_POLICY_DIGEST = "bifrost.application_policy_digest.v1"
        const val EXTRA_APPLICATION_POLICY_GENERATION = "bifrost.application_policy_generation.v1"
        const val EXTRA_APPLICATION_POLICY_BINDINGS = "bifrost.application_policy_bindings.v1"
        const val EXTRA_ACTION = "bifrost.action"
        const val EXTRA_RECOVERY_EPOCH = "bifrost.root.recovery_epoch"
        const val ACTION_DISCONNECT = "disconnect"
        const val ACTION_STATUS = "status"
        const val ACTION_ROOT_ATTACH = "root-attach"
    }

    private inner class AndroidBlackholeController : BifrostBlackholeController {
        private var descriptor: ParcelFileDescriptor? = null

        @Synchronized
        override fun enter(): Boolean {
            rootTunnel?.let { root ->
                try { return root.block() } catch (error: Exception) {
                    BifrostDiagnostics.record(this@BifrostVpnService, "root-boundary-failed", error)
                    throw error
                }
            }
            if (descriptor != null) return true
            val replacement = runCatching {
                Builder()
                    .setSession(BifrostUiText.blackholeSession)
                    // Android may reuse this VPN network agent for the ready
                    // TUN. It must inherit Wi-Fi/cellular cost from the start.
                    .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false) }
                    .addDisallowedApplication(packageName)
                    .addAddress("10.254.254.1", 32)
                    .addAddress("fdfe:ffff:ffff::1", 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .establish()
            }.getOrNull() ?: return false
            // Establish first, then close the old descriptor: no window is
            // intentionally created where an ordinary route is restored.
            val old = descriptor
            descriptor = replacement
            runCatching { old?.close() }
            return true
        }

        @Synchronized
        override fun release() {
            rootTunnel?.let { it.releaseFence(); return }
            val old = descriptor
            // Keep the descriptor reference until close succeeds.  A failed
            // native/platform close must leave the fence addressable and
            // retryable instead of claiming STOPPED/IDLE.
            old?.close()
            descriptor = null
        }
    }
}
