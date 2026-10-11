package com.bifrost.client

import com.bifrost.client.ui.model.BifrostConnectionState
import com.bifrost.client.ui.model.BifrostRuntimeEvidence
import com.bifrost.client.ui.model.BifrostRuntimeSignal
import com.bifrost.client.ui.model.BifrostRoutingContract
import com.bifrost.client.ui.model.BifrostUiContract
import com.bifrost.client.ui.model.BifrostUiReducer
import com.bifrost.client.ui.model.BifrostUiEvent
import com.bifrost.client.ui.model.BifrostUiState
import com.bifrost.client.ui.model.BifrostUiStateReducer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostUiModelTest {
    @Test
    fun successfulUpdateDiscoveryAndOfflineConfigAreNotRenderedAsFailures() {
        assertEquals(com.bifrost.client.ui.model.BifrostUiText.updateAvailable,
            BifrostUiErrorMapper.success("update", "available"))
        assertEquals(com.bifrost.client.ui.model.BifrostUiText.offlineConfig,
            BifrostUiErrorMapper.success("refresh", "offline"))
    }

    @Test
    fun everyActiveConnectionPhaseCanBeStoppedEvenIfConfigIsUnavailable() {
        for (state in BifrostConnectionState.entries) {
            assertEquals(state != BifrostConnectionState.IDLE && state != BifrostConnectionState.ERROR,
                com.bifrost.client.ui.model.BifrostUiActions.canStop(state))
        }
    }

    @Test
    fun manualAndSmartGateModesCannotKeepAnInvisibleApplicationPolicy() {
        val initial = BifrostUiState(mode = "smart", appPolicyEnabled = true)
        for (mode in listOf("global", "smartgate")) {
            assertFalse(BifrostUiStateReducer.reduce(initial, BifrostUiEvent.Mode(mode)).appPolicyEnabled)
        }
        val manual = BifrostUiStateReducer.reduce(initial, BifrostUiEvent.CandidateMode("manual"))
        assertFalse(manual.appPolicyEnabled)
        assertFalse(BifrostUiStateReducer.reduce(manual, BifrostUiEvent.AppPolicyEnabled(true)).appPolicyEnabled)
    }

    @Test
    fun protectedRequiresVerifiedServiceReadback() {
        val transaction = "0123456789abcdef0123456789abcdef"
        val generation = "abcdefabcdefabcdefabcdefabcdefab"
        val digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val status = "Bifrost VPN 已连接"
        assertFalse(BifrostUiReducer.fromServiceStatus(status, BifrostRuntimeEvidence()).isProtected)
        assertFalse(BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, false, transaction, digest, generation, "[]", BifrostRuntimeSignal.PROTECTED),
            transaction,
            digest,
            generation,
            "[]",
        ).isProtected)
        assertFalse(BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, true, "fedcba9876543210fedcba9876543210", digest, generation, "[]", BifrostRuntimeSignal.PROTECTED),
            transaction,
            digest,
            generation,
            "[]",
        ).isProtected)
        assertFalse(BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, true, transaction, digest, generation, "[]", BifrostRuntimeSignal.PROTECTED),
            "fedcba9876543210fedcba9876543210",
            digest,
            generation,
            "[]",
        ).isProtected)
        assertFalse(BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, true, transaction, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", generation, "[]", BifrostRuntimeSignal.PROTECTED),
            transaction,
            digest,
            generation,
            "[]",
        ).isProtected)
        assertFalse(BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, true, transaction, digest, generation, "[{\"package_name\":\"com.example.proxy\"}]", BifrostRuntimeSignal.PROTECTED),
            transaction,
            digest,
            generation,
            "[]",
        ).isProtected)
        val verified = BifrostUiReducer.fromServiceStatus(
            status,
            BifrostRuntimeEvidence(true, true, transaction, digest, generation, "[]", BifrostRuntimeSignal.PROTECTED),
            transaction,
            digest,
            generation,
            "[]",
        )
        assertEquals(BifrostConnectionState.PROTECTED, verified.state)
    }

    @Test
    fun idleNeverInventsTelemetryAndThemeIsPresentationOnly() {
        val idle = BifrostUiReducer.fromServiceStatus("未连接", BifrostRuntimeEvidence())
        assertEquals("—", idle.metrics.download)
        assertEquals("—", idle.metrics.upload)
        assertTrue(idle.metrics.samples.isEmpty())
    }

    @Test
    fun navigationAndModesAreTheCrossPlatformContract() {
        assertEquals(listOf("连接", "线路", "活动", "设置"), BifrostUiContract.navigation)
        assertEquals(listOf("smart", "global", "smartgate"), BifrostUiContract.modes.map { it.first })
    }

    @Test
    fun appPolicySwitchUsesTypedPerAppContractWithoutChangingSmartGatePresentation() {
        val disabled = BifrostRoutingContract.select(
            "smartgate", false, "allow", listOf("com.example.proxy"), emptyList(),
        )
        assertEquals("smart", disabled.wireMode)
        assertEquals("none", disabled.policyMode)
        assertTrue(disabled.include.isEmpty() && disabled.exclude.isEmpty())

        val enabled = BifrostRoutingContract.select(
            "smartgate", true, "allow", listOf("com.example.proxy"), emptyList(),
        )
        assertEquals("per-app", enabled.wireMode)
        assertEquals("allow", enabled.policyMode)
        assertEquals(listOf("com.example.proxy"), enabled.include)
    }

    @Test
    fun immutableUiReducerPreservesOneStateAndDoesNotPersistSecrets() {
        val initial = BifrostUiState(baseUrl = "https://trusted.invalid", includeText = "old")
        val changed = BifrostUiStateReducer.reduce(initial, BifrostUiEvent.Mode("global"))
        val routed = BifrostUiStateReducer.reduce(changed, BifrostUiEvent.AppPolicyEnabled(true))
        assertEquals("smart", initial.mode)
        assertEquals("global", changed.mode)
        assertFalse(routed.appPolicyEnabled)
        assertEquals("old", routed.includeText)
        assertFalse(routed.recovery.isNotBlank())
        assertFalse(routed.pairing.isNotBlank())
    }

    @Test
    fun interactivePolicyAndSmartGateControlsClearConflictingUiState() {
        val manual = BifrostUiState(
            mode = "smart",
            candidateMode = "manual",
            candidateLabel = "A-01",
            appPolicy = "allow",
            includeText = "com.example.proxy",
            excludeText = "com.example.direct",
        )
        val gate = BifrostUiStateReducer.reduce(manual, BifrostUiEvent.Mode("smartgate"))
        assertEquals("auto", gate.candidateMode)
        assertEquals("", gate.candidateLabel)

        val exclude = BifrostUiStateReducer.reduce(manual, BifrostUiEvent.AppPolicy("exclude"))
        assertEquals("exclude", exclude.appPolicy)
        assertEquals("", exclude.includeText)
        assertEquals("com.example.direct", exclude.excludeText)

        val allow = BifrostUiStateReducer.reduce(exclude.copy(includeText = "com.example.proxy"), BifrostUiEvent.AppPolicy("allow"))
        assertEquals("allow", allow.appPolicy)
        assertEquals("", allow.excludeText)
        assertEquals("com.example.proxy", allow.includeText)
    }

    @Test
    fun displayTextCannotAuthorizeProtectedState() {
        val evidence = BifrostRuntimeEvidence(
            serviceAccepted = true,
            readbackVerified = true,
            transactionId = "tx",
            digest = "digest",
            generation = "generation",
            bindings = "[]",
            signal = BifrostRuntimeSignal.ERROR,
        )
        val state = BifrostUiReducer.fromRuntimeSignal(
            BifrostRuntimeSignal.ERROR,
            evidence,
            "tx",
            "digest",
            "generation",
            "[]",
            "已连接",
        )
        assertFalse(state.isProtected)
        assertEquals(BifrostConnectionState.ERROR, state.state)
    }

    @Test
    fun bindingAdditionRemovalAndReorderingFailClosed() {
        val tx = "0123456789abcdef0123456789abcdef"
        val digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val generation = "abcdefabcdefabcdefabcdefabcdefab"
        val expected = "[{\"package_name\":\"com.example.a\",\"image_identity\":\"v1|version:1|updated:1|signers:1|64:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}]"
        val evidence = BifrostRuntimeEvidence(true, true, tx, digest, generation, expected, BifrostRuntimeSignal.PROTECTED)
        fun state(binding: String) = BifrostUiReducer.fromRuntimeSignal(BifrostRuntimeSignal.PROTECTED, evidence, tx, digest, generation, binding)
        assertTrue(state(expected).isProtected)
        assertFalse(state("[]").isProtected)
        assertFalse(state(expected.replace("com.example.a", "com.example.b")).isProtected)
        assertFalse(state(expected + ",{}").isProtected)
    }

    @Test
    fun sourceReconcilePreservesValidChoiceAndClearsOnlyRemovedAuthority() {
        val viewModel = com.bifrost.client.ui.model.BifrostUiViewModel()
        viewModel.initialize(BifrostUiState(source = "a", country = "CN", frontSource = "AUTO"))
        viewModel.reconcileAuthorities(listOf("A", "B"), listOf("auto", "CN"), listOf("auto", "A"))
        assertEquals("A", viewModel.state.value.source)
        assertEquals("CN", viewModel.state.value.country)
        assertEquals("auto", viewModel.state.value.frontSource)
        viewModel.reconcileAuthorities(listOf("B"), listOf("auto"), listOf("auto"))
        assertEquals("", viewModel.state.value.source)
        assertEquals("auto", viewModel.state.value.country)
        assertEquals("auto", viewModel.state.value.frontSource)
    }

    @Test
    fun sourceEventsRemainOneImmutableStateTransition() {
        val viewModel = com.bifrost.client.ui.model.BifrostUiViewModel()
        viewModel.initialize(BifrostUiState(source = "A"))
        val before = viewModel.state.value
        viewModel.dispatch(BifrostUiEvent.Source("B"))
        assertEquals("A", before.source)
        assertEquals("B", viewModel.state.value.source)
        assertEquals(before.mode, viewModel.state.value.mode)
        assertEquals(before.includeText, viewModel.state.value.includeText)
    }

    @Test
    fun candidateContractSeparatesAutoManualCoreAndSafeCountryLabels() {
        val content = """
            {"sources":[{"code":"A","configured":true,"display_name":"线路 A",
              "candidates":[{"label":"A-01","display_name":"北线" ,"dial_address":"127.0.0.1","port":443,"uuid":"secret"}]}],
             "countries":[{"code":"CN","name_zh":"中国"}]}
        """.trimIndent()
        val options = BifrostCandidateSelectionContract.candidateOptions(content, "A")
        assertEquals(listOf("A-01"), options.map { it.label })
        assertEquals("北线", options.single().displayName)
        assertEquals(listOf("auto", "CN"), BifrostCandidateSelectionContract.countryOptions(content).map { it.first })
        assertEquals("中国", BifrostCandidateSelectionContract.countryOptions(content).last().second)
        val auto = BifrostCandidateSelectionContract.validate(
            content, "A", "smart", "CN", BifrostNodeSelection(core = "xray"),
        )
        assertEquals(BifrostCandidateMode.AUTO, auto.mode)
        val manual = BifrostCandidateSelectionContract.validate(
            content, "A", "smart", "CN", BifrostNodeSelection(BifrostCandidateMode.MANUAL, "A-01", "sing-box"),
        )
        assertEquals("A-01", manual.manualLabel)
        assertFalse(BifrostCandidateSelectionContract.visibleCandidateChooser("smartgate", "CN"))
        assertTrue(BifrostCandidateSelectionContract.visibleCandidateChooser("smart", "CN"))
    }

    @Test
    fun candidateContractRejectsCrossSourceOrTransportLabels() {
        val content = """{"sources":[{"code":"A","configured":true,"candidates":[{"label":"A-01","dial_address":"127.0.0.1"}]}]}"""
        assertTrue(BifrostCandidateSelectionContract.candidateOptions(content, "B").isEmpty())
        try {
            BifrostCandidateSelectionContract.validate(content, "A", "smart", "auto", BifrostNodeSelection(BifrostCandidateMode.MANUAL, "127.0.0.1", "auto"))
            throw AssertionError("cross-source/dial label accepted")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun connectionTypeAndRouteModeAreIndependentAndUnknownValuesFailClosed() {
        val direct = BifrostConnectionRouteContract.fromUiMode("global", false)
        assertEquals(BifrostConnectionType.DIRECT_VMESH, direct.connectionType)
        assertEquals(BifrostRouteMode.GLOBAL, direct.routeMode)
        val gate = BifrostConnectionRouteContract.fromUiMode("smartgate", true)
        assertEquals(BifrostConnectionType.SMARTGATE, gate.connectionType)
        assertEquals(BifrostRouteMode.PER_APP, gate.routeMode)
        assertEquals("smartgate", BifrostConnectionRouteContract.presentationMode(gate))
        try {
            BifrostConnectionRouteContract.parse("smartgate", "global")
            throw AssertionError("ambiguous SmartGate/global route accepted")
        } catch (_: IllegalArgumentException) { }
        try {
            BifrostConnectionRouteContract.parse("smartgate", "smartgate")
            throw AssertionError("presentation mode accepted as route mode")
        } catch (_: IllegalArgumentException) { }
    }

    @Test
    fun smartGateAdvancedFrontIsExplicitlyCollapsedAndPurelyPresentational() {
        val gate = BifrostUiStateReducer.reduce(BifrostUiState(mode = "smartgate"), BifrostUiEvent.ShowAdvancedFront(true))
        assertTrue(gate.showAdvancedFront)
        val ordinary = BifrostUiStateReducer.reduce(gate, BifrostUiEvent.Mode("smart"))
        assertFalse(ordinary.showAdvancedFront)
    }
}
