package com.bifrost.client

import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class BifrostFeatureTransitionTest {
    @After fun clean() { BifrostApplicationPolicySnapshotRegistry.clear(); BifrostUpdateInstallGate.end() }

    @Test fun rootPermissionWaitExcludesQuickConnectAndInstallation() {
        val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        val owner = BifrostApplicationPolicySnapshotRegistry.beginConfigurationChange()
        assertNotNull(owner)
        assertTrue(BifrostFeaturePreferences.changing)
        assertFalse(BifrostApplicationPolicySnapshotRegistry.register("a".repeat(32), snapshot))
        assertFalse(BifrostUpdateInstallGate.begin())
        BifrostApplicationPolicySnapshotRegistry.endConfigurationChange(owner)
        assertFalse(BifrostFeaturePreferences.changing)
        assertTrue(BifrostApplicationPolicySnapshotRegistry.register("a".repeat(32), snapshot))
        assertNull(BifrostApplicationPolicySnapshotRegistry.beginConfigurationChange())
    }

    @Test fun latePermissionCallbackCannotReleaseAnotherModeChange() {
        val first = BifrostApplicationPolicySnapshotRegistry.beginConfigurationChange()
        BifrostApplicationPolicySnapshotRegistry.endConfigurationChange(first)
        val second = BifrostApplicationPolicySnapshotRegistry.beginConfigurationChange()
        assertNotNull(second)
        BifrostApplicationPolicySnapshotRegistry.endConfigurationChange(first)
        assertTrue(BifrostFeaturePreferences.changing)
        BifrostApplicationPolicySnapshotRegistry.endConfigurationChange(second)
        assertTrue(BifrostUpdateInstallGate.begin())
    }
}
