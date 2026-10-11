package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostInitialReleaseTest {
    @Test fun manualUpgradeAfterFailedDownloadCanUseTheNewerSignedApkAnchor() {
        var stored: String? = null
        val machine = ReleaseBootstrapStateMachine({ stored }, { stored = it; true })
        assertTrue(machine.initializeInstalledApk(100L))
        assertTrue(machine.reserve(stored!!, 100L, "download-failed"))
        assertTrue(machine.abort(stored!!, "download-failed"))
        assertFalse(machine.reserve(stored!!, 200L, "initial-apk-200"))
        assertTrue(machine.advanceUnusedInstalledApkAnchor(200L))
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertFalse(machine.advanceUnusedInstalledApkAnchor(100L))
        assertFalse(machine.reserve(stored!!, 100L, "old-apk-replay"))
        assertTrue(machine.reserve(stored!!, 200L, "initial-apk-200"))
        assertTrue(machine.commit(stored!!, "initial-apk-200"))
    }

    @Test fun manualUpgradeCannotResetReservationsTombstonesOrCorruption() {
        var stored: String? = null
        val machine = ReleaseBootstrapStateMachine({ stored }, { stored = it; true })
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertTrue(machine.initializeInstalledApk(100L))
        assertTrue(machine.reserve(stored!!, 100L, "owned-install"))
        val reserved = stored
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertEquals(reserved, stored)
        assertTrue(machine.commit(stored!!, "owned-install"))
        val committed = stored
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertEquals(committed, stored)
        stored = "corrupt"
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertEquals("corrupt", stored)
    }

    @Test fun failedAnchorAdvanceDoesNotGrantTheNewSequence() {
        var stored: String? = null
        var failWrite = false
        val machine = ReleaseBootstrapStateMachine({ stored }, { if (failWrite) false else { stored = it; true } })
        assertTrue(machine.initializeInstalledApk(100L))
        failWrite = true
        assertFalse(machine.advanceUnusedInstalledApkAnchor(200L))
        assertFalse(machine.reserve(stored!!, 200L, "initial-apk-200"))
    }

    @Test fun signedApkAnchorAllowsANonAdjacentFutureReleaseOnce() {
        var stored: String? = null
        val machine = ReleaseBootstrapStateMachine({ stored }, { stored = it; true })
        assertTrue(machine.initializeInstalledApk(1788700123L))
        // Sequences are timestamps. The previous sequence is the installed
        // APK's anchor, never the next manifest's sequence minus one.
        assertFalse(machine.reserve(stored!!, 1788800788L, "future-release-operation"))
        assertTrue(machine.reserve(stored!!, 1788700123L, "future-release-operation"))
        assertTrue(machine.commit(stored!!, "future-release-operation"))
        assertFalse(machine.initializeInstalledApk(1788800789L))
        assertFalse(machine.reserve(stored!!, 1788700123L, "replayed-release-operation"))
    }

    @Test fun currentManifestCanBeAnchoredWithoutReinstallingTheApk() {
        var stored: String? = null
        val machine = ReleaseBootstrapStateMachine({ stored }, { stored = it; true })
        assertTrue(machine.initializeInstalledApk(12345678L))
        assertTrue(machine.reserve(stored!!, 12345678L, "initial-apk-12345678"))
        assertTrue(machine.commit(stored!!, "initial-apk-12345678"))
        assertFalse(machine.initializeInstalledApk(12345678L))
    }

    @Test fun failedInstallRetainsOriginalAnchorAndCorruptionNeverReinitializes() {
        var stored: String? = null
        val machine = ReleaseBootstrapStateMachine({ stored }, { stored = it; true })
        assertTrue(machine.initializeInstalledApk(100L))
        assertTrue(machine.reserve(stored!!, 100L, "attempt-one"))
        assertTrue(machine.abort(stored!!, "attempt-one"))
        assertTrue(machine.reserve(stored!!, 100L, "attempt-two"))
        assertFalse(machine.initializeInstalledApk(200L))
        stored = "corrupted-record"
        assertFalse(machine.initializeInstalledApk(200L))
        assertFalse(machine.reserve(stored!!, 100L, "attempt-three"))
    }

    @Test fun invalidAnchorOrFailedDurableWriteCannotGrantBootstrap() {
        var writes = 0
        val machine = ReleaseBootstrapStateMachine({ null }, { writes++; false })
        assertFalse(machine.initializeInstalledApk(0L))
        assertFalse(machine.initializeInstalledApk(-1L))
        assertEquals(0, writes)
        assertFalse(machine.initializeInstalledApk(1L))
        assertEquals(1, writes)
    }
}
