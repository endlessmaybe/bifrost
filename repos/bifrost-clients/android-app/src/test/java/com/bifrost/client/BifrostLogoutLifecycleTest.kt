package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class BifrostLogoutLifecycleTest {
    @Test fun failedRemoteLogoutPreservesIdentityForRetry() {
        var cleared = false
        try {
            BifrostLogoutCoordinator.complete({ throw IOException("offline") }, { cleared = true })
            fail("offline logout cannot claim completion")
        } catch (_: IOException) { }
        assertFalse(cleared)
        val order = mutableListOf<String>()
        BifrostLogoutCoordinator.complete({ order += "revoked" }, { order += "cleared" })
        assertEquals(listOf("revoked", "cleared"), order)
    }

    @Test fun lostSuccessfulResponseCanFinishOnConfirmedRevocation() {
        var cleared = false
        BifrostLogoutCoordinator.complete({ throw BifrostDeviceRevokedException() }, { cleared = true })
        assertTrue(cleared)
        cleared = false
        try {
            BifrostLogoutCoordinator.complete({ BifrostLogoutCoordinator.remoteFailure(401) }, { cleared = true })
            fail("expired bearer alone is not revocation")
        } catch (_: IllegalStateException) { }
        assertFalse(cleared)
    }

    @Test fun revocationRequiresExactChallengeResponse() {
        assertTrue(BifrostDeviceRevokedException.confirmed(401, "BF-AUTH-003"))
        assertTrue(BifrostDeviceRevokedException.confirmed(404, "BF-DEVICE-404"))
        for (status in listOf(200, 403, 500, 503)) assertFalse(BifrostDeviceRevokedException.confirmed(status, "BF-AUTH-003"))
        for (code in listOf(null, "BF-AUTH-005", "BF-AUTH-003: extra")) assertFalse(BifrostDeviceRevokedException.confirmed(401, code))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(BifrostDeviceRevokedException()))
    }
}
