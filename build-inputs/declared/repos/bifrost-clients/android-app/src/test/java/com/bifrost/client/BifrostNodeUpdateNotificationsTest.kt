package com.bifrost.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class BifrostNodeUpdateNotificationsTest {
    @Test fun accountRevocationCountersDoNotAnnounceNewNodes() {
        val original = """{"config_version":69,"anti_rollback":69,"account":{"public_id":"fixture"},"sources":[{"code":"A","transport":{"uuid":"one","port":443}}],"countries":[],"routing":{"ruleset_version":"one"},"core_policy":{"default":"sing-box"}}"""
        val revoked = original.replace(":69", ":70")
        assertEquals(BifrostNodeUpdateNotifications.fingerprint(original), BifrostNodeUpdateNotifications.fingerprint(revoked))
        assertFalse(BifrostNodeUpdateNotifications.shouldNotify(69, 70, 69, false))
        val changed = revoked.replace("\"uuid\":\"one\"", "\"uuid\":\"two\"")
        assertNotEquals(BifrostNodeUpdateNotifications.fingerprint(original), BifrostNodeUpdateNotifications.fingerprint(changed))
        assertTrue(BifrostNodeUpdateNotifications.shouldNotify(69, 70, 69, true))
    }
    @Test fun onlyVerifiedVersionAdvancesProduceNewNotices() {
        assertTrue(BifrostNodeUpdateNotifications.shouldNotify(69, 70, 69))
        assertFalse(BifrostNodeUpdateNotifications.shouldNotify(0, 70, 0))
        assertFalse(BifrostNodeUpdateNotifications.shouldNotify(69, 69, 0))
        assertFalse(BifrostNodeUpdateNotifications.shouldNotify(70, 69, 0))
        assertFalse(BifrostNodeUpdateNotifications.shouldNotify(69, 70, 70))
    }
}
