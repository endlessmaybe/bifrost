package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostNotificationTrafficTest {
    @Test fun backgroundCountersDoNotNeedVisibleChartsAndExpire() {
        val traffic = BifrostNotificationTraffic()
        traffic.accept(2 * 1024 * 1024, 28 * 1024, 10_000, true)
        assertEquals(listOf("\u2191 28.0 KB/s", "\u2193 2.0 MB/s"), traffic.lines(12_000))
        assertEquals("\u2191 28.0 KB/s\n\u2193 2.0 MB/s", traffic.text(12_000))
        assertEquals("\u2191 --\n\u2193 --", traffic.text(15_001))
        assertEquals("\u2191 --\n\u2193 --", traffic.text(9_999))
    }
    @Test fun UnavailableAndNewSessionsCannotShowStaleSpeed() {
        val traffic = BifrostNotificationTraffic()
        traffic.accept(1024, -50, 10_000, true)
        assertEquals("\u2191 0 B/s\n\u2193 1.0 KB/s", traffic.text(10_000))
        traffic.accept(0, 0, 11_000, false)
        assertEquals("\u2191 --\n\u2193 --", traffic.text(11_000))
        traffic.accept(2000, 1000, 12_000, true)
        traffic.reset()
        assertEquals("\u2191 --\n\u2193 --", traffic.text(12_000))
    }
}
