package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostFailureRecoveryTest {
    private val failure = "open connection to example.com:443 using outbound/selector[proxy]: dial tcp: i/o timeout"
    @Test fun sparseFailuresTriggerLowTrafficRecoveryWithCooldown() {
        val policy = BifrostFailureRecovery()
        policy.observe(1000, failure); policy.observe(2000, failure)
        assertFalse(policy.claim(2100, 0.0, true))
        policy.observe(3000, failure)
        assertFalse(policy.claim(3100, 1_000_000.0, true))
        assertFalse(policy.claim(3100, 0.0, false))
        assertTrue(policy.claim(3200, 0.0, true))
        repeat(4) { policy.observe(4000L + it * 1000, failure) }
        assertFalse(policy.claim(8000, 0.0, true))
    }
    @Test fun networkGraceExpiredFailuresAndNonProxyErrorsCannotTrigger() {
        val policy = BifrostFailureRecovery()
        policy.networkChanged(1000)
        repeat(3) { policy.observe(2000L + it * 1000, failure) }
        assertFalse(policy.claim(10000, 0.0, true))
        policy.observe(10000, failure);policy.observe(140000, failure);policy.observe(141000, failure)
        assertFalse(policy.claim(142000, 0.0, true))
        assertFalse(BifrostFailureRecovery.isTransportFailure("dns exchange failed: timeout"))
        assertFalse(BifrostFailureRecovery.isTransportFailure("open connection to example.com using outbound/direct[direct]: timeout"))
        assertFalse(BifrostFailureRecovery.isTransportFailure("connection download closed: context canceled"))
        assertTrue(BifrostFailureRecovery.isTransportFailure("connection download handshake: connection reset by peer"))
    }
    @Test fun intermittentBrowsingFailuresWithinTwoMinutesAreNotForgotten() {
        val policy = BifrostFailureRecovery()
        policy.observe(10000, failure);policy.observe(40000, failure);policy.observe(70000, failure)
        assertTrue(policy.claim(71000, 1000.0, true))
    }
}
