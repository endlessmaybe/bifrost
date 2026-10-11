package com.bifrost.client

import java.net.Inet6Address
import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

class InterfaceAddressTest {
    @Test fun scopedIpv6IsPassedToNativeAsAnUnscopedPrefix() {
        val raw = InetAddress.getByName("fe80::1234").address
        val scoped = Inet6Address.getByAddress(null, raw, 19)
        assertTrue(scoped.hostAddress!!.contains('%'))
        val prefix = BifrostInterfaceAddress.prefix(scoped, 64)
        assertFalse(prefix.contains('%'))
        assertTrue(prefix.endsWith("/64"))
        assertArrayEquals(raw, InetAddress.getByName(prefix.substringBefore('/')).address)
        assertEquals("192.0.2.5/24", BifrostInterfaceAddress.prefix(InetAddress.getByName("192.0.2.5"), 24))
    }
}
