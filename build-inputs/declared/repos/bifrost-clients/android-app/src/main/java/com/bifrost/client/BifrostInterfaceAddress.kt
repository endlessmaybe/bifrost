package com.bifrost.client

import java.net.InetAddress

internal object BifrostInterfaceAddress {
    fun prefix(address: InetAddress, bits: Int): String {
        val raw = address.address
        require(bits in 0..(raw.size * 8)) { "BF-NETWORK-OBSERVER-UNAVAILABLE" }
        // Android attaches an interface scope to link-local IPv6 addresses.
        // libbox consumes IP prefixes and its native parser rejects zones.
        // Reconstructing the numeric address from bytes avoids carrying a
        // hostname or scope into the native boundary.
        return InetAddress.getByAddress(raw).hostAddress + "/" + bits
    }
}
