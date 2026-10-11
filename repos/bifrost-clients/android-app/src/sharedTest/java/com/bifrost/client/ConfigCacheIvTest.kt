package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class ConfigCacheIvTest {
    @Test fun providerGeneratedIvIsStoredAndCanDecryptTheCache() {
        val key = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")
        val content = "TEST-ONLY encrypted cache".toByteArray()
        val first = BifrostConfigCodec.encode(content, key)
        val second = BifrostConfigCodec.encode(content, key)
        assertFalse(first.copyOfRange(1, 13).contentEquals(second.copyOfRange(1, 13)))
        assertArrayEquals(content, BifrostConfigCodec.decode(first, key))
        assertArrayEquals(content, BifrostConfigCodec.decode(second, key))
        first[1] = (first[1].toInt() xor 1).toByte()
        assertThrows(Exception::class.java) { BifrostConfigCodec.decode(first, key) }
    }
}
