package com.bifrost.client

import com.google.crypto.tink.subtle.X25519
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class DeviceKeyAgreementTest {
    @Test fun decodedEnvelopeKeyWorksThroughTheProductionKeyAgreementBoundary() {
        val own = X25519.generatePrivateKey()
        val peer = X25519.generatePrivateKey()
        val ownPublic = X25519.publicFromPrivate(own)
        val peerPublic = X25519.publicFromPrivate(peer)
        val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00)
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(prefix + peerPublic)
        val decoded = DeviceKeys.decodeX25519PublicRaw(encoded)
        val privateCopy = own.copyOf()
        try {
            val shared = DeviceKeys.deriveEncryptionSharedSecret(decoded) { privateCopy }
            assertArrayEquals(X25519.computeSharedSecret(peer, ownPublic), shared)
            assertTrue(privateCopy.all { it == 0.toByte() })
            assertArrayEquals(peerPublic, decoded)
            shared.fill(0)
        } finally { own.fill(0); peer.fill(0); privateCopy.fill(0) }
    }

    @Test fun rejectsWrongKeyLengthsBeforeReadingPrivateMaterial() {
        for (size in listOf(0, 31, 33, 44)) {
            var read = false
            assertThrows(IllegalStateException::class.java) {
                DeviceKeys.deriveEncryptionSharedSecret(ByteArray(size)) { read = true; X25519.generatePrivateKey() }
            }
            assertFalse(read)
        }
    }

    @Test fun rejectsLowOrderPeerAndWipesPrivateMaterial() {
        val key = X25519.generatePrivateKey()
        val error = assertThrows(IllegalStateException::class.java) {
            DeviceKeys.deriveEncryptionSharedSecret(ByteArray(32)) { key }
        }
        assertEquals("BF-DEVICE-KEYS-CORRUPT", error.message)
        assertTrue(key.all { it == 0.toByte() })
    }
}
