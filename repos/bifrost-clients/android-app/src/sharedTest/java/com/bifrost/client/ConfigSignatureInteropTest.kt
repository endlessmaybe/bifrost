package com.bifrost.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Executes identical Control vectors on the host JVM and Android framework. */
class ConfigSignatureInteropTest {
    @Test
    fun productionConfigKeyStateInteropVectorVerifiesAcrossControlAndAndroid() {
        val state = JSONObject(
            """{"version":1,"purpose":"config-signing-key-state","root_key_id":"bifrost-root-v1","root_fingerprint":"927f6805f64a39b053573c834813fae05cb0ffb2bc89762f29b718a7a78d63f9","generation":3,"active_key_id":"config-signing-v3","trusted_keys":[{"key_id":"config-signing-v1","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAi6QsvjrIm172Gyi4Hgl7aes6xwTGyX2ZPNGecspN/Jc=\n-----END PUBLIC KEY-----\n","fingerprint":"499b8d8662929a4e723365da39aa4b71485cc6ec097923b1cc0cf70d917b0c34","activation_floor":26,"retirement_floor":null},{"key_id":"config-signing-v3","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAef72vsOcp7qUwXpf5woo2JewaRo4Cp2Qq5/ZN+RHleU=\n-----END PUBLIC KEY-----\n","fingerprint":"f15f0bfa364160f92c54b47e9187c1d3d13ba9fcfa7cc959517312b9e36715d2","activation_floor":45,"retirement_floor":null}],"previous_state_digest":"4e5e5439c24b4302f8e0a3a2b74b28c7aadb6a5e39402a125e8c4eb56fbbd2c2","signature":"e87aa04fVxiKLpFBBWB-z-ztgSVBVqQOCd1qAYj-ksrzxWMPys0nG2WnwsDjhgsEuK4I43bFG_mQJNhev2zRDg"}"""
        )
        val rootPem = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAN9xea5Mh4CsoOZ7oRDhGesPWG5tFBZ5M+lAcbDzxOgU=
-----END PUBLIC KEY-----
"""
        BifrostProtocolContract.validateSchema("ConfigKeyState", state)
        val manifest = JSONObject()
            .put("schema_version", "1.0").put("config_version", 66)
            .put("rollback_floor", 66).put("digest", "a".repeat(64))
            .put("config_key_state", state)
        BifrostProtocolContract.validateResponse("/v1/config/manifest", manifest)
        assertEquals(66L, BifrostManifestValidator.validate(manifest, 65).version)
        for (invalid in listOf(
            JSONObject(manifest.toString()).put("unexpected", true),
            JSONObject(manifest.toString()).put("config_key_state", JSONObject.NULL),
            JSONObject(manifest.toString()).put("config_key_state", "invalid"),
            JSONObject(manifest.toString()).put("config_version", 64),
        )) assertThrows(IllegalStateException::class.java) { BifrostManifestValidator.validate(invalid, 65) }
        val verified = ConfigKeyTrust.verify(
            state,
            rootKeyId = "bifrost-root-v1",
            rootPem = rootPem,
            rootFingerprint = "927f6805f64a39b053573c834813fae05cb0ffb2bc89762f29b718a7a78d63f9",
            currentConfigVersion = 66,
        )
        assertEquals(3L, verified.generation)
        assertEquals("config-signing-v3", verified.activeKeyId)
        val unsigned = JSONObject(state.toString()).apply { remove("signature") }
        // The pre-fix reconstruction fails on the framework because both
        // production leaf PEM values contain '/'. Demonstrate the regression
        // on Android, rather than signing test data with the same serializer.
        if (System.getProperty("java.vm.name") == "Dalvik" || System.getProperty("bifrost.test.androidJson") == "true") {
            fun legacy(value: Any?): String = when (value) {
                null, JSONObject.NULL -> "null"
                is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + legacy(value.get(it)) }
                is org.json.JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { legacy(value.get(it)) }
                is String -> JSONObject.quote(value)
                else -> value.toString()
            }
            assertNotEquals(ConfigKeyTrust.canonicalJson(unsigned), legacy(unsigned))
            val verifier = com.google.crypto.tink.subtle.Ed25519Verify(ConfigKeyTrust.rawEd25519PublicKey(rootPem))
            assertThrows(java.security.GeneralSecurityException::class.java) {
                verifier.verify(java.util.Base64.getUrlDecoder().decode(state.getString("signature")), legacy(unsigned).toByteArray(Charsets.UTF_8))
            }
        }
        val tampered = JSONObject(state.toString()).put("generation", 4)
        assertEquals("BF-CONFIG-KEY-SIGNATURE", assertThrows(IllegalStateException::class.java) {
            ConfigKeyTrust.verify(tampered, "bifrost-root-v1", rootPem,
                "927f6805f64a39b053573c834813fae05cb0ffb2bc89762f29b718a7a78d63f9", currentConfigVersion = 66)
        }.message)
    }
}
