package com.bifrost.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostJsonStringTest {
    @Test fun stringBytesMatchControlIncludingSlashesAndUnicode() {
        val pairs = listOf(
            "https://example.test/a/b" to "\"https://example.test/a/b\"",
            "</script>" to "\"</script>\"",
            "公钥/🗝\u2028\u2029" to "\"公钥/🗝\u2028\u2029\"",
            "\"\\\b\u000c\n\r\t\u0000\u001f" to "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f\"",
            "\ud800/\udc00" to "\"\\ud800/\\udc00\"",
        )
        for ((input, expected) in pairs) assertEquals(expected, BifrostJsonString.quote(input))
    }

    @Test fun configKeyAndControlAndUpdateUseIdenticalProtocolStringBytes() {
        val payload = JSONObject().put("path", "/v1/config/manifest").put("key/", "base64/leaf=\n")
        val expected = "{\"key/\":\"base64/leaf=\\n\",\"path\":\"/v1/config/manifest\"}"
        assertEquals(expected, ConfigKeyTrust.canonicalJson(payload))
        val control = BifrostControlClient(android.content.ContextWrapper(null), true)
        val method = BifrostControlClient::class.java.getDeclaredMethod("canonical", Any::class.java).apply { isAccessible = true }
        assertEquals(expected, method.invoke(control, payload))
        val context = object : android.content.ContextWrapper(null) {
            override fun getSharedPreferences(name: String, mode: Int): android.content.SharedPreferences =
                java.lang.reflect.Proxy.newProxyInstance(
                    android.content.SharedPreferences::class.java.classLoader,
                    arrayOf(android.content.SharedPreferences::class.java),
                ) { _, _, _ -> throw AssertionError("Serialization must not read preferences") } as android.content.SharedPreferences
        }
        val update = BifrostUpdateManager(context, object : ReleaseBootstrapStore {
            override fun reserve(expectedPreviousSequence: Long, operationId: String) = false
        })
        val updateMethod = BifrostUpdateManager::class.java.getDeclaredMethod("canonicalJson", Any::class.java).apply { isAccessible = true }
        assertEquals(expected, updateMethod.invoke(update, payload))
    }

    @Test fun androidFrameworkEscapingDifferenceIsExplicitlyCovered() {
        if (System.getProperty("java.vm.name") == "Dalvik" || System.getProperty("bifrost.test.androidJson") == "true") {
            assertEquals("\"a\\/b\"", JSONObject.quote("a/b"))
            assertNotEquals(JSONObject.quote("a/b"), BifrostJsonString.quote("a/b"))
        }
    }
}
