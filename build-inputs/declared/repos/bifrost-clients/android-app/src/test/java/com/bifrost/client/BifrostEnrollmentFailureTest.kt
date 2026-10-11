package com.bifrost.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BifrostEnrollmentFailureTest {
    private fun response(code: Any) = JSONObject().put("error", JSONObject().put("code", code).put("message", "secret payload"))

    @Test fun rejectedCodeIsNotMisreportedAsNetworkFailure() {
        for (code in listOf("BF-ENROLL-001", "BF-ENROLL-002", "BF-ENROLL-003")) {
            val mapped = BifrostEnrollmentFailure.code(400, response(code))
            assertEquals(code, mapped)
            val message = BifrostUiErrorMapper.message("登记", IllegalStateException(mapped))
            assertTrue(message.contains(code))
            assertFalse(message.contains("检查网络"))
            assertFalse(message.contains("secret"))
        }
    }

    @Test fun malformedOrUnrelatedErrorCannotSelectCredentialMessage() {
        for (value in listOf<Any>("BF-ENROLL-001: secret", "BF-OTHER", 123))
            assertEquals("BF-ENROLL-HTTP", BifrostEnrollmentFailure.code(400, response(value)))
        assertEquals("BF-ENROLL-HTTP", BifrostEnrollmentFailure.code(503, response("BF-ENROLL-001")))
        assertEquals("BF-ENROLL-HTTP", BifrostEnrollmentFailure.code(400, null))
        assertEquals("BF-ENROLL-RATE-LIMIT", BifrostEnrollmentFailure.code(429, null))
    }
}
