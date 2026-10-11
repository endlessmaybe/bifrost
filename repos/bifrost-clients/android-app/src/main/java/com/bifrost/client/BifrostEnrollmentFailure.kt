package com.bifrost.client

import org.json.JSONObject

/** Only known codes from a contract-validated error response cross into UI. */
internal object BifrostEnrollmentFailure {
    fun code(status: Int, response: JSONObject?): String {
        val code = response?.optJSONObject("error")?.opt("code") as? String
        return when {
            status == 400 && code in setOf("BF-ENROLL-001", "BF-ENROLL-002", "BF-ENROLL-003") -> code!!
            status == 429 -> "BF-ENROLL-RATE-LIMIT"
            else -> "BF-ENROLL-HTTP"
        }
    }
}
