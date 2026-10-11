package com.bifrost.client

/** Only a contract-validated device challenge rejection proves loss of this identity. */
internal class BifrostDeviceRevokedException : IllegalStateException("BF-AUTH-003") {
    companion object {
        fun confirmed(status: Int, code: String?): Boolean =
            status == 401 && code == "BF-AUTH-003" || status == 404 && code == "BF-DEVICE-404"
    }
}
