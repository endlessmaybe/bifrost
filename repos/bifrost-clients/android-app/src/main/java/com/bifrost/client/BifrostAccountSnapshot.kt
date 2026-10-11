package com.bifrost.client

/** Account presence is independent of the availability of its configuration. */
internal data class BifrostAccountSnapshot(
    val publicId: String,
    val hasRecovery: Boolean,
    val needsResume: Boolean,
) {
    val enrolled: Boolean get() = publicId.isNotBlank()

    companion object {
        val KEYS = setOf("public_id", "account_recovery_code", "session_token", "config_version", "enrollment_pending_origin")

        fun from(values: Map<String, String?>): BifrostAccountSnapshot {
            val id = values["public_id"].orEmpty()
            val resume = id.isBlank() && listOf("session_token", "enrollment_pending_origin").any {
                !values[it].isNullOrBlank()
            } || id.isBlank() && (values["config_version"]?.toLongOrNull() ?: 0L) > 0
            return BifrostAccountSnapshot(id, !values["account_recovery_code"].isNullOrBlank(), resume)
        }

        fun requireSessionIdentity(previous: String, returned: String) {
            check(returned.isNotBlank() && (previous.isBlank() || previous == returned)) { "BF-SESSION-RESPONSE" }
        }
    }
}

/** An unreadable store is unknown, never a successful read of an empty account. */
internal data class BifrostAccountDisplay(
    val snapshot: BifrostAccountSnapshot? = null,
    val unavailable: Boolean = false,
) {
    val ready: Boolean get() = snapshot != null && !unavailable && !snapshot.needsResume
    val message: String get() = when {
        unavailable -> "暂时无法读取账号，原有数据已保留，请重试"
        snapshot?.needsResume == true -> "正在恢复已有设备登记，请稍候或重试"
        snapshot == null -> "正在读取账号"
        else -> ""
    }

    fun accept(result: Result<BifrostAccountSnapshot>): BifrostAccountDisplay = result.fold(
        { BifrostAccountDisplay(it) },
        { copy(unavailable = true) },
    )
}

/** A damaged cache may be replaced only by the normal verified online path. */
internal object BifrostConfigRepairPolicy {
    fun <T> readForOnlineRepair(read: () -> T?): T? = try {
        read()
    } catch (error: IllegalStateException) {
        if (error.message != "BF-CONFIG-CACHE-CORRUPT") throw error
        null
    }

    fun requireSameVersionDigest(version: Long, storedVersion: Long, digest: String, storedDigest: String) {
        if (version == storedVersion && storedDigest.isNotBlank())
            check(storedDigest == digest) { "BF-CONFIG-EQUIVOCATION" }
    }
}
