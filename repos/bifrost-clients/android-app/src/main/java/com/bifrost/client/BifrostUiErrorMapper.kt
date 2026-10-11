package com.bifrost.client

import com.bifrost.client.ui.model.BifrostUiText

/**
 * Converts internal failures to stable, actionable Chinese UI text.
 *
 * Exception messages are inspected only for a complete, locally-defined
 * Bifrost error code.  The original text is never returned, logged, or put in
 * a notification; this prevents URLs, paths, tokens, and node material from
 * crossing the UI boundary.
 */
internal object BifrostUiErrorMapper {
    // BF- plus at most 61 code characters keeps the complete token <= 64 bytes.
    private val codePattern = Regex("BF-[A-Z0-9-]{1,61}")
    private val runtimeMessages = mapOf(
        "BF-NOT-ENROLLED" to "请先激活 Bifrost，再使用快捷连接 [BF-NOT-ENROLLED]",
        "BF-VPN-PERMISSION" to "首次连接需要在 Bifrost 中确认系统 VPN 授权 [BF-VPN-PERMISSION]",
        "BF-CONNECTION-IN-FLIGHT" to "连接、断开、Root 授权或更新尚未完成，请等待当前操作结束后重试 [BF-CONNECTION-IN-FLIGHT]",
        "BF-ROOT-UNSUPPORTED" to "当前系统缺少 Root 网络所需组件，请使用普通 VPN 模式 [BF-ROOT-UNSUPPORTED]",
        "BF-ROOT-COMMAND" to "系统未能配置 Root 网络，请关闭 Root 模式并分享运行诊断 [BF-ROOT-COMMAND]",
        "BF-ROOT-READBACK" to "Root 网络状态检查未通过，请关闭 Root 模式并分享运行诊断 [BF-ROOT-READBACK]",
        "BF-ROOT-PERMISSION" to "尚未获得 Root 权限，请在 Root 管理器中允许 Bifrost 后重试 [BF-ROOT-PERMISSION]",
        "BF-ROOT-OTHER-VPN" to "请先断开其他 VPN，再连接 Bifrost Root 模式 [BF-ROOT-OTHER-VPN]",
        "BF-ROOT-START" to "Root 网络通道未能建立，可关闭 Root 模式继续使用普通 VPN [BF-ROOT-START]",
        "BF-ROOT-COLLISION" to "检测到占用的 Root 网络规则，请先断开后重试 [BF-ROOT-COLLISION]",
        "BF-ROOT-CLEANUP" to "Root 网络清理未完成，请在应用内再次断开 [BF-ROOT-CLEANUP]",
        "BF-AUTH-003" to "此设备授权已失效，请使用新的注册码或账号恢复码重新登记 [BF-AUTH-003]",
        "BF-LOGOUT-REMOTE" to "服务端尚未确认注销，请重试；旧设备绑定暂未释放 [BF-LOGOUT-REMOTE]",
        "BF-ENROLL-001" to "注册码无效、已撤销，或已用于另一台 Android 设备。请核对注册码；已有账号请使用恢复码 [BF-ENROLL-001]",
        "BF-ENROLL-002" to "注册码已过期，请联系管理员重新获取 [BF-ENROLL-002]",
        "BF-ENROLL-003" to "本设备已有账号绑定，请恢复已有账号 [BF-ENROLL-003]",
        "BF-ENROLL-HTTP" to "服务器未接受登记请求，请稍后重试或联系管理员 [BF-ENROLL-HTTP]",
        "BF-ENROLL-RATE-LIMIT" to "登记尝试过于频繁，请稍后重试 [BF-ENROLL-RATE-LIMIT]",
        "BF-RUNTIME-HEALTH" to "代理连接健康检查失败，请重试或更换线路 [BF-RUNTIME-HEALTH]",
        "BF-TRANSPORT-PROBE-PROXY" to "代理链路未能建立，请更换前置线路后重试 [BF-TRANSPORT-PROBE-PROXY]",
        "BF-TRANSPORT-PROBE-TLS" to "代理链路的安全连接检查失败，请重试或更换线路 [BF-TRANSPORT-PROBE-TLS]",
        "BF-TRANSPORT-PROBE-HTTP" to "代理链路未返回预期检查响应，请重试或更换线路 [BF-TRANSPORT-PROBE-HTTP]",
    )

    private fun stableCode(error: Throwable): String? {
        val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
        var current: Throwable? = error
        while (current != null && seen.add(current)) {
            val raw = current.message?.trim()
            if (!raw.isNullOrEmpty()) {
                // A suffix is not part of a stable code.  Treat strings such as
                // "BF-CODE: secret" as unknown so secret-bearing text cannot
                // select a tailored UI message.
                if (raw.matches(codePattern) && (BifrostErrorRegistry.isRegistered(raw) || raw in runtimeMessages)) return raw
            }
            current = current.cause
        }
        return null
    }

    internal fun isCode(error: Throwable, expected: String): Boolean = stableCode(error) == expected

    internal fun code(error: Throwable): String = stableCode(error) ?: "BF-INTERNAL"

    internal fun message(action: String, error: Throwable): String {
        val code = stableCode(error)
        runtimeMessages[code]?.let { return it }
        val override = when (code) {
            "BF-RELEASE-ROLLBACK" -> "更新通道提供的版本早于本机已信任版本，已阻止降级。请等待发布通道同步后重试 [BF-RELEASE-ROLLBACK]"
            "BF-RELEASE-DIGEST" -> "更新文件校验失败，未安装。请重试；若持续失败，请检查发布服务器文件 [BF-RELEASE-DIGEST]"
            "BF-RELEASE-REDIRECT" -> "更新下载入口暂不可用，请稍后重试 [BF-RELEASE-REDIRECT]"
            "BF-BLACKHOLE-UNAVAILABLE" -> BifrostUiText.errorBlackhole
            "BF-CONFIG-CACHE-MISSING" -> BifrostUiText.errorConfigMissing
            "BF-SOURCE-SELECTION-REQUIRED" -> BifrostUiText.errorSourceRequired
            "BF-APP-ALLOW-EMPTY" -> BifrostUiText.errorAllowEmpty
            "BF-APP-EXCLUDE-EMPTY" -> BifrostUiText.errorExcludeEmpty
            "BF-CONFIG-TRANSACTION" -> BifrostUiText.errorTransaction
            else -> null
        }
        // An unrecognised/tainted exception has no stable code.  Keep the
        // action-specific wording as the declared safe override; every
        // recognised code still resolves through the generated registry.
        if (override != null) return override
        if (code == null) return transportMessage(action, error) ?: BifrostUiText.actionFailed(action)
        val message = BifrostErrorRegistry.describe(code).messageZh
        // A generic catalog entry is not evidence of bad user input. Keep the
        // locally registered diagnostic so activation failures are actionable,
        // without ever exposing a server message or exception payload.
        return if (message == BifrostUiText.genericRequestFailure) {
            BifrostUiText.diagnosticFailure(action, code)
        } else message
    }

    // Fixed descriptions selected by exception type, never by server text.
    // These explain a failure without changing the offline/security decision.
    private fun transportMessage(action: String, error: Throwable): String? {
        val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
        var current: Throwable? = error
        while (current != null && seen.add(current)) {
            when (current) {
                is BifrostReachableStatusException -> return when (current.status) {
                    502, 503, 504, 530 -> "${action}暂未完成：服务器暂时不可用，请稍后重试 [BF-CONTROL-HTTP]"
                    401, 403 -> "${action}失败：服务器未接受设备认证，请重试认证 [BF-AUTH-PROOF]"
                    410 -> "${action}失败：设备授权已失效 [BF-AUTH-PROOF]"
                    429 -> "${action}失败：请求过于频繁，请稍后重试 [BF-CONTROL-HTTP]"
                    else -> "${action}失败：服务器返回 HTTP ${current.status} [BF-CONTROL-HTTP]"
                }
                is javax.net.ssl.SSLPeerUnverifiedException -> return "${action}失败：服务器证书验证未通过，请确认系统时间 [BF-CONTROL-CERT]"
                is javax.net.ssl.SSLException -> return "${action}失败：安全连接未建立，请切换 Wi-Fi 或移动网络重试 [BF-CONTROL-SSL]"
                is java.net.UnknownHostException -> return "${action}失败：无法解析服务器地址，请切换网络重试 [BF-CONTROL-CONNECT]"
                is java.net.SocketTimeoutException -> return "${action}失败：服务器响应超时，请重试 [BF-CONTROL-DEADLINE]"
                is java.net.SocketException -> return "${action}失败：与服务器的连接中断，请重试 [BF-CONTROL-CONNECT]"
                is java.io.IOException -> return "${action}失败：响应读取未完成，请重试 [BF-CONTROL-RESPONSE]"
            }
            current = current.cause
        }
        return null
    }

    /** Map only client-owned result states to UI text; never surface a
     * server/transport message or exception string directly. */
    internal fun success(action: String, state: String): String = when (state) {
        "enrolled" -> BifrostUiText.enrolledSuccess
        "resumed" -> "已恢复此设备原有账号；如需换号，请先注销此设备"
        "not-enrolled" -> BifrostUiText.needsActivation
        "pending-approval" -> BifrostUiText.recoveryPendingApproval
        "pairing-created" -> BifrostUiText.pairingCreated
        "paired" -> BifrostUiText.pairedSuccess
        // "cached" is returned only after the online signed manifest matches
        // the installed configuration. Network fallback has its own state.
        "cached" -> BifrostUiText.configUpToDate
        "updated", "staged" -> BifrostUiText.configUpdated
        "up-to-date" -> if (action == BifrostUiText.updateAction) "当前已是最新版本" else BifrostUiText.configUpToDate
        "logged-out" -> BifrostUiText.loggedOut
        "disabled" -> BifrostUiText.controlDisabled
        "permission-required" -> BifrostUiText.updatePermissionRequired
        "unavailable" -> BifrostUiText.updateUnavailable
        "pending" -> BifrostUiText.updatePending
        "available" -> BifrostUiText.updateAvailable
        "offline" -> BifrostUiText.offlineConfig
        "recovery-ready" -> BifrostUiText.recoveryRenewed
        else -> BifrostUiText.actionFailed(action, retryNetwork = false)
    }
}
