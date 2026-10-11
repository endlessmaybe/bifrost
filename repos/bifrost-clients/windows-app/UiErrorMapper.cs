namespace Bifrost;

/// <summary>
/// Stable UI error boundary. Exception text never crosses into WPF; only a
/// complete registered code may select an explicitly declared action hint.
/// All other wording comes from the generated error registry.
/// </summary>
internal static class UiErrorMapper
{
    internal static string ToUserMessage(Exception? error, string action)
    {
        var code = ExtractCode(error);
        var mapped = code switch
        {
            "BF-BLACKHOLE-UNAVAILABLE" => "安全阻断通道建立失败，请开启系统 VPN 锁定后重试",
            "BF-CONFIG-CACHE-MISSING" => "没有可用的已验证配置，请先完成设备激活",
            "BF-SOURCE-SELECTION-REQUIRED" => "请先选择源站 A 或 B",
            "BF-APP-ALLOW-EMPTY" => "包含名单不能为空，请至少选择一个应用",
            "BF-APP-EXCLUDE-EMPTY" => "排除名单不能为空，请至少选择一个应用",
            "BF-TUN-ALREADY-OPEN" => "检测到现有全局 TUN，但 Bifrost 无法安全绑定到底层物理网络，请刷新配置后重试",
            "BF-TUN-COEXIST-CUTOVER-UNSAFE" => "检测到现有全局 TUN，Bifrost 已阻止可能导致断网的路由切换；当前网络保持不变",
            "BF-TUN-ESTABLISH" => "Bifrost 切换 TUN 后真实出网失败，已自动恢复原网络；为避免再次断网，本次不会继续自动切换线路",
            "BF-TUN-DNS" or "BF-TUN-DNS-READBACK" => "Bifrost 未能接管域名解析，已取消本次连接，请重新连接",
            "BF-TUN-DNS-OWNER" => "Bifrost 虚拟网卡存在其他 DNS 设置，已保留该设置并取消连接",
            "BF-TUN-DNS-RESTORE" => "Bifrost 虚拟网卡的 DNS 恢复未完成，请使用网络修复后重新连接",
            "BF-TRANSPORT-PROBE-UNAVAILABLE" => "Bifrost 隧道已建立，但真实出网验证失败，已阻止假连接；请检查当前节点或上游网络",
            "BF-RELEASE-ROLLBACK" => "更新通道提供的版本早于本机已信任版本，已阻止降级。请等待发布通道同步后重试 [BF-RELEASE-ROLLBACK]",
            "BF-RELEASE-DIGEST" => "更新文件校验失败，未安装。请重试；若持续失败，请检查发布服务器文件 [BF-RELEASE-DIGEST]",
            "BF-CONFIG-TRANSACTION" => "配置事务失败，上一份有效配置仍被保留",
            "BF-CONTROL-UNCONFIGURED" => "控制面尚未配置，请先完成设置",
            "BF-CONTROL-ORIGIN-MISMATCH" or "BF-CONTROL-STATE-CORRUPT" => "控制面配置不可用，请使用受信任版本",
            "BF-ENROLL-001" => "邀请码无效或已经使用，请核对后再试",
            "BF-ENROLL-002" => "邀请码已过期，请获取新的邀请码",
            "BF-ENROLL-003" => "此设备已经登记，但激活资料没有补全。请重新打开软件后再点一次“激活设备”",
            "BF-ENROLL-INVITE" => "上一次激活可能已提交。请使用刚才同一个邀请码重试，不要更换邀请码",
            "BF-CONFIG-TRUST-ROOT" => "控制端返回的配置无法验证。邀请码已保留，请用同一个邀请码重试或联系管理员检查发布配置",
            "BF-IPC-IDENTITY" => "客户端与本机服务版本不一致，请从安装目录启动或重新安装当前版本",
            "BF-AUTH-003" => "控制端未接受当前设备身份或会话，请联系管理员核对设备状态；不要更换激活码 [BF-AUTH-003]",
            "BF-AUTH-004" => "认证挑战已过期或重复，请确认电脑时间已同步后重试 [BF-AUTH-004]",
            "BF-AUTH-005" or "BF-AUTH-PROOF" => "设备请求签名未通过验证，请联系管理员核对设备身份；不要更换激活码 [" + code + "]",
            "BF-AUTH-NONCE-REPLAY" => "认证请求被判定重复，请重试 [BF-AUTH-NONCE-REPLAY]",
            "BF-AUTH-REQUIRED" or "BF-AUTH-SESSION" => "设备会话暂不可用，请重试连接；无需重新购买或更换激活码 [" + code + "]",
            "BF-EDGE-CHANNEL" or "BF-EDGE-FORWARDED" => "控制端入口校验失败，请联系管理员检查服务入口；不是邀请码错误 [" + code + "]",
            _ => null
        };
        if (mapped is not null) return mapped;
        var message = ErrorRegistry.Describe(code ?? "BF-INTERNAL").MessageZh;
        return code is not null && message == "请求无法处理，请检查输入后重试"
            ? $"{action}未完成（{code}），请保留此错误码以便排查"
            : message;
    }

    internal static string? ExtractCode(Exception? error)
    {
        for (var current = error; current is not null; current = current.InnerException)
        {
            var raw = current.Message?.Trim();
            if (string.IsNullOrEmpty(raw)) continue;
            if (IsStableCode(raw) && ErrorRegistry.IsRegistered(raw)) return raw;
        }
        return null;
    }

    private static bool IsStableCode(string value)
    {
        if (value.Length < 4 || value.Length > 64 || !value.StartsWith("BF-", StringComparison.Ordinal)) return false;
        for (var index = 3; index < value.Length; index++)
        {
            var ch = value[index];
            if (!(ch is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-')) return false;
        }
        return true;
    }
}
