namespace Bifrost;

/// <summary>Display-only projections of the existing connection authority.</summary>
public sealed partial class UiShellViewModel
{
    public string DashboardStatusTitle => Presentation.State switch
    {
        UiConnectionState.Protected => "已连接",
        UiConnectionState.Preparing => "正在连接",
        UiConnectionState.Reconnecting => "正在恢复连接",
        UiConnectionState.Blocked => "流量已阻断",
        UiConnectionState.Error => "连接异常",
        _ => "未连接",
    };

    public string DashboardStatusDetail => Presentation.State switch
    {
        UiConnectionState.Protected => $"当前使用{DashboardModeName}",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting or UiConnectionState.Error => StatusText,
        UiConnectionState.Blocked => "连接中断后流量已阻断，可使用连接按钮解除阻断。",
        _ when !IsEnrolled => "请在设置中完成设备激活，然后选择线路连接。",
        _ => "选择线路与连接模式，准备就绪后建立连接。",
    };

    public string DashboardModeName => Mode switch
    {
        ProtocolCodes.ModeGlobal => "全局代理",
        ProtocolCodes.ModeSmartGate => " SmartGate",
        _ => "智能选线",
    };

    public string DashboardRouteKind => IsSmartGateMode ? SelectedCountryDisplay : "标准线路";
    public string DashboardModeHint => CanEditConnectionSettings
        ? "选择智能选线、全局代理或 SmartGate。"
        : "请先断开连接，再调整连接模式。";

    public string DashboardProtectionDetail => Presentation.State switch
    {
        UiConnectionState.Protected => "网络保护正常 · 隧道已验证",
        UiConnectionState.Blocked => "网络保护 · 流量已阻断",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting => "网络保护 · 正在验证连接",
        UiConnectionState.Error => "网络保护 · 连接异常，可查看诊断",
        _ => "尚未建立隧道",
    };
}
