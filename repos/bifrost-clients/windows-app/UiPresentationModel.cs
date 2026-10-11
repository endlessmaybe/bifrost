using System.Collections.Immutable;

namespace Bifrost;

/// <summary>
/// The only state shape consumed by the WPF presentation.  Runtime state is
/// created from the typed local-service response; the screenshot constructor
/// is internal and is only visible to the deterministic renderer assembly.
/// </summary>
public enum UiConnectionState
{
    Idle,
    Preparing,
    Protected,
    Reconnecting,
    Blocked,
    Error,
}

public sealed record UiMetric(string Label, string Value);

public sealed record UiPresentationState
{
    internal UiPresentationState(
        UiConnectionState state,
        string statusText,
        string source,
        string route,
        string country,
        string core,
        string download,
        string upload,
        string sessionTraffic,
        string duration,
        ImmutableArray<double> samples,
        bool isTestState = false,
        ImmutableArray<double> uploadSamples = default)
    {
        State = state;
        StatusText = statusText;
        Source = source;
        Route = route;
        Country = country;
        Core = core;
        Download = download;
        Upload = upload;
        SessionTraffic = sessionTraffic;
        Duration = duration;
        Samples = samples;
        IsTestState = isTestState;
        UploadSamples = uploadSamples;
    }

    public UiConnectionState State { get; }
    public string StatusText { get; }
    public string Source { get; }
    public string Route { get; }
    public string Country { get; }
    public string Core { get; }
    public string Download { get; }
    public string Upload { get; }
    public string SessionTraffic { get; }
    public string Duration { get; }
    public ImmutableArray<double> Samples { get; }
    public ImmutableArray<double> UploadSamples { get; }
    public bool IsTestState { get; }

    public bool HasSamples => !Samples.IsDefaultOrEmpty;
    public bool IsProtected => State == UiConnectionState.Protected;

    public static UiPresentationState Idle(string status = "未连接") =>
        new(UiConnectionState.Idle, status, "—", "—", "—", "自动", "—", "—", "—", "—", ImmutableArray<double>.Empty);

    public static UiPresentationState Preparing(string status = "正在连接…") =>
        new(UiConnectionState.Preparing, status, "—", "正在建立安全隧道", "—", "自动", "—", "—", "—", "—", ImmutableArray<double>.Empty);

    public static UiPresentationState Reconnecting(string status = "正在源站内切换线路…") =>
        new(UiConnectionState.Reconnecting, status, "—", "正在尝试同一源站的下一条候选", "—", "自动", "—", "—", "—", "—", ImmutableArray<double>.Empty);

    public static UiPresentationState Error(string status) =>
        new(UiConnectionState.Error, status, "—", "—", "—", "自动", "—", "—", "—", "—", ImmutableArray<double>.Empty);

    internal static UiPresentationState TestProtected() =>
        new(
            UiConnectionState.Protected,
            "已连接",
            "A",
            "A-03",
            "自动",
            "自动（Mihomo）",
            "18.6 MB/s",
            "4.2 MB/s",
            "3.42 GB",
            "01:42:18",
            ImmutableArray.Create(12d, 18d, 15d, 22d, 20d, 26d, 24d, 28d),
            isTestState: true,
            uploadSamples: ImmutableArray.Create(8d, 11d, 10d, 15d, 13d, 18d, 16d, 20d));
}

public static class UiPresentationReducer
{
    public static UiPresentationState FromServiceStatus(ClientService.ServiceStatus status)
    {
        if (status is null) return UiPresentationState.Idle("服务不可用");
        if (status.Ok && !status.Connected && status.State == "reconnecting" && status.Code is null)
            return UiPresentationState.Reconnecting("正在恢复所选连接…");
        var verified = status.Ok && status.Connected && status.State == "connected" && status.Code is null &&
            status.Core is "auto" or "mihomo" &&
            status.Mode is "smart" or "global" or "per-app" &&
            PipeClientProtocol.IsOpaqueId(status.ConfigId, "cfg_") && ClientService.ServiceSelectionCodes.IsSource(status.Source) &&
            status.Enforcement is { ReadbackVerified: true } enforcement &&
            enforcement.Route == status.Mode &&
            (enforcement.Route == "per-app" ? enforcement.Policy is "allow" or "exclude" && enforcement.IdentityCount > 0 : enforcement.Policy == "none" && enforcement.IdentityCount == 0) &&
            IsCanonicalHex(enforcement.Digest, 64) && IsCanonicalHex(enforcement.Generation, 32);
        var state = verified
            ? UiConnectionState.Protected
            : string.Equals(status.State, "blocked", StringComparison.OrdinalIgnoreCase)
                ? UiConnectionState.Blocked
                : status.Ok
                    ? UiConnectionState.Idle
                    : UiConnectionState.Error;
        var mode = ProtocolCodes.ModeLabel(status.Mode ?? ProtocolCodes.ModeSmart);
        var core = ProtocolCodes.CoreLabel(status.Core ?? ProtocolCodes.CoreAuto);
        return new(
            state,
            state switch
            {
                UiConnectionState.Protected => "已连接",
                UiConnectionState.Blocked => "已阻断",
                UiConnectionState.Error => "服务暂不可用",
                _ => "未连接",
            },
            status.Enforcement is null ? "—" : "A/B",
            "—",
            "—",
            core,
            "—",
            "—",
            "—",
            "—",
            ImmutableArray<double>.Empty);
    }

    private static bool IsCanonicalHex(string? value, int length) => value is { Length: var actual } && actual == length && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal static class UiCaptureContext
{
    [ThreadStatic]
    internal static bool Active;
}
