using System.ComponentModel;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Input;
using Bifrost.ClientService;
using Bifrost.Release;

namespace Bifrost;

/// Immutable, serialisable UI choices.  It intentionally contains no secret,
/// service handle, WPF control, or raw control-plane response.
public sealed record UiShellState(
    string Page = "home",
    string Theme = "dark",
    string DesignDirection = "a",
    string Mode = ProtocolCodes.ModeSmart,
    string Core = ProtocolCodes.CoreAuto,
    string Source = "",
    string Country = "default",
    string FrontSource = "auto",
    string CandidateMode = "auto",
    string CandidateLabel = "",
    string AppPolicy = "allow",
    bool AppPolicyEnabled = false,
    string IncludeApps = "",
    string ExcludeApps = "",
    bool IsBusy = false,
    bool IsEnrolled = false,
    string StatusText = "未连接",
    string UpdateText = "可手动检查程序更新",
    string ConfigText = "配置：等待控制面",
    UiPresentationState Presentation = null!,
    string ConnectionType = "direct-vmess",
    string RouteMode = ProtocolCodes.ModeSmart)
{
    public UiShellState() : this(Presentation: UiPresentationState.Idle()) { }

    public bool IsProtected => Presentation.IsProtected;
    public bool IsRoutingEnabled => AppPolicyEnabled;
    public string ConnectionAction => IsProtected ? "点击断开" : "点击连接";
}

/// <summary>
/// Product-level visual directions.  These values are deliberately UI-only:
/// they never cross the service/control-plane boundary and cannot change any
/// connection authority or runtime policy.
/// </summary>
public sealed record UiDesignDirectionOption(
    string Code,
    string Name,
    string Subtitle,
    string Description,
    bool Recommended = false);

public sealed record UiLiveEvent(string Time, string Event, string Route, string Status);

public sealed record UiSourceRouteGroup(
    string Code,
    string Name,
    int CandidateCount,
    bool IsSelected)
{
    public string CountText => CandidateCount == 1 ? "1 条线路" : $"{CandidateCount} 条线路";
    public string AutomationName => $"{Name}，{CountText}{(IsSelected ? "，当前源站" : "，点击查看")}";
}

public sealed record UiCandidateRoute(
    string Code,
    string Name,
    string LatencyText,
    string StatusText,
    string StatusKind,
    bool CanUse,
    bool IsSelected)
{
    public string ActionText => "使用并连接";
    public string AutomationName => $"{Name}，{StatusText}，延迟 {LatencyText}，{ActionText}";
}

public sealed record CandidateProbeProgress(
    string Source,
    int Completed,
    int Total,
    CandidateProbeStatus Status);

public interface IUiShellPersistence
{
    UiShellState Load();
    void Save(UiShellState state);
}

public interface IUiShellCoordinator : IDisposable
{
    bool IsEnrolled { get; }
    bool HasPendingRecovery { get; }
    bool HasPendingEnrollment { get; }
    bool IsLocalEvaluation { get; }
    string? ControlUrl { get; }
    string CompiledOriginDisplay { get; }
    string ControlOriginStatus { get; }
    string? SessionToken { get; }
    string? RecoveryCode { get; }
    long LastConfigVersion { get; }
    string? NodeConfigurationFingerprint => null;
    UiConfigOptions GetUiConfigOptions();
    event Action? NetworkProbeInvalidated;
    Task<ControlResult> EnrollAsync(string inviteCode, CancellationToken cancellationToken);
    Task<ControlResult> RecoverAsync(string publicId, string recoveryCode, CancellationToken cancellationToken);
    Task<ControlResult> RetrieveRecoveryDeliveryAsync(CancellationToken cancellationToken);
    Task<ControlResult> RotateRecoveryCodeAsync(CancellationToken cancellationToken);
    Task<ControlResult> CreatePairingAsync(string targetPlatform, CancellationToken cancellationToken);
    Task<ControlResult> RedeemPairingAsync(string pairingCode, CancellationToken cancellationToken);
    Task<ControlResult> RefreshAsync(CancellationToken cancellationToken);
    Task LogoutAsync(CancellationToken cancellationToken);
    Task<CandidateProbeSnapshot> ProbeCandidateStatusesAsync(string source, Action<CandidateProbeProgress>? progress, CancellationToken cancellationToken);
    Task<SignedClientPackageRequest> PrepareSignedPackageAsync(UiShellState state, ApplicationPolicySnapshot snapshot, CancellationToken cancellationToken);
    Task<ServiceStatus> StageConfigAsync(SignedClientPackageRequest package, CancellationToken cancellationToken);
    Task<ServiceStatus> ConnectAsync(UiShellState state, ApplicationPolicySnapshot snapshot, string configId, string stagedCore, CancellationToken cancellationToken);
    Task<ServiceStatus> DisconnectAsync(CancellationToken cancellationToken);
    Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<ReleaseCheckResult?> CheckProgramUpdateAsync(IProgress<ReleaseUpdateProgress>? progress, CancellationToken cancellationToken);
    Task<ReleaseCheckResult?> DiscoverProgramUpdateAsync(CancellationToken cancellationToken) =>
        CheckProgramUpdateAsync(null, cancellationToken);
    Task<ServiceStatus> ApplyProgramUpdateAsync(CancellationToken cancellationToken);
}

internal interface IStartupRetryScheduler
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class SystemStartupRetryScheduler : IStartupRetryScheduler
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

internal interface IProgramUpdateScheduler
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class SystemProgramUpdateScheduler : IProgramUpdateScheduler
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

internal sealed class ProtectedUiShellPersistence : IUiShellPersistence
{
    private readonly UiStateStore _store;
    internal ProtectedUiShellPersistence(UiStateStore? store = null) => _store = store ?? new UiStateStore();

    public UiShellState Load()
    {
        var json = _store.Load();
        return new UiShellState(
            Mode: json["mode"]?.GetValue<string>() ?? ProtocolCodes.ModeSmart,
            ConnectionType: json["connection_type"]?.GetValue<string>() ?? "",
            RouteMode: json["route_mode"]?.GetValue<string>() ?? "",
            Core: json["core"]?.GetValue<string>() ?? ProtocolCodes.CoreAuto,
            Source: json["source"]?.GetValue<string>() ?? "",
            Country: json["country"]?.GetValue<string>() ?? "default",
            FrontSource: json["front_source"]?.GetValue<string>() ?? "auto",
            CandidateMode: json["candidate_mode"]?.GetValue<string>() is { } candidateMode && candidateMode is ("auto" or "manual") ? candidateMode : "auto",
            CandidateLabel: json["candidate_label"]?.GetValue<string>() ?? "",
            AppPolicy: json["app_policy"]?.GetValue<string>() ?? "allow",
            AppPolicyEnabled: json["app_policy_enabled"]?.GetValue<bool>() == true,
            IncludeApps: json["include_apps"]?.GetValue<string>() ?? "",
            ExcludeApps: json["exclude_apps"]?.GetValue<string>() ?? "",
            Theme: "dark",
            DesignDirection: json["design_direction"]?.GetValue<string>() is { } direction && direction is ("a" or "b" or "c") ? direction : "a",
            Presentation: UiPresentationState.Idle());
    }

    public void Save(UiShellState state)
    {
        _store.Save(new JsonObject
        {
            ["mode"] = state.Mode,
            ["connection_type"] = state.ConnectionType,
            ["route_mode"] = state.RouteMode,
            ["core"] = state.Core,
            ["source"] = state.Source,
            ["country"] = state.Country,
            ["front_source"] = state.FrontSource,
            ["candidate_mode"] = state.CandidateMode,
            ["candidate_label"] = state.CandidateLabel,
            ["app_policy"] = state.AppPolicy,
            ["app_policy_enabled"] = state.AppPolicyEnabled,
            ["include_apps"] = state.IncludeApps,
            ["exclude_apps"] = state.ExcludeApps,
            ["theme"] = state.Theme,
            ["design_direction"] = state.DesignDirection,
        });
    }
}

internal sealed class InMemoryUiShellPersistence : IUiShellPersistence
{
    private UiShellState _state;
    internal InMemoryUiShellPersistence(UiShellState state) => _state = state;
    public UiShellState Load() => _state;
    public void Save(UiShellState state) => _state = state;
}

internal sealed class ProductionUiShellCoordinator : IUiShellCoordinator
{
    private readonly BifrostControlClient _control;
    private readonly ClientServiceContract _service;
    private readonly ReleaseUpdateManager _updates;
    private Action? _networkProbeInvalidated;
    private readonly SemaphoreSlim _candidateMeasurementGate = new(1, 1);
    private CandidateProbeSnapshot? _candidateMeasurementCache;
    private string? _candidateMeasurementSource;
    private long _candidateMeasurementVersion;
    private DateTimeOffset _candidateMeasurementAt;

    internal ProductionUiShellCoordinator(
        BifrostControlClient? control = null,
        ClientServiceContract? service = null,
        ReleaseUpdateManager? updates = null)
    {
#if BIFROST_TEST_HARNESS
        _control = control ?? new BifrostControlClient(UiCaptureContext.Active);
#else
        _control = control ?? new BifrostControlClient();
#endif
        _service = service ?? new ClientServiceContract();
        _updates = updates ?? ReleaseUpdateManager.FromEnvironment();
        _control.NetworkProbeInvalidated += OnNetworkProbeInvalidated;
    }

    public bool IsEnrolled => _control.IsEnrolled;
    public bool HasPendingRecovery => _control.HasPendingRecovery;
    public bool HasPendingEnrollment => _control.HasPendingEnrollment;
    public bool IsLocalEvaluation => _control.IsLocalEvaluation;
    public string? ControlUrl => _control.ControlUrl;
    public string CompiledOriginDisplay => _control.CompiledOriginDisplay;
    public string ControlOriginStatus => _control.IsLocalEvaluation
        ? (_control.IsEnrolled ? $"本机控制面 {DisplayOrigin(_control.CompiledOriginDisplay)}、已激活" : $"本机控制面 {DisplayOrigin(_control.CompiledOriginDisplay)}、尚未激活")
        : (_control.ConfigurationStatus == "CONFIGURED" ? "发行版已配置控制面" : "此测试构建未配置控制面");
    public string? SessionToken => _control.SessionToken;
    public string? RecoveryCode => _control.RecoveryCode;
    public long LastConfigVersion => _control.LastConfigVersion;
    public string? NodeConfigurationFingerprint => _control.NodeConfigurationFingerprint;
    public event Action? NetworkProbeInvalidated
    {
        add => _networkProbeInvalidated += value;
        remove => _networkProbeInvalidated -= value;
    }
    public UiConfigOptions GetUiConfigOptions() => _control.GetUiConfigOptions();
    public Task<ControlResult> EnrollAsync(string inviteCode, CancellationToken cancellationToken) => _control.EnrollAsync(inviteCode, cancellationToken);
    public Task<ControlResult> RecoverAsync(string publicId, string recoveryCode, CancellationToken cancellationToken) => _control.RecoverAsync(publicId, recoveryCode, cancellationToken);
    public Task<ControlResult> RetrieveRecoveryDeliveryAsync(CancellationToken cancellationToken) => _control.RetrieveRecoveryDeliveryAsync(cancellationToken);
    public Task<ControlResult> RotateRecoveryCodeAsync(CancellationToken cancellationToken) => _control.RotateRecoveryCodeAsync(cancellationToken);
    public Task<ControlResult> CreatePairingAsync(string targetPlatform, CancellationToken cancellationToken) => _control.CreatePairingAsync(targetPlatform, cancellationToken);
    public Task<ControlResult> RedeemPairingAsync(string pairingCode, CancellationToken cancellationToken) => _control.RedeemPairingAsync(pairingCode, cancellationToken);
    public Task<ControlResult> RefreshAsync(CancellationToken cancellationToken) => _control.RefreshAsync(cancellationToken);
    public Task LogoutAsync(CancellationToken cancellationToken) => _control.LogoutAsync(cancellationToken);
    public async Task<CandidateProbeSnapshot> ProbeCandidateStatusesAsync(string source, Action<CandidateProbeProgress>? progress, CancellationToken cancellationToken)
    {
        if (CandidateMeasurementCacheIsFresh(source))
            return _candidateMeasurementCache!;
        await _candidateMeasurementGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (CandidateMeasurementCacheIsFresh(source))
                return _candidateMeasurementCache!;
            var measured = await ProbeCandidateStatusesCoreAsync(source, progress, cancellationToken).ConfigureAwait(false);
            _candidateMeasurementCache = measured;
            _candidateMeasurementSource = source;
            _candidateMeasurementVersion = LastConfigVersion;
            _candidateMeasurementAt = DateTimeOffset.UtcNow;
            return measured;
        }
        finally { _candidateMeasurementGate.Release(); }
    }

    private bool CandidateMeasurementCacheIsFresh(string source)
    {
        if (_candidateMeasurementCache is null ||
            !string.Equals(_candidateMeasurementSource, source, StringComparison.OrdinalIgnoreCase) ||
            _candidateMeasurementVersion != LastConfigVersion)
            return false;
        // Reuse a real successful measurement round long enough to avoid
        // starting duplicate cores from the Lines page and Connect button.
        // A total-failure snapshot is deliberately short lived: a transient
        // probe outage must not make a source look dead for two minutes.
        var ttl = _candidateMeasurementCache.Candidates.Any(candidate => candidate.Success)
            ? TimeSpan.FromMinutes(2)
            : TimeSpan.FromSeconds(5);
        return DateTimeOffset.UtcNow - _candidateMeasurementAt < ttl;
    }

    private async Task<CandidateProbeSnapshot> ProbeCandidateStatusesCoreAsync(string source, Action<CandidateProbeProgress>? progress, CancellationToken cancellationToken)
    {
        var options = GetUiConfigOptions();
        var candidates = options.CandidatesBySource is not null && options.CandidatesBySource.TryGetValue(source, out var sourceCandidates)
            ? sourceCandidates
            : Array.Empty<UiOption>();
        if (candidates.Count == 0) return new CandidateProbeSnapshot(source, null, Array.Empty<CandidateProbeStatus>());

        // Build one signed descriptor, then let LocalSystem expand the signed
        // candidate labels into a bounded batch.  This avoids one named-pipe
        // transaction and one serial core startup per row while preserving
        // the exact v2rayN-compatible HTTP measurement for every candidate.
        // The service streams each completed row back immediately.
        var policy = ApplicationPolicySnapshot.Create(ProtocolCodes.ModeGlobal, "none",
            Array.Empty<string>(), Array.Empty<string>(), Guid.NewGuid().ToString("N"));
        var package = await _control.PrepareSignedPackageAsync(source, "default", ProtocolCodes.ModeGlobal,
            ProtocolCodes.CoreAuto, candidates[0].Code, Array.Empty<string>(), Array.Empty<string>(), null,
            "none", cancellationToken, policy, "direct-vmess").ConfigureAwait(false);
        var statuses = new Dictionary<string, CandidateProbeStatus>(StringComparer.OrdinalIgnoreCase);
        await _service.MeasureLatencyBatchAsync(package, candidates.Select(candidate => candidate.Code).ToArray(), frame =>
        {
            if (frame.Kind != "progress" || string.IsNullOrWhiteSpace(frame.Label)) return;
            var latency = frame.LatencyMs;
            var status = new CandidateProbeStatus(frame.Label, frame.Ok && frame.State == "measured" && latency is > 0,
                latency, frame.Ok && frame.State == "measured" && latency is > 0 ? 0 : null,
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), frame.Code);
            statuses[frame.Label] = status;
            progress?.Invoke(new CandidateProbeProgress(source, frame.Completed, frame.Total, status));
        }, cancellationToken).ConfigureAwait(false);
        var ordered = candidates.Select(candidate => statuses.TryGetValue(candidate.Code, out var status)
            ? status
            : new CandidateProbeStatus(candidate.Code, false, null, null, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())).ToArray();
        var selected = ordered.Where(status => status.Success && status.RttMs is > 0)
            .OrderBy(status => status.RttMs).ThenBy(status => status.Code, StringComparer.Ordinal).FirstOrDefault()?.Code;
        return new CandidateProbeSnapshot(source, selected, ordered);
    }

    public Task<SignedClientPackageRequest> PrepareSignedPackageAsync(UiShellState state, ApplicationPolicySnapshot snapshot, CancellationToken cancellationToken) =>
        _control.PrepareSignedPackageAsync(state.Source, RequestCountry(state), ConnectionRouteSelection.Parse(state.ConnectionType, state.RouteMode).RouteModeCode, state.Core, state.CandidateMode == "manual" ? state.CandidateLabel : null,
            state.AppPolicyEnabled ? SplitApplications(state.IncludeApps) : Array.Empty<string>(),
            state.AppPolicyEnabled ? SplitApplications(state.ExcludeApps) : Array.Empty<string>(), RequestFrontSource(state),
            state.AppPolicyEnabled ? state.AppPolicy : "none", cancellationToken, snapshot, state.ConnectionType);
    public Task<ServiceStatus> StageConfigAsync(SignedClientPackageRequest package, CancellationToken cancellationToken) => _service.StageConfigAsync(package, cancellationToken);
    public async Task<ServiceStatus> ConnectAsync(UiShellState state, ApplicationPolicySnapshot snapshot, string configId, string stagedCore, CancellationToken cancellationToken)
    {
        var status = await _service.ConnectAsync(ConnectionRouteSelection.Parse(state.ConnectionType, state.RouteMode).RouteModeCode,
            stagedCore, state.Source, RequestCountry(state), configId, snapshot.PolicyMode, cancellationToken, snapshot, state.ConnectionType).ConfigureAwait(false);
        // The authenticated LocalSystem service returns "connected" only after
        // Mihomo is ready, the owned TUN and routes are committed, group
        // selection/readback agrees, and its no-proxy HTTPS canary succeeds.
        // That service result is the connection authority. A second desktop
        // HTTP probe used to keep the UI busy after the tunnel was already
        // usable and could even tear down a service-verified connection during
        // normal Windows route-notification convergence.
        return status;
    }
    public Task<ServiceStatus> DisconnectAsync(CancellationToken cancellationToken) => _service.DisconnectAsync(cancellationToken);
    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken) => _service.GetStatusAsync(cancellationToken);
    public Task<ReleaseCheckResult?> CheckProgramUpdateAsync(IProgress<ReleaseUpdateProgress>? progress, CancellationToken cancellationToken) => CheckUpdateCoreAsync(progress, cancellationToken);
    public Task<ReleaseCheckResult?> DiscoverProgramUpdateAsync(CancellationToken cancellationToken) => CheckUpdateCoreAsync(null, cancellationToken, stageArtifacts: false);
    public Task<ServiceStatus> ApplyProgramUpdateAsync(CancellationToken cancellationToken) => _service.ApplyPendingUpdateAsync(cancellationToken);

    private static string RequestCountry(UiShellState state) =>
        ConnectionRouteSelection.Parse(state.ConnectionType, state.RouteMode).ConnectionType == ConnectionType.SmartGate
            ? state.Country
            : "default";

    private static string? RequestFrontSource(UiShellState state) =>
        ConnectionRouteSelection.Parse(state.ConnectionType, state.RouteMode).ConnectionType == ConnectionType.SmartGate
            ? state.FrontSource
            : null;

    private static string DisplayOrigin(string origin) => origin.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        ? origin["http://".Length..]
        : origin.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? origin["https://".Length..] : origin;

    private async Task<ReleaseCheckResult?> CheckUpdateCoreAsync(IProgress<ReleaseUpdateProgress>? progress, CancellationToken cancellationToken, bool stageArtifacts = true)
    {
        if (!IsEnrolled)
        {
            var activation = await _control.RefreshAsync(cancellationToken).ConfigureAwait(false);
            if (!activation.Ok || !IsEnrolled) return null;
        }
        if (string.IsNullOrWhiteSpace(ControlUrl)) return null;
        await _control.EnsureSessionForUpdateAsync(cancellationToken).ConfigureAwait(false);
        var sessionToken = SessionToken ?? throw new InvalidOperationException("BF-AUTH-SESSION");
        if (string.IsNullOrWhiteSpace(sessionToken)) throw new InvalidOperationException("BF-AUTH-SESSION");
        return await _updates.CheckAndStageWithSessionAsync(ControlUrl!, sessionToken, cancellationToken,
            (token, method, uri, body) => _control.CreateSenderProofForSession(token, method, uri, body),
            (rejectedToken, token) => _control.RefreshSessionForUpdateAsync(rejectedToken, token), progress, stageArtifacts);
    }

    private void OnNetworkProbeInvalidated()
    {
        _candidateMeasurementCache = null;
        _candidateMeasurementSource = null;
        _networkProbeInvalidated?.Invoke();
    }
    public void Dispose()
    {
        _control.NetworkProbeInvalidated -= OnNetworkProbeInvalidated;
        _control.Dispose();
        _candidateMeasurementGate.Dispose();
        _updates.Dispose();
    }

    private static string[] SplitApplications(string value)
    {
        if (string.IsNullOrEmpty(value)) return Array.Empty<string>();
        var normalized = value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var parts = normalized.Split(new[] { ',', ';', '\n' }, StringSplitOptions.None);
        if (parts.Any(string.IsNullOrWhiteSpace)) throw new InvalidDataException("BF-APP-ID");
        return parts.Select(part => part.Trim()).ToArray();
    }
}

/// A production-free coordinator used only by the WPF renderer and fixture.
internal sealed class FixtureUiShellCoordinator : IUiShellCoordinator
{
    private readonly UiPresentationState _presentation;
    internal FixtureUiShellCoordinator(UiPresentationState presentation) => _presentation = presentation;
    public bool IsEnrolled => true;
    public bool HasPendingRecovery => false;
    public bool HasPendingEnrollment => false;
    public bool IsLocalEvaluation => false;
    public string? ControlUrl => null;
    public string CompiledOriginDisplay => "TEST-ONLY";
    public string ControlOriginStatus => "此测试构建未配置控制面";
    public string? SessionToken => null;
    public string? RecoveryCode => "BFR-TEST-ONLY-RECOVERY-CODE";
    public long LastConfigVersion => 1;
    public event Action? NetworkProbeInvalidated { add { } remove { } }
    public UiConfigOptions GetUiConfigOptions() => new(
        new[] { new UiOption("A", "线路 A") },
        new[] { new UiOption("auto", "按国家默认") },
        new[]
        {
            new UiOption("SG-SG", "新加坡 SmartGate"),
            new UiOption("SG-US", "美国 SmartGate"),
        },
        new Dictionary<string, IReadOnlyList<UiOption>>(StringComparer.OrdinalIgnoreCase)
        {
            ["A"] = new[]
            {
                new UiOption("A-01", "新加坡 01"),
                new UiOption("A-02", "东京 02"),
                new UiOption("A-03", "洛杉矶 03"),
            },
        });
    public Task<ControlResult> EnrollAsync(string _, CancellationToken __) => Task.FromResult(new ControlResult(false, "fixture", null, null, 0));
    public Task<ControlResult> RecoverAsync(string _, string __, CancellationToken ___) => Task.FromResult(new ControlResult(false, "fixture", null, null, 0));
    public Task<ControlResult> RetrieveRecoveryDeliveryAsync(CancellationToken _) => Task.FromResult(new ControlResult(false, "fixture", null, null, 0));
    public Task<ControlResult> RotateRecoveryCodeAsync(CancellationToken _) => Task.FromResult(new ControlResult(true, "fixture", "TEST-ONLY-public-id", "BFR-TEST-ONLY-ROTATED-RECOVERY-CODE", 1));
    public Task<ControlResult> CreatePairingAsync(string _, CancellationToken __) => Task.FromResult(new ControlResult(false, "fixture", null, null, 0));
    public Task<ControlResult> RedeemPairingAsync(string _, CancellationToken __) => Task.FromResult(new ControlResult(false, "fixture", null, null, 0));
    public Task<ControlResult> RefreshAsync(CancellationToken _) => Task.FromResult(new ControlResult(true, "fixture", null, null, 0));
    public Task LogoutAsync(CancellationToken _) => Task.CompletedTask;
    public Task<CandidateProbeSnapshot> ProbeCandidateStatusesAsync(string source, Action<CandidateProbeProgress>? progress, CancellationToken _)
    {
        var statuses = new[]
        {
            new CandidateProbeStatus("A-01", true, 34, 0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
            new CandidateProbeStatus("A-02", true, 46, 0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
            new CandidateProbeStatus("A-03", true, 128, 0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
        };
        for (var index = 0; index < statuses.Length; index++)
            progress?.Invoke(new CandidateProbeProgress(source, index + 1, statuses.Length, statuses[index]));
        return Task.FromResult(new CandidateProbeSnapshot(source, "A-01", statuses));
    }
    public Task<SignedClientPackageRequest> PrepareSignedPackageAsync(UiShellState state, ApplicationPolicySnapshot snapshot, CancellationToken cancellationToken) =>
        Task.FromResult(new SignedClientPackageRequest(ProtocolCodes.ModeSmart, ProtocolCodes.CoreAuto, "A", "default", snapshot.PolicyMode, snapshot));
    public Task<ServiceStatus> StageConfigAsync(SignedClientPackageRequest _, CancellationToken __) => Task.FromResult(ServiceStatus.Staged("cfg_fixture", ProtocolCodes.CoreMihomo, ProtocolCodes.ModeSmart));
    public Task<ServiceStatus> ConnectAsync(UiShellState _, ApplicationPolicySnapshot ___, string ____, string stagedCore, CancellationToken _____) => Task.FromResult(ServiceStatus.ConnectedState(stagedCore, ProtocolCodes.ModeSmart, "cfg_fixture", "A1", new EnforcementSummary(ProtocolCodes.ModeSmart, "none", 0, new string('f', 64), new string('a', 32), true)));
    public Task<ServiceStatus> DisconnectAsync(CancellationToken _) => Task.FromResult(ServiceStatus.Disconnected());
    public Task<ServiceStatus> GetStatusAsync(CancellationToken _) => Task.FromResult(_presentation.IsProtected ? ServiceStatus.ConnectedState(ProtocolCodes.CoreAuto, ProtocolCodes.ModeSmart, "cfg_fixture", "A1", new EnforcementSummary(ProtocolCodes.ModeSmart, "none", 0, new string('f', 64), new string('a', 32), true)) : ServiceStatus.Disconnected());
    public Task<ReleaseCheckResult?> CheckProgramUpdateAsync(IProgress<ReleaseUpdateProgress>? _, CancellationToken __) => Task.FromResult<ReleaseCheckResult?>(null);
    public Task<ServiceStatus> ApplyProgramUpdateAsync(CancellationToken _) => Task.FromResult(ServiceStatus.UpdateScheduled());
    public void Dispose() { }
}

public sealed partial class UiShellViewModel : INotifyPropertyChanged, IDisposable
{
    // Keep TUN mutation to one attempt per click.  The RealPing round already
    // ranks every usable candidate; repeatedly creating/destroying a Windows
    // TUN for second/third choices causes host-wide route churn.  Until Bifrost
    // has an in-process selector/urltest group that can fail over without
    // restarting the TUN, connect only the best measured candidate and make a
    // later click perform a fresh measurement round.
    public sealed record EnrollRequest(string InviteCode);
    public sealed record RecoverRequest(string PublicId, string RecoveryCode);
    public sealed record PairingRequest(string PairingCode);
    private readonly IUiShellCoordinator _coordinator;
    private readonly IUiShellPersistence _persistence;
    private readonly AsyncCommand _connectCommand;
    private readonly AsyncCommand _refreshCommand;
    private readonly AsyncCommand _checkUpdateCommand;
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _recoveryDeliveryTask;
    private readonly WindowsProbeLifecycle _probeLifecycle;
    private readonly IUiStateDispatcher _dispatcher;
    private readonly IStartupRetryScheduler _startupRetryScheduler;
    private readonly IProgramUpdateScheduler _programUpdateScheduler;
    private readonly WindowsTunnelTelemetry _tunnelTelemetry = new();
    private UiShellState _state;
    private bool _serviceReady;
    private string _autoCandidateLabel = "";
    private UiTunnelTelemetry _telemetry = UiTunnelTelemetry.Empty;
    private DateTimeOffset? _lastStatusUpdated;
    private string? _lastLiveEventSignature;
    private Task? _statusPollTask;
    private Task? _configRefreshTask;
    private Task? _startupTask;
    private Task? _programUpdateLoopTask;
    private static readonly TimeSpan ProgramUpdateStartupDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan[] ActivationResumeRetryDelays =
    {
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(15),
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(1),
    };
    // Keep release propagation near-real-time without turning the control edge
    // into a tight polling loop. Enrolled clients check five seconds after
    // startup and at most five minutes after a later signed release is pushed.
    private static readonly TimeSpan ProgramUpdateInterval = TimeSpan.FromMinutes(5);
    private bool _probeLifecycleStarted;
    private DateTimeOffset? _lastOperationErrorAt;
    private readonly Dictionary<string, IReadOnlyDictionary<string, CandidateProbeStatus>> _candidateProbesBySource = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (int Completed, int Total)> _candidateProbeProgressBySource = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _candidateProbeStartedBySource = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TimeSpan> _candidateProbeDurationBySource = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _lastAutomaticCandidateAttempts = new();
    private CandidateProbeSnapshot? _lastAutomaticMeasurement;
    private readonly HashSet<string> _pendingCandidateProbeSources = new(StringComparer.OrdinalIgnoreCase);
    private int _updateOperationRunning;
    private int _updateProgress;
    private string _updateStatusKind = "idle";
    private string _updateStatusTitle = "准备检查更新";
    private string _updateStatusMessage = "—";
    private int _automaticFailoverRunning;
    private string? _automaticFailoverSuppressedSource;
    private long _automaticFailoverSuppressedVersion;
    private int _disposed;

    public UiShellViewModel(
        IUiShellCoordinator coordinator,
        IUiShellPersistence persistence,
        UiShellState? initial = null,
        WindowsProbeLifecycle? probeLifecycle = null,
        IUiStateDispatcher? dispatcher = null)
        : this(coordinator, persistence, initial, probeLifecycle, dispatcher, new SystemStartupRetryScheduler(), new SystemProgramUpdateScheduler())
    {
    }

    internal UiShellViewModel(
        IUiShellCoordinator coordinator,
        IUiShellPersistence persistence,
        UiShellState? initial,
        WindowsProbeLifecycle? probeLifecycle,
        IUiStateDispatcher? dispatcher,
        IStartupRetryScheduler startupRetryScheduler,
        IProgramUpdateScheduler? programUpdateScheduler = null)
    {
        _coordinator = coordinator;
        _persistence = persistence;
        _dispatcher = dispatcher ?? new WpfUiStateDispatcher();
        _startupRetryScheduler = startupRetryScheduler;
        _programUpdateScheduler = programUpdateScheduler ?? new SystemProgramUpdateScheduler();
        _serviceReady = !coordinator.IsLocalEvaluation;
        var loadedState = initial ?? LoadInitialState(persistence);
        _state = NormalizePersistedApplicationPolicy(loadedState);
        if (_state != loadedState)
        {
            try { _persistence.Save(_state); } catch { }
        }
        var initialStatus = coordinator.IsLocalEvaluation && !coordinator.IsEnrolled
            ? "请先双击 Bifrost 管理后台"
            : _state.StatusText;
        var initialConfig = coordinator.IsLocalEvaluation
            ? $"本机控制面 127.0.0.1:17880；{(coordinator.IsEnrolled ? "已激活" : "尚未激活")}"
            : _state.ConfigText;
        var enrolled = coordinator.IsEnrolled;
        _state = _state with
        {
            Page = enrolled ? _state.Page : "settings",
            IsEnrolled = enrolled,
            StatusText = initialStatus,
            ConfigText = initialConfig,
            Presentation = _state.Presentation ?? UiPresentationState.Idle(initialStatus)
        };
        NavigateCommand = new AsyncCommand(parameter => NavigateAsync(parameter?.ToString() ?? "home"));
        ToggleThemeCommand = new AsyncCommand(_ => ToggleThemeAsync());
        SelectSourceCommand = new AsyncCommand(parameter => SelectSourceAsync(parameter?.ToString()));
        SelectCandidateCommand = new AsyncCommand(parameter => SelectCandidateAsync(parameter?.ToString()));
        UseCandidateCommand = new AsyncCommand(parameter => UseCandidateAsync(parameter?.ToString()));
        RefreshCandidateProbesCommand = new AsyncCommand(_ => RefreshCandidateProbesAsync());
        _connectCommand = new AsyncCommand(_ => ConnectAsync());
        _refreshCommand = new AsyncCommand(_ => RefreshAsync());
        _checkUpdateCommand = new AsyncCommand(_ => CheckProgramUpdateAsync());
        EnrollCommand = new AsyncResultCommand<EnrollRequest, ControlResult?>(request => EnrollAsync(request.InviteCode));
        RecoverCommand = new AsyncResultCommand<RecoverRequest, ControlResult?>(request => RecoverAsync(request.PublicId, request.RecoveryCode));
        PairCommand = new AsyncResultCommand<PairingRequest, ControlResult?>(request => string.IsNullOrWhiteSpace(request.PairingCode)
            ? CreatePairingAsync()
            : RedeemPairingAsync(request.PairingCode));
        LogoutCommand = new AsyncCommand(_ => LogoutAsync());
        _probeLifecycle = probeLifecycle ?? new WindowsProbeLifecycle(coordinator, PublishProbeOutcome);
        _coordinator.NetworkProbeInvalidated += OnNetworkProbeInvalidated;
        if (_coordinator.IsEnrolled)
        {
            try { ApplyOptions(_coordinator.GetUiConfigOptions()); } catch { }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action<long>? ProgramUpdateScheduled;
    public event Action<long>? ProgramUpdateAvailable;
    public event Action<long>? NodeConfigurationUpdated;
    private long _lastNotifiedNodeVersion;
    public event Action<long, bool>? ProgramUpdatePreparing;
    private long _lastPromptedUpdateSequence;
    private long _connectionActionRevision;
    private bool _updatePromotionRunning;
    public UiShellState State => _state;
    public string Page => _state.Page;
    public string Theme { get => _state.Theme; set => SetTheme(value); }
    public string DesignDirection { get => _state.DesignDirection; set => SetDesignDirection(value); }
    public IReadOnlyList<UiDesignDirectionOption> DesignDirectionOptions { get; } = new[]
    {
        new UiDesignDirectionOption("a", "A · Precision", "克制 · 专业 · 高效率", "紧凑的信息层级、明确的边界与快速扫描，适合高频网络操作。", Recommended: true),
        new UiDesignDirectionOption("b", "B · Spatial", "现代 · 精致 · 空间层级", "更充裕的留白、更强的前后层级和更柔和的分组，适合长时间观察。"),
        new UiDesignDirectionOption("c", "C · Signal", "品牌 · 记忆点 · 强识别", "更鲜明的品牌轴线、非对称比例与状态强调，适合强调 Bifrost 个性。"),
    };
    public string DesignDirectionName => DesignDirectionOptions.First(option => option.Code == _state.DesignDirection).Name;
    public bool IsDirectionA => _state.DesignDirection == "a";
    public bool IsDirectionB => _state.DesignDirection == "b";
    public bool IsDirectionC => _state.DesignDirection == "c";
    public string Mode { get => _state.Mode; set
    {
        var applicationPolicyEnabled = value == ProtocolCodes.ModeSmart && _state.AppPolicyEnabled;
        var typed = ConnectionRouteSelection.FromPresentation(value, applicationPolicyEnabled);
        var smartGate = value == ProtocolCodes.ModeSmartGate;
        var nextCountry = smartGate && ContainsOption(CountryOptions, _state.Country) ? _state.Country : smartGate ? "" : "default";
        Update(_state with
        {
            Mode = value,
            ConnectionType = typed.ConnectionTypeCode,
            RouteMode = typed.RouteModeCode,
            AppPolicyEnabled = applicationPolicyEnabled,
            Country = nextCountry,
            FrontSource = smartGate ? _state.FrontSource : "auto",
            CandidateMode = value == ProtocolCodes.ModeSmart ? "auto" : smartGate ? "auto" : "manual",
            CandidateLabel = value is ProtocolCodes.ModeSmart or ProtocolCodes.ModeSmartGate ? "" : _state.CandidateLabel,
        }, persist: true);
    } }
    public string ConnectionType => _state.ConnectionType;
    public string RouteMode => _state.RouteMode;
    public string Core { get => _state.Core; set => Update(_state with { Core = value }, persist: true); }
    public string Source { get => _state.Source; set => SetSource(value); }
    public string Country { get => _state.Country; set => Update(_state with { Country = IsSmartGateMode ? value : "default" }, persist: true); }
    public string FrontSource { get => _state.FrontSource; set => Update(_state with { FrontSource = value }, persist: true); }
    public string AppPolicy { get => _state.AppPolicy; set
    {
        var normalized = value == "exclude" ? "exclude" : "allow";
        Update(normalized == "allow"
            ? _state with { AppPolicy = normalized, ExcludeApps = "" }
            : _state with { AppPolicy = normalized, IncludeApps = "" }, persist: true);
    } }
    public bool AppPolicyEnabled { get => _state.AppPolicyEnabled; set
    {
        var enabled = value && _state.Mode == ProtocolCodes.ModeSmart;
        var typed = ConnectionRouteSelection.FromPresentation(_state.Mode, enabled);
        Update(_state with { AppPolicyEnabled = enabled, ConnectionType = typed.ConnectionTypeCode, RouteMode = typed.RouteModeCode }, persist: true);
    } }
    public string IncludeApps { get => _state.IncludeApps; set => Update(_state with { IncludeApps = value }, persist: true); }
    public string ExcludeApps { get => _state.ExcludeApps; set => Update(_state with { ExcludeApps = value }, persist: true); }
    public void AddApplicationIdentities(IEnumerable<string> identities)
    {
        var incoming = ApplicationPolicySnapshot.NormalizeIdentities(identities).ToArray();
        if (incoming.Length == 0) return;
        var existing = SplitApplications(_state.AppPolicy == "exclude" ? _state.ExcludeApps : _state.IncludeApps);
        var combined = ApplicationPolicySnapshot.NormalizeIdentities(existing.Concat(incoming));
        var text = string.Join(Environment.NewLine, combined);
        var typed = ConnectionRouteSelection.FromPresentation(ProtocolCodes.ModeSmart, appPolicyEnabled: true);
        var next = _state with
        {
            Mode = ProtocolCodes.ModeSmart,
            ConnectionType = typed.ConnectionTypeCode,
            RouteMode = typed.RouteModeCode,
            Country = "default",
            FrontSource = "auto",
            AppPolicyEnabled = true,
            IncludeApps = _state.AppPolicy == "allow" ? text : "",
            ExcludeApps = _state.AppPolicy == "exclude" ? text : "",
        };
        Update(next, persist: true);
    }
    public string StatusText => _state.StatusText;
    public string UpdateText => _state.UpdateText;
    public string ConfigText => _state.ConfigText;
    public bool IsUpdateChecking => Volatile.Read(ref _updateOperationRunning) != 0 || _updatePromotionRunning;
    public int UpdateProgress => Math.Clamp(_updateProgress, 0, 100);
    public bool UpdateProgressIndeterminate => IsUpdateChecking && _updateStatusKind == "checking";
    public string UpdateProgressText => UpdateProgressIndeterminate
        ? "…"
        : UpdateProgress == 0 && _updateStatusKind is "warning" or "failed"
            ? "—"
            : $"{UpdateProgress}%";
    public string UpdateStatusKind => _updateStatusKind;
    public string UpdateStatusTitle => _updateStatusTitle;
    public string UpdateStatusMessage => _updateStatusMessage;
    public string UpdateActionLabel => _updatePromotionRunning ? "正在安装…" : IsUpdateChecking ? "正在检查…" : _updateStatusKind == "available" ? "更新软件" : "检查软件更新";
    public string UpdateAvailabilityText => _coordinator.IsLocalEvaluation ? "评估版关闭" : "已启用";
    public string ProductVersion
    {
        get
        {
            // Keep the shipping executable's version authoritative. Audit
            // hosts (dotnet.exe / renderer) instead use the product assembly.
            var executable = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(executable) && string.Equals(
                    Path.GetFileNameWithoutExtension(executable), typeof(UiShellViewModel).Assembly.GetName().Name,
                    StringComparison.OrdinalIgnoreCase))
            {
                var fileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(executable).FileVersion;
                if (Version.TryParse(fileVersion, out var parsed)) return $"{parsed.Major}.{parsed.Minor}.{parsed.Build}";
            }
            var version = typeof(UiShellViewModel).Assembly.GetName().Version;
            return version is null ? "2.0.0" : $"{version.Major}.{version.Minor}.{version.Build}";
        }
    }
    public bool IsEnrolled => _state.IsEnrolled && _coordinator.IsEnrolled;
    public string RecoveryCode => _coordinator.RecoveryCode ?? "";
    public bool HasRecoveryCode => IsEnrolled && !string.IsNullOrWhiteSpace(_coordinator.RecoveryCode);
    public string RecoveryCodeStatus => HasRecoveryCode
        ? "完整恢复码已使用 Windows 当前用户加密保存在本机。"
        : "本机没有保存旧恢复码，可以在下方重新生成。旧恢复码会立即失效。";
    public bool RequiresActivation => !IsEnrolled;
    public bool IsRecoveryPending => _coordinator.HasPendingRecovery;
    public bool IsEnrollmentPending => _coordinator.HasPendingEnrollment;
    public bool CanStartEnrollment => !IsRecoveryPending && CanInteract;
    public bool CanStartRecovery => !IsRecoveryPending && CanInteract;
    public string DeviceRegistrationStatus => IsEnrolled
        ? "已激活"
        : IsRecoveryPending
            ? "等待恢复批准"
            : IsEnrollmentPending
                ? (_state.IsBusy ? "正在完成激活" : "激活未完成，请重试")
                : "需要激活";
    public string ControlOriginStatus => _coordinator.ControlOriginStatus;
    public bool IsHomePage => _state.Page == "home";
    public bool IsNodesPage => _state.Page == "nodes";
    public bool IsRoutingPage => _state.Page == "routing";
    public bool IsActivityPage => _state.Page == "activity";
    public bool IsSettingsPage => _state.Page == "settings";
    public bool IsSmartMode => string.Equals(_state.Mode, ProtocolCodes.ModeSmart, StringComparison.Ordinal);
    public bool IsGlobalMode => string.Equals(_state.Mode, ProtocolCodes.ModeGlobal, StringComparison.Ordinal);
    public bool IsSmartGateMode => string.Equals(_state.Mode, ProtocolCodes.ModeSmartGate, StringComparison.Ordinal);
    public bool IsBusy => _state.IsBusy;
    public bool CanInteract => !_state.IsBusy && !_updatePromotionRunning;
    public bool CanEditConnectionSettings => !_state.IsBusy && !_updatePromotionRunning && _state.Presentation.State is UiConnectionState.Idle or UiConnectionState.Error;
    // The central dial is the primary recovery/connection action and must
    // never become a silent dead surface merely because enrollment/config
    // prerequisites are temporarily unavailable.  Idle/Error clicks are
    // allowed to retry the control-plane refresh and surface an actionable
    // error; Protected/Blocked clicks remain the disconnect/release action.
    // An in-flight UI transaction stays fenced by IsBusy. Service-owned
    // recovery remains cancellable through the same primary action.
    public bool CanUsePrimaryAction => !_state.IsBusy && !_updatePromotionRunning &&
        _state.Presentation.State != UiConnectionState.Preparing;
    public bool CanConnect => !_state.IsBusy &&
        (_state.IsProtected || _state.Presentation.State == UiConnectionState.Blocked ||
         (_serviceReady && _state.IsEnrolled && _coordinator.IsEnrolled && _coordinator.LastConfigVersion > 0 && Options.Sources.Count > 0 && ConnectionSelectionsReady));
    private bool ConnectionSelectionsReady =>
        ContainsOption(SourceOptions, Source) &&
        CountrySelectionReady &&
        CandidateSelectionContract.CoreOptions.Any(option => string.Equals(option.Code, Core, StringComparison.Ordinal)) &&
        (CandidateMode != "manual" || ContainsOption(CandidateOptions, CandidateLabel)) &&
        ApplicationPolicyInputReady;
    private bool CountrySelectionReady => IsSmartGateMode
        ? CountryOptions.Count > 0 && ContainsOption(CountryOptions, Country)
        : string.Equals(Country, "default", StringComparison.OrdinalIgnoreCase);
    public bool HasSelectedSmartGateNode => IsSmartGateMode && CountryOptions.Count > 0 && ContainsOption(CountryOptions, Country);
    public bool CanUseSmartGateAction => !_state.IsBusy &&
        (_state.Presentation.State is UiConnectionState.Protected or UiConnectionState.Blocked ||
         (_state.Presentation.State is not (UiConnectionState.Preparing or UiConnectionState.Reconnecting) && HasSelectedSmartGateNode));
    private bool ApplicationPolicyInputReady
    {
        get
        {
            if (!_state.AppPolicyEnabled) return true;
            try
            {
                var include = SplitApplications(_state.IncludeApps);
                var exclude = SplitApplications(_state.ExcludeApps);
                return _state.AppPolicy == "allow"
                    ? include.Length > 0 && exclude.Length == 0
                    : _state.AppPolicy == "exclude" && exclude.Length > 0 && include.Length == 0;
            }
            catch { return false; }
        }
    }
    public bool IsProtected => _state.IsProtected; public bool IsRoutingEnabled => _state.IsRoutingEnabled;
    public UiPresentationState Presentation => _state.Presentation;
    public string PrimaryActionLabel => _state.Presentation.State switch
    {
        UiConnectionState.Protected when IsSmartGateMode => "断开 SmartGate",
        UiConnectionState.Protected => "断开连接",
        UiConnectionState.Blocked => "解除阻断",
        UiConnectionState.Reconnecting when !_state.IsBusy => "取消重连",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting => "连接处理中",
        _ when IsSmartGateMode && !HasSelectedSmartGateNode => "请先选择 SmartGate 节点",
        _ when IsSmartGateMode => "连接所选 SmartGate 节点",
        _ => "建立安全连接",
    };
    public string StateIcon => _state.Presentation.State switch
    {
        UiConnectionState.Preparing => "…", UiConnectionState.Protected => "✓", UiConnectionState.Reconnecting => "↻",
        UiConnectionState.Blocked => "!", UiConnectionState.Error => "×", _ => "○",
    };
    public string SourceSummary => _state.Presentation.Source;
    public string RouteSummary => _state.Presentation.Route == "—" ? _state.Presentation.Country : _state.Presentation.Route;
    public string CoreSummary => _state.Presentation.Core;
    public string DownloadMetric => _state.Presentation.IsTestState ? _state.Presentation.Download : _telemetry.DownloadRate;
    public string UploadMetric => _state.Presentation.IsTestState ? _state.Presentation.Upload : _telemetry.UploadRate;
    public string SessionMetric => _state.Presentation.IsTestState ? _state.Presentation.SessionTraffic : _telemetry.SessionTraffic;
    public string DurationMetric => _state.Presentation.IsTestState ? _state.Presentation.Duration : _telemetry.Duration;
    // The service contract does not currently expose a trustworthy RTT in
    // the connected status response.  Keep production honest with an em dash;
    // the deterministic TEST-only renderer uses the approved 36 ms fixture so
    // visual evidence can exercise the completed sidebar composition.
    public string LatencyMetric => _state.Presentation.IsTestState ? "36 ms" : "—";
    public string PacketLossMetric => _state.Presentation.IsTestState ? "0.12%" : "—";
    public string SelectedSourceDisplay => SourceOptions.FirstOrDefault(option => string.Equals(option.Code, Source, StringComparison.OrdinalIgnoreCase))?.Name
        ?? (string.IsNullOrWhiteSpace(Source) ? "尚未选择源站" : Source);
    // "No country exit" is a deliberate fail-closed empty state: the UI must
    // surface that no signed egress exists instead of inventing a fallback.
    public string SelectedCountryDisplay => !IsSmartGateMode
        ? "普通 A/B（不使用国家出口）"
        : CountryOptions.FirstOrDefault(option => string.Equals(option.Code, Country, StringComparison.OrdinalIgnoreCase))?.Name
            ?? (CountryOptions.Count == 0 ? "暂无 SmartGate 节点" : "请选择 SmartGate 节点");
    public bool HasCountryOptions => CountryOptions.Count > 0;
    public bool NoCountryOptions => CountryOptions.Count == 0;
    public bool HasCandidateOptions => CandidateOptions.Count > 0;
    public string CandidateCountText => CandidateOptions.Count == 0 ? "暂无可选线路" : $"{CandidateOptions.Count} 条可选线路";
    public string TransportSummary => "VMess · WSS";
    public string LiveStatusText => _lastStatusUpdated is null ? "实时状态 · 等待首次刷新" : $"实时状态 · {_lastStatusUpdated:HH:mm:ss}";
    public string TelemetryAvailabilityText => _state.IsProtected
        ? (_telemetry.Available ? "实时流量" : "正在获取流量数据…")
        : "连接后显示实时流量";
    public ImmutableArray<double> LiveDownloadSamples => _state.Presentation.IsTestState ? _state.Presentation.Samples : _telemetry.DownloadSamples;
    public ImmutableArray<double> LiveUploadSamples => _state.Presentation.IsTestState ? _state.Presentation.UploadSamples : _telemetry.UploadSamples;
    public ObservableCollection<UiLiveEvent> LiveEvents { get; } = new();
    public string NetworkQualityStatus => _state.Presentation.State switch
    {
        UiConnectionState.Protected => "受保护",
        UiConnectionState.Preparing => "正在连接",
        UiConnectionState.Reconnecting => "正在切换",
        UiConnectionState.Blocked => "已阻断",
        UiConnectionState.Error => "异常",
        _ => "未连接",
    };
    public string ConnectionStateDetail => _state.Presentation.State switch
    {
        UiConnectionState.Protected => $"隧道已由本机服务验证 · {SelectedCoreDisplay}",
        UiConnectionState.Preparing => "正在刷新配置、优选线路并建立受保护隧道",
        UiConnectionState.Reconnecting => "网络发生变化，正在安全切换线路",
        UiConnectionState.Blocked => "安全边界已阻断流量；点击主按钮执行释放/恢复",
        UiConnectionState.Error => "连接未建立；可重试或前往设置查看诊断信息",
        _ => "尚未建立隧道；连接前仍可调整线路、分流与核心",
    };
    public string NetworkProtectionStatus => _state.Presentation.State switch
    {
        UiConnectionState.Protected => "正常",
        UiConnectionState.Blocked => "已阻断",
        UiConnectionState.Error => "异常",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting => "切换中",
        _ => "等待连接",
    };
    public string SmartGateManualStatus => _state.Mode != ProtocolCodes.ModeSmartGate
        ? "未启用"
        : HasSelectedSmartGateNode ? "节点已选择" : "等待选择节点";
    public string SmartGateManualActionLabel => _state.Presentation.State switch
    {
        UiConnectionState.Protected => "断开 SmartGate",
        UiConnectionState.Blocked => "解除 SmartGate 阻断",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting => "SmartGate 连接处理中",
        _ when !HasSelectedSmartGateNode => "请先选择 SmartGate 节点",
        _ => "连接所选 SmartGate 节点",
    };
    public string SmartGateNodeSummary => HasSelectedSmartGateNode
        ? SelectedCountryDisplay
        : CountryOptions.Count == 0 ? "暂无可用 SmartGate 节点" : "请选择节点";
    public string SmartGateNodeAvailabilityText => CountryOptions.Count == 0
        ? "暂无已发布节点"
        : $"已发布 {CountryOptions.Count} 个";
    public string SmartGateManualFailoverStatus => _state.Mode == ProtocolCodes.ModeSmartGate ? "不跨用户所选节点切换" : "—";
    public string SmartGateStatus => _state.Mode == ProtocolCodes.ModeSmartGate
        ? (_state.Presentation.IsProtected ? "运行中" : "已配置")
        : "未启用";
    public string SmartGateActionLabel => _state.Presentation.State switch
    {
        UiConnectionState.Protected => "断开 SmartGate",
        UiConnectionState.Blocked => "解除阻断",
        UiConnectionState.Preparing or UiConnectionState.Reconnecting => "SmartGate 连接处理中",
        _ => "使用 SmartGate 建立连接",
    };
    public string FrontSourceSummary => string.IsNullOrWhiteSpace(_state.FrontSource) || _state.FrontSource == "auto"
        ? "自动"
        : FrontSourceOptions.FirstOrDefault(option => string.Equals(option.Code, _state.FrontSource, StringComparison.OrdinalIgnoreCase))?.Name ?? _state.FrontSource;
    public string FailoverStatus => _state.Mode == ProtocolCodes.ModeSmartGate ? "由 SmartGate 管理" : "—";
    public string RoutingModeTitle => _state.Mode switch
    {
        ProtocolCodes.ModeGlobal => "全局代理",
        ProtocolCodes.ModeSmartGate => "SmartGate",
        _ => "智能选线",
    };
    public string RoutingModeDescription => _state.Mode switch
    {
        ProtocolCodes.ModeGlobal => "全部受支持流量通过 Bifrost",
        ProtocolCodes.ModeSmartGate => "由 SmartGate 选择和维护线路",
        _ => $"固定源站 {Source}，只在该源站内部自动选择和故障切换候选线路",
    };
    public string SelectedCoreDisplay => CandidateSelectionContract.CoreOptions.FirstOrDefault(option => option.Code == _state.Core)?.DisplayName ?? _state.Core;
    /// <summary>Compact protected-session summary sourced only from the trusted presentation model.</summary>
    public string SessionSummary => string.Join(" · ", DurationMetric, SessionMetric, DownloadMetric);
    public bool HasSamples => _state.Presentation.IsTestState ? _state.Presentation.HasSamples : !_telemetry.DownloadSamples.IsDefaultOrEmpty;
    public bool NoSamples => !HasSamples;
    public bool IsTestState => _state.Presentation.IsTestState;
    public UiConfigOptions Options { get; private set; } = UiConfigOptions.Empty;
    public IReadOnlyList<UiOption> SourceOptions => Options.Sources;
    public IReadOnlyList<UiOption> FrontSourceOptions => Options.FrontSources;
    public IReadOnlyList<UiOption> CountryOptions => Options.Countries;
    public IReadOnlyList<UiOption> CandidateOptions =>
        Options.CandidatesBySource is not null && Options.CandidatesBySource.TryGetValue(Source, out var values)
            ? values
            : Array.Empty<UiOption>();
    public IReadOnlyList<UiSourceRouteGroup> SourceRouteGroups => SourceOptions.Select(option =>
    {
        var count = Options.CandidatesBySource is not null && Options.CandidatesBySource.TryGetValue(option.Code, out var candidates)
            ? candidates.Count
            : 0;
        return new UiSourceRouteGroup(option.Code, option.Name, count, string.Equals(option.Code, Source, StringComparison.OrdinalIgnoreCase));
    }).ToArray();
    private IReadOnlyList<UiCandidateRoute>? _candidateRouteCache;
    private object? _candidateRouteCacheOptions, _candidateRouteCacheProbes;
    private (string Source, string Label, bool Manual, bool Pending) _candidateRouteCacheSelection;
    private long _candidateProbeUiRevision, _candidateRouteCacheRevision, _lastProbeUiPaintTick;
    public IReadOnlyList<UiCandidateRoute> CandidateRoutes
    {
        get
        {
            _candidateProbesBySource.TryGetValue(Source, out var probes);
            var pending = _pendingCandidateProbeSources.Contains(Source);
            var options = CandidateOptions;
            var selection = (Source, CandidateLabel, IsManualCandidateMode, pending);
            if (_candidateRouteCache is not null && ReferenceEquals(options, _candidateRouteCacheOptions) &&
                ReferenceEquals(probes, _candidateRouteCacheProbes) && selection == _candidateRouteCacheSelection &&
                _candidateProbeUiRevision == _candidateRouteCacheRevision) return _candidateRouteCache;
            _candidateRouteCacheOptions = options; _candidateRouteCacheProbes = probes;
            _candidateRouteCacheSelection = selection; _candidateRouteCacheRevision = _candidateProbeUiRevision;
            var completedRound = !pending && probes is not null;
            return _candidateRouteCache = options.Select(option =>
            {
                CandidateProbeStatus? probe = null;
                probes?.TryGetValue(option.Code, out probe);
                var statusKind = probe is { Success: true }
                    ? "available"
                    : probe is not null || completedRound
                        ? "unavailable"
                        : "pending";
                var latency = probe is { Success: true, RttMs: double rtt }
                    ? $"{Math.Max(1, Math.Round(rtt)):0} ms"
                    : probe is null ? "—" : "超时";
                var status = statusKind switch
                {
                    "available" => "可用",
                    "unavailable" => probe is null ? "测速失败" : "不可用",
                    _ => pending ? "测速中" : "等待测速",
                };
                return new UiCandidateRoute(
                    option.Code,
                    option.Name,
                    latency,
                    status,
                    statusKind,
                    statusKind == "available",
                    string.Equals(option.Code, CandidateLabel, StringComparison.OrdinalIgnoreCase) && IsManualCandidateMode);
            }).ToArray();
        }
    }
    public bool NoCandidateOptions => CandidateOptions.Count == 0;
    public bool IsCandidateProbeRunning => _pendingCandidateProbeSources.Contains(Source);
    public bool CanRefreshCandidateProbes => IsCandidateProbeRunning || CanEditConnectionSettings && CandidateOptions.Count > 0;
    public int CandidateProbeProgressPercent => _candidateProbeProgressBySource.TryGetValue(Source, out var progress) && progress.Total > 0
        ? Math.Clamp((int)Math.Round(progress.Completed * 100d / progress.Total, MidpointRounding.AwayFromZero), 0, 100)
        : 0;
    public string CandidateProbeActionLabel => IsCandidateProbeRunning
        ? "停止测速"
        : "重新测速";
    public string CandidateProbeAutomationName => IsCandidateProbeRunning
        ? "停止当前线路测速"
        : "重新测量当前源站全部线路延迟";
    public string CandidateDetailTitle => string.IsNullOrWhiteSpace(SelectedSourceDisplay) ? "线路详情" : $"{SelectedSourceDisplay} · 线路详情";
    public string CandidateProbeSummaryText => CandidateOptions.Count == 0
        ? "当前源站没有已签名线路"
        : _pendingCandidateProbeSources.Contains(Source)
            ? _candidateProbeProgressBySource.TryGetValue(Source, out var progress) && progress.Total > 0
                ? $"正在测速 · {progress.Completed}/{progress.Total} · 已完成的线路会立即显示结果"
                : $"正在测速 · 共 {CandidateOptions.Count} 条"
            : _candidateProbesBySource.TryGetValue(Source, out var probes)
                ? $"{probes.Values.Count(candidate => candidate.Success)} 条可用 · 共 {CandidateOptions.Count} 条{CandidateProbeDurationText(Source)}"
                : $"共 {CandidateOptions.Count} 条 · 点击重新测速";
    public string CandidateEmptyText => _coordinator.IsEnrolled
        ? "当前签名配置没有可展示的候选线路；可以刷新配置或切换源站。"
        : "完成设备激活后，已签名候选线路会显示在这里。";
    public string CandidateMode { get => _state.CandidateMode; set
    {
        var mode = CandidateSelectionContract.ParseMode(value);
        var next = mode == global::Bifrost.CandidateMode.Manual ? "manual" : "auto";
        if (next == _state.CandidateMode) return;
        if (next == "auto") _autoCandidateLabel = "";
        var presentationMode = _state.Mode == ProtocolCodes.ModeSmartGate
            ? ProtocolCodes.ModeSmartGate
            : next == "auto" ? ProtocolCodes.ModeSmart : ProtocolCodes.ModeGlobal;
        var typed = ConnectionRouteSelection.FromPresentation(presentationMode, _state.AppPolicyEnabled && presentationMode == ProtocolCodes.ModeSmart);
        Update(_state with
        {
            Mode = presentationMode,
            ConnectionType = typed.ConnectionTypeCode,
            RouteMode = typed.RouteModeCode,
            CandidateMode = _state.Mode == ProtocolCodes.ModeSmartGate ? "auto" : next,
            CandidateLabel = next == "manual" ? _state.CandidateLabel : "",
            Country = presentationMode == ProtocolCodes.ModeSmartGate ? _state.Country : "default",
            FrontSource = presentationMode == ProtocolCodes.ModeSmartGate ? _state.FrontSource : "auto",
        }, persist: true);
        if (next == "auto" && _probeLifecycleStarted) _probeLifecycle.TriggerManual();
    } }
    public bool IsAutoCandidateMode { get => CandidateMode == "auto"; set { if (value) CandidateMode = "auto"; } }
    public bool IsManualCandidateMode { get => CandidateMode == "manual"; set { if (value) CandidateMode = "manual"; } }
    public string CandidateLabel { get => _state.CandidateLabel; set => Update(_state with { CandidateLabel = value ?? "" }, persist: true); }
    public string EffectiveCandidateLabel => _state.IsProtected && !string.IsNullOrWhiteSpace(_autoCandidateLabel)
        ? _autoCandidateLabel
        : CandidateMode == "manual"
        ? (string.IsNullOrWhiteSpace(CandidateLabel) ? "请选择线路" : CandidateOptions.FirstOrDefault(option => option.Code == CandidateLabel)?.Name ?? CandidateLabel)
        : (string.IsNullOrWhiteSpace(_autoCandidateLabel) ? "自动优选" : CandidateOptions.FirstOrDefault(option => option.Code == _autoCandidateLabel)?.Name ?? _autoCandidateLabel);
    internal IReadOnlyList<string> LastAutomaticCandidateAttempts => _lastAutomaticCandidateAttempts.ToArray();
    internal CandidateProbeSnapshot? LastAutomaticMeasurement => _lastAutomaticMeasurement;
#if BIFROST_INTERNAL_LIVE_VALIDATION
    internal Task<CandidateProbeSnapshot> RunLiveLatencyValidationAsync(string source) =>
        _coordinator.ProbeCandidateStatusesAsync(source, null, _lifetime.Token);
#endif
    public IReadOnlyList<string> ApplicationRuleItems => ActiveApplicationText
        .Replace("\r\n", "\n", StringComparison.Ordinal)
        .Replace('\r', '\n')
        .Split(new[] { ',', ';', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Take(6)
        .ToArray();
    public string ApplicationRuleAction => _state.AppPolicy == "exclude" ? "直连" : "代理";
    public string ApplicationRuleSummary => !_state.AppPolicyEnabled
        ? "应用分流未启用"
        : ApplicationRuleItems.Count == 0 ? "尚未添加应用" : $"已配置 {ApplicationRuleItems.Count} 个应用";
    private string ActiveApplicationText => _state.AppPolicy == "exclude" ? _state.ExcludeApps : _state.IncludeApps;
    public ICommand NavigateCommand { get; }
    public ICommand ToggleThemeCommand { get; }
    public ICommand SelectSourceCommand { get; }
    public ICommand SelectCandidateCommand { get; }
    public ICommand UseCandidateCommand { get; }
    public ICommand RefreshCandidateProbesCommand { get; }
    public ICommand ConnectCommand => _connectCommand;
    public ICommand RefreshCommand => _refreshCommand; public ICommand CheckUpdateCommand => _checkUpdateCommand; public AsyncResultCommand<EnrollRequest, ControlResult?> EnrollCommand { get; }
    public AsyncResultCommand<RecoverRequest, ControlResult?> RecoverCommand { get; }
    public AsyncResultCommand<PairingRequest, ControlResult?> PairCommand { get; } public ICommand LogoutCommand { get; }

    public Task StartAsync()
    {
        if (_coordinator.HasPendingRecovery)
        {
            EnsureRecoveryDeliveryLoopStarted();
            return Task.CompletedTask;
        }
        if (!_coordinator.IsEnrolled)
        {
            // The control plane can have accepted this device even when the
            // first signed configuration was not committed locally. Always
            // keep using the retained device identity until activation finishes.
            // A bounded backoff handles slow Wi-Fi, DNS and transient Control
            // outages without user clicks. RefreshAsync returns Ok=false only
            // when Control explicitly reports that the key is not registered.
            _startupTask ??= WarmStartAsync();
            return Task.CompletedTask;
        }
        // First paint must not wait for a control-plane round-trip or a full
        // real-delay sweep. Cached, already-verified options were loaded in
        // the constructor; background owners take over after the window is
        // interactive.
        if (_statusPollTask is null) _statusPollTask = PollServiceStatusAsync();
        EnsureConfigRefreshLoopStarted();
        EnsureProgramUpdateLoopStarted();
        _startupTask ??= WarmStartAsync();
        return Task.CompletedTask;
    }

    private void EnsureRecoveryDeliveryLoopStarted()
    {
        if (_recoveryDeliveryTask is null && _coordinator.HasPendingRecovery)
            _recoveryDeliveryTask = RecoveryDeliveryLoopAsync();
    }

    private async Task RecoveryDeliveryLoopAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested && _coordinator.HasPendingRecovery)
            {
                try
                {
                    var result = await _coordinator.RetrieveRecoveryDeliveryAsync(_lifetime.Token).ConfigureAwait(false);
                    if (result.Ok && _coordinator.IsEnrolled)
                    {
                        ApplyOptions(_coordinator.GetUiConfigOptions());
                        Update(_state with
                        {
                            Page = "home",
                            IsEnrolled = true,
                            UpdateText = "设备恢复完成，正在恢复连接和更新检查。",
                            ConfigText = $"配置：签名有效 v{result.ConfigVersion}"
                        }, persist: true);
                        StartProbeLifecycleIfReady();
                        EnsureConfigRefreshLoopStarted();
                        EnsureProgramUpdateLoopStarted();
                        return;
                    }
                }
                catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { return; }
                catch
                {
                    Update(_state with { UpdateText = "恢复申请已提交，等待管理员批准；批准后软件会自动继续。" });
                }
                await Task.Delay(TimeSpan.FromSeconds(15), _lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        finally { _recoveryDeliveryTask = null; }
    }

    private void EnsureProgramUpdateLoopStarted()
    {
        if (_programUpdateLoopTask is null && _coordinator.IsEnrolled)
            _programUpdateLoopTask = ProgramUpdateLoopAsync();
    }

    private async Task ProgramUpdateLoopAsync()
    {
        try
        {
            await _programUpdateScheduler.DelayAsync(ProgramUpdateStartupDelay, _lifetime.Token).ConfigureAwait(false);
            while (!_lifetime.IsCancellationRequested)
            {
                await CheckProgramUpdateCoreAsync(automatic: true).ConfigureAwait(false);
                await _programUpdateScheduler.DelayAsync(ProgramUpdateInterval, _lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
    }

    private async Task WarmStartAsync()
    {
        var previousConfigVersion = _coordinator.LastConfigVersion;
        var previousNodeFingerprint = _coordinator.NodeConfigurationFingerprint;
        var resumeActivation = !_coordinator.IsEnrolled;
        var retryIndex = 0;
        while (!_lifetime.IsCancellationRequested)
        {
            try
            {
                var result = await _coordinator.RefreshAsync(_lifetime.Token).ConfigureAwait(false);
                if (!result.Ok || !_coordinator.IsEnrolled)
                    return;

                var options = _coordinator.GetUiConfigOptions();
                var currentNodeFingerprint = _coordinator.NodeConfigurationFingerprint;
                _dispatcher.Post(() =>
                {
                    if (Volatile.Read(ref _disposed) != 0) return;
                    ApplyOptions(options);
                    NotifyNodeConfigurationUpdated(previousConfigVersion, result.ConfigVersion, previousNodeFingerprint, currentNodeFingerprint);
                    Update(_state with
                    {
                        IsEnrolled = true,
                        ConfigText = $"配置：签名有效 v{result.ConfigVersion}"
                    }, persist: true);
                    if (_statusPollTask is null) _statusPollTask = PollServiceStatusAsync();
                    StartProbeLifecycleIfReady();
                    EnsureConfigRefreshLoopStarted();
                    EnsureProgramUpdateLoopStarted();
                });
                return;
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { return; }
            catch
            {
                if (!resumeActivation) return;
                // A retained identity remains the activation authority after a
                // transient failure. Retry forever with a delay capped at one
                // minute; only the explicit not-registered result above stops it.
            }

            var delay = ActivationResumeRetryDelays[Math.Min(retryIndex, ActivationResumeRetryDelays.Length - 1)];
            retryIndex++;
            try
            {
                await _startupRetryScheduler.DelayAsync(delay, _lifetime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { return; }
        }
    }
    internal void SetPresentation(UiPresentationState presentation) => Update(_state with { Presentation = presentation, IsEnrolled = true, StatusText = presentation.StatusText });
    internal void SetTheme(string theme)
    {
        const string normalized = "dark";
        var next = _state with { Theme = normalized };
        // Apply the visual choice first.  A secure-store write failure must
        // not make the theme toggle look inert; persistence is best effort and
        // never blocks navigation or the local evaluation workflow.
        Update(next, persist: false);
        try { _persistence.Save(next); } catch { }
    }
    internal void SetDesignDirection(string direction)
    {
        var normalized = direction is "b" or "c" ? direction : "a";
        var next = _state with { DesignDirection = normalized };
        // Match theme behaviour: switching visual direction should feel
        // immediate even when protected storage is momentarily unavailable.
        Update(next, persist: false);
        try { _persistence.Save(next); } catch { }
    }
    // Page selection is an ephemeral UI concern.  A filesystem/DPAPI
    // persistence hiccup must not make navigation appear broken or revert to
    // the home page; only user configuration choices require persistence.
    internal void SetPage(string page) => Update(_state with { Page = page is "nodes" or "routing" or "activity" or "settings" ? page : "home" }, persist: false);
    public Task NavigateAsync(string page)
    {
        SetPage(page);
        if (string.Equals(_state.Page, "nodes", StringComparison.Ordinal) &&
            CandidateOptions.Count > 0 && !_candidateProbesBySource.ContainsKey(Source) &&
            !_pendingCandidateProbeSources.Contains(Source))
            EnsureProbeLifecycleStarted(clearExisting: false);
        return Task.CompletedTask;
    }
    private Task SelectSourceAsync(string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || !ContainsOption(SourceOptions, code)) return Task.CompletedTask;
        Source = code;
        return Task.CompletedTask;
    }
    private Task SelectCandidateAsync(string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || !ContainsOption(CandidateOptions, code)) return Task.CompletedTask;
        var typed = ConnectionRouteSelection.FromPresentation(ProtocolCodes.ModeGlobal, appPolicyEnabled: false);
        Update(_state with { Mode = ProtocolCodes.ModeGlobal, ConnectionType = typed.ConnectionTypeCode, RouteMode = typed.RouteModeCode, CandidateMode = "manual", CandidateLabel = code, Country = "default", FrontSource = "auto", AppPolicyEnabled = false }, persist: true);
        return Task.CompletedTask;
    }
    private Task ToggleThemeAsync()
    {
        SetTheme("dark");
        return Task.CompletedTask;
    }
    private async Task UseCandidateAsync(string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || !CanEditConnectionSettings || !ContainsOption(CandidateOptions, code)) return;
        var route = CandidateRoutes.FirstOrDefault(candidate => string.Equals(candidate.Code, code, StringComparison.OrdinalIgnoreCase));
        if (route is not { CanUse: true }) return;
        var mode = ProtocolCodes.ModeGlobal;
        var applicationPolicyEnabled = mode == ProtocolCodes.ModeSmart && _state.AppPolicyEnabled;
        var typed = ConnectionRouteSelection.FromPresentation(mode, applicationPolicyEnabled);
        Update(_state with
        {
            Mode = mode,
            ConnectionType = typed.ConnectionTypeCode,
            RouteMode = typed.RouteModeCode,
            CandidateMode = "manual",
            CandidateLabel = code,
            AppPolicyEnabled = applicationPolicyEnabled,
        }, persist: true);
        await ConnectAsync();
    }
    private Task RefreshCandidateProbesAsync()
    {
        if (!_coordinator.IsEnrolled || string.IsNullOrWhiteSpace(Source)) return Task.CompletedTask;
        if (IsCandidateProbeRunning)
        {
            var source = Source;
            var progress = _candidateProbeProgressBySource.TryGetValue(source, out var current) ? current : (0, CandidateOptions.Count);
            _probeLifecycle.CancelManual();
            _pendingCandidateProbeSources.Remove(source);
            _candidateProbeProgressBySource.Remove(source);
            if (_candidateProbeStartedBySource.Remove(source, out var started))
                _candidateProbeDurationBySource[source] = DateTimeOffset.UtcNow - started;
            Update(_state with
            {
                UpdateText = progress.Item2 > 0
                    ? $"已停止线路测速：已完成 {progress.Item1}/{progress.Item2}"
                    : "已停止线路测速"
            });
            return Task.CompletedTask;
        }
        if (CandidateOptions.Count == 0) return Task.CompletedTask;
        if (!EnsureProbeLifecycleStarted(clearExisting: true))
        {
            MarkCandidateProbePending(Source, clearExisting: true);
            _probeLifecycle.TriggerManual();
        }
        return Task.CompletedTask;
    }

    public async Task<ControlResult?> EnrollAsync(string inviteCode)
    {
        if (!TryBeginBusy()) return null;
        ShouldClearEnrollmentInvite = false;
        try
        {
            Update(_state with { UpdateText = "正在激活设备，请勿关闭软件或更换邀请码…" });
            var result = await _coordinator.EnrollAsync(inviteCode, _lifetime.Token);
            ApplyOptions(_coordinator.GetUiConfigOptions());
            var activated = result.Ok && _coordinator.IsEnrolled;
            Update(_state with
            {
                Page = activated ? "home" : "settings",
                IsEnrolled = activated,
                UpdateText = $"节点更新：{result.Message}（配置版本 {result.ConfigVersion}）",
                ConfigText = activated ? $"配置：签名有效 v{result.ConfigVersion}" : "配置：请重新激活设备"
            }, persist: true);
            if (activated && _coordinator.IsLocalEvaluation) await RefreshServiceReadinessAsync();
            if (activated)
            {
                StartProbeLifecycleIfReady();
                EnsureConfigRefreshLoopStarted();
                EnsureProgramUpdateLoopStarted();
            }
            ShouldClearEnrollmentInvite = true;
            return result;
        }
        catch (Exception error)
        {
            _lastOperationErrorAt = DateTimeOffset.UtcNow;
            // A rejected code cannot be resumed, so clear it and allow the user to
            // enter a replacement.  Every other failure can be after server-side
            // redemption, in which case retaining the exact code enables a safe retry.
            ShouldClearEnrollmentInvite = UiErrorMapper.ExtractCode(error) is "BF-ENROLL-001" or "BF-ENROLL-002";
            Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "激活") });
            return null;
        }
        finally { EndBusy(); }
    }

    internal bool ShouldClearEnrollmentInvite { get; private set; } = true;

    public async Task<ControlResult?> RecoverAsync(string publicId, string recoveryCode)
    {
        if (!TryBeginBusy()) return null;
        try
        {
            var result = await _coordinator.RecoverAsync(publicId, recoveryCode, _lifetime.Token);
            Update(_state with { UpdateText = "恢复申请已提交，等待管理员批准；批准后软件会自动继续。" });
            EnsureRecoveryDeliveryLoopStarted();
            return result;
        }
        catch (Exception error) { Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "恢复申请") }); return null; }
        finally { EndBusy(); }
    }

    public async Task<ControlResult?> RotateRecoveryCodeAsync()
    {
        if (!TryBeginBusy()) return null;
        try
        {
            var result = await _coordinator.RotateRecoveryCodeAsync(_lifetime.Token);
            Update(_state with { UpdateText = "新的账号恢复码已生成并安全保存在本机；旧恢复码已失效。" });
            return result;
        }
        catch (Exception error)
        {
            Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "重新生成恢复码") });
            return null;
        }
        finally { EndBusy(); }
    }

    public async Task<ControlResult?> CreatePairingAsync()
    {
        if (!TryBeginBusy()) return null;
        try { return await _coordinator.CreatePairingAsync("android", _lifetime.Token); }
        catch (Exception error) { Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "生成配对码") }); return null; }
        finally { EndBusy(); }
    }

    public async Task<ControlResult?> RedeemPairingAsync(string pairingCode)
    {
        if (!TryBeginBusy()) return null;
        try
        {
            var result = await _coordinator.RedeemPairingAsync(pairingCode, _lifetime.Token);
            ApplyOptions(_coordinator.GetUiConfigOptions());
            Update(_state with { IsEnrolled = result.Ok, UpdateText = $"配对完成：配置 v{result.ConfigVersion}" }, persist: true);
            if (result.Ok && _coordinator.IsLocalEvaluation) await RefreshServiceReadinessAsync();
            if (result.Ok)
            {
                StartProbeLifecycleIfReady();
                EnsureConfigRefreshLoopStarted();
                EnsureProgramUpdateLoopStarted();
            }
            return result;
        }
        catch (Exception error) { Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "兑换配对码") }); return null; }
        finally { EndBusy(); }
    }

    // Activation and pairing can complete while the process was opened
    // un-enrolled. Start the one lifetime owner only after the coordinator has
    // published an enrolled state and a positive verified config generation.
    // An empty source is intentional here: the owner remains armed so a later
    // valid explicit selection starts exactly one probe.
    private void StartProbeLifecycleIfReady()
    {
        if (string.Equals(_state.Page, "nodes", StringComparison.Ordinal))
            EnsureProbeLifecycleStarted(clearExisting: false);
    }

    private bool EnsureProbeLifecycleStarted(bool clearExisting)
    {
        if (_probeLifecycleStarted || !_coordinator.IsEnrolled || _coordinator.LastConfigVersion <= 0 ||
            string.IsNullOrWhiteSpace(Source) || string.Equals(Source, "auto", StringComparison.OrdinalIgnoreCase)) return false;
        _probeLifecycleStarted = true;
        MarkCandidateProbePending(Source, clearExisting);
        _probeLifecycle.Start(Source, _coordinator.LastConfigVersion);
        return true;
    }

    public async Task LogoutAsync()
    {
        if (!TryBeginBusy()) return;
        try
        {
            if (_state.IsProtected) ApplyStatus(await _coordinator.DisconnectAsync(_lifetime.Token));
            await _coordinator.LogoutAsync(_lifetime.Token);
            SetServiceReady(false);
            Update(_state with { IsEnrolled = false, Presentation = UiPresentationState.Idle("设备已注销"), UpdateText = "账户：设备已注销，需要邀请码或恢复码重新登记", ConfigText = "配置：请重新激活设备" }, persist: true);
        }
        catch (Exception error) { Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "注销") }); }
        finally { EndBusy(); }
    }

    public async Task ConnectAsync()
        => await ConnectCoreAsync(automaticRecovery: false);

    private async Task ConnectCoreAsync(bool automaticRecovery)
    {
        Interlocked.Increment(ref _connectionActionRevision);
        if (_updatePromotionRunning) return;
        if (!TryBeginBusy()) return;
        var connectTimer = System.Diagnostics.Stopwatch.StartNew();
        var connectPhase = "begin";
        try
        {
            if (!automaticRecovery && _state.Presentation.State == UiConnectionState.Reconnecting)
            {
                ApplyStatus(await _coordinator.DisconnectAsync(_lifetime.Token));
                return;
            }
            if (_state.IsProtected)
            {
                // A delayed recovery must never toggle a connection that has
                // already recovered in Mihomo or through a user action.
                if (automaticRecovery) return;
                ApplyStatus(await _coordinator.DisconnectAsync(_lifetime.Token));
                return;
            }
            // A failed connect intentionally leaves the LocalSystem runtime in
            // a fail-closed Blocked phase until an explicit teardown occurs.
            // Keep that recovery action reachable from the same dial instead
            // of disabling the UI and forcing a service restart.
            if (_state.Presentation.State == UiConnectionState.Blocked)
            {
                ApplyStatus(await _coordinator.DisconnectAsync(_lifetime.Token));
                if (!automaticRecovery && (_state.Mode != ProtocolCodes.ModeSmart || _state.CandidateMode != "auto")) return;
                if (_state.Presentation.State == UiConnectionState.Blocked)
                    throw new ServiceException("BF-CONNECTION-TEARDOWN", "runtime teardown did not complete");
                Update(_state with
                {
                    Presentation = UiPresentationState.Reconnecting(),
                    StatusText = IsSmartGateMode ? "正在恢复所选 SmartGate 节点…" : "当前候选失效，正在源站内切换…"
                });
            }
            // Give the primary dial observable feedback before any control
            // refresh, candidate probe or LocalSystem startup can block for a
            // few seconds.  A real click must never look like a dead surface.
            Update(_state with
            {
                Presentation = UiPresentationState.Preparing(),
                StatusText = "正在连接…"
            });
            // Refresh through the production control client before every
            // compile/stage/connect.  Only its narrow transport classifier
            // may authorize offline LKG use; auth, revocation, contract and
            // signature failures remain blocked.
            connectPhase = "control-refresh";
            var refresh = await _coordinator.RefreshAsync(_lifetime.Token);
            if (!refresh.Ok) throw new InvalidOperationException(_coordinator.IsLocalEvaluation ? "BF-LOCAL-EVALUATION-ACTIVATION-REQUIRED" : "BF-CONTROL-REFRESH");
            // A click is also a recovery path after a transient startup/control
            // refresh failure.  Rehydrate the signed option catalogue here so
            // the primary action can recover without requiring the user to
            // visit the Lines page and press Refresh first.
            ApplyOptions(_coordinator.GetUiConfigOptions());
            Update(_state with
            {
                IsEnrolled = true,
                ConfigText = $"配置：签名有效 v{refresh.ConfigVersion}",
                StatusText = "配置已同步，正在准备线路…"
            });
            if (_coordinator.IsLocalEvaluation) await RefreshServiceReadinessAsync(applyPresentation: false);
            if (string.IsNullOrWhiteSpace(Source) || Source.Equals("auto", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SOURCE-SELECTION-REQUIRED");
            if (IsSmartGateMode && !HasSelectedSmartGateNode)
            {
                Update(_state with
                {
                    Presentation = UiPresentationState.Error("请先选择 SmartGate 节点"),
                    StatusText = "请先选择 SmartGate 节点",
                    UpdateText = CountryOptions.Count == 0 ? "当前没有管理员已发布的 SmartGate 节点" : "SmartGate 需要由用户手动选择节点后才能连接"
                });
                return;
            }
            var include = _state.AppPolicyEnabled ? SplitApplications(_state.IncludeApps) : Array.Empty<string>();
            var exclude = _state.AppPolicyEnabled ? SplitApplications(_state.ExcludeApps) : Array.Empty<string>();
            if (_state.AppPolicyEnabled && ((_state.AppPolicy == "allow" && (include.Length == 0 || exclude.Length > 0)) || (_state.AppPolicy == "exclude" && (exclude.Length == 0 || include.Length > 0))))
                throw new InvalidDataException(_state.AppPolicy == "allow" ? "BF-APP-ALLOW-EMPTY" : "BF-APP-EXCLUDE-EMPTY");
            var typed = ConnectionRouteSelection.Parse(_state.ConnectionType, _state.RouteMode);
            var mode = typed.RouteModeCode;
            var snapshot = ApplicationPolicySnapshot.Create(mode, _state.AppPolicyEnabled ? _state.AppPolicy : "none", include, exclude, Guid.NewGuid().ToString("N"));
            Update(_state with { StatusText = "正在准备安全配置…" });
            IReadOnlyList<string> candidateOrder;
            if (_state.CandidateMode == "auto")
            {
                _lastAutomaticCandidateAttempts.Clear();
                _lastAutomaticMeasurement = null;
                // The placeholder candidate authorizes the signed source
                // package only. LocalSystem compiles every candidate in that
                // source into one Mihomo provider; Mihomo's URLTest performs
                // selection without a second pre-connect sweep or TUN restart.
                var placeholder = CandidateOptions.FirstOrDefault()?.Code;
                if (string.IsNullOrWhiteSpace(placeholder)) throw new ServiceException("BF-CANDIDATE-MISSING", "selected source has no signed candidates");
                candidateOrder = new[] { placeholder };
                connectPhase = "prepare-mihomo-provider";
                Update(_state with { StatusText = $"正在启动源站 {_state.Source} 的 Mihomo 智能选线…" });
            }
            else
            {
                if (!ContainsOption(CandidateOptions, _state.CandidateLabel)) throw new InvalidDataException("BF-CANDIDATE-NOT-READY");
                candidateOrder = new[] { _state.CandidateLabel };
            }

            Exception? lastCandidateFailure = null;
            ServiceStatus? connectedStatus = null;
            for (var candidateIndex = 0; candidateIndex < candidateOrder.Count; candidateIndex++)
            {
                var candidateLabel = candidateOrder[candidateIndex];
                var packageState = _state with { CandidateMode = "manual", CandidateLabel = candidateLabel };
                try
                {
                    Update(_state with { StatusText = _state.CandidateMode == "auto"
                        ? $"正在并发测量源站 {_state.Source} 的 {CandidateOptions.Count} 条线路并选择最优项…"
                        : $"正在连接 {_state.Source} · {candidateLabel}…" });
                    connectPhase = "prepare-signed-package";
                    var package = await _coordinator.PrepareSignedPackageAsync(packageState, snapshot, _lifetime.Token);
                    connectPhase = "stage-config";
                    var staged = await _coordinator.StageConfigAsync(package, _lifetime.Token);
                    if (!staged.Ok || string.IsNullOrWhiteSpace(staged.ConfigId) || !PipeClientProtocol.IsOpaqueId(staged.ConfigId, "cfg_") || staged.Core != ProtocolCodes.CoreMihomo)
                        throw new ServiceException(staged.Code ?? "BF-CONFIG-PACKAGE", "invalid staged configuration identity");
                    connectPhase = "connect-runtime";
                    connectedStatus = await _coordinator.ConnectAsync(packageState, snapshot, staged.ConfigId, staged.Core, _lifetime.Token);
                    if (_state.CandidateMode == "auto") _autoCandidateLabel = "";
                    break;
                }
                catch (Exception error) when (_state.CandidateMode == "auto" && !_lifetime.IsCancellationRequested &&
                    error is not ServiceException { Code: "BF-CONNECTION-RESET-REQUIRED" })
                {
                    lastCandidateFailure = error;
                    var abortAutomaticFailover = IsHostCutoverFailure(error);
                    var hasNextCandidate = !abortAutomaticFailover && candidateIndex + 1 < candidateOrder.Count;
                    Update(_state with { StatusText = hasNextCandidate
                        ? $"{_state.Source} · {candidateLabel} 失败，正在恢复原网络…"
                        : $"源站 {_state.Source} 的全部可用候选均连接失败，正在恢复原网络…" });
                    // A failed startup is never allowed to leave a partial
                    // TUN behind, even when this was the final candidate.
                    // Service-side rollback is authoritative; this explicit
                    // disconnect is a second idempotent cleanup fence.  Never
                    // swallow cleanup failure and then stack another startup
                    // on top of stale routes/TUN state: if the service cannot
                    // prove a fully disconnected state, automatic failover
                    // stops here and the original error is replaced by the
                    // teardown failure.
                    var cleanup = await _coordinator.DisconnectAsync(_lifetime.Token);
                    if (!cleanup.Ok || cleanup.Connected || !string.Equals(cleanup.State, "disconnected", StringComparison.OrdinalIgnoreCase))
                        throw new ServiceException(cleanup.Code ?? "BF-CONNECTION-TEARDOWN", "failed candidate did not restore the original network before retry");
                    var cleanReadback = await _coordinator.GetStatusAsync(_lifetime.Token);
                    if (!cleanReadback.Ok || cleanReadback.Connected || !string.Equals(cleanReadback.State, "disconnected", StringComparison.OrdinalIgnoreCase))
                        throw new ServiceException(cleanReadback.Code ?? "BF-CONNECTION-TEARDOWN", "service readback is not clean after failed candidate teardown");
                    if (abortAutomaticFailover)
                        throw;
                    if (hasNextCandidate)
                        Update(_state with { StatusText = $"原网络已恢复，正在尝试下一条…" });
                }
            }
            if (connectedStatus is null) throw lastCandidateFailure ?? new ServiceException("BF-CANDIDATE-PROBE-FAILED", "all candidates in the selected source failed connect");
            ApplyStatus(connectedStatus);
            connectPhase = "connected-readback";
            connectTimer.Stop();
            if (_state.Presentation.IsProtected)
                Update(_state with { UpdateText = $"连接完成 · {connectTimer.Elapsed.TotalSeconds:0.0} 秒" });
        }
        catch (Exception error)
        {
            // A conflicting request was never admitted. Its cleanup must not
            // disconnect a session established by another request/window.
            if (error is ServiceException { Code: "BF-CONNECTION-RESET-REQUIRED" })
            {
                try
                {
                    var active = await _coordinator.GetStatusAsync(_lifetime.Token);
                    if (active.Ok && active.Connected)
                    {
                        ApplyStatus(active);
                        Update(_state with { UpdateText = "当前连接仍在运行，本次连接请求未执行；切换设置请先断开当前连接。" });
                        return;
                    }
                }
                catch { }
            }
            RecordStableConnectFailure(error, connectPhase);
            var message = error.Message == "BF-LOCAL-EVALUATION-ACTIVATION-REQUIRED"
                ? "请先在本机控制面完成邀请码激活并刷新已验证配置"
                : UiErrorMapper.ToUserMessage(error, "连接");
            var diagnostic = _coordinator.IsLocalEvaluation
                ? error is ServiceException serviceError
                    ? string.IsNullOrWhiteSpace(serviceError.Diagnostic)
                        ? serviceError.Code
                        : $"{serviceError.Code}|{serviceError.Diagnostic}"
                    : UiErrorMapper.ExtractCode(error)
                : null;
            UiPresentationState? blockedPresentation = null;
            if (error is ServiceException)
            {
                try
                {
                    var serviceStatus = await _coordinator.GetStatusAsync(_lifetime.Token);
                    if (string.Equals(serviceStatus.State, "blocked", StringComparison.OrdinalIgnoreCase))
                        blockedPresentation = UiPresentationReducer.FromServiceStatus(serviceStatus);
                }
                catch { }
            }
            var displayMessage = string.IsNullOrWhiteSpace(diagnostic) ? message : $"{message} [{diagnostic}]";
            Update(_state with
            {
                Presentation = blockedPresentation ?? UiPresentationState.Error(displayMessage),
                StatusText = displayMessage,
                UpdateText = string.IsNullOrWhiteSpace(diagnostic) ? _state.UpdateText : $"本地诊断：{diagnostic}"
            });
        }
        finally { EndBusy(); }
    }

    private static void RecordStableConnectFailure(Exception error, string phase)
    {
        try
        {
            string? code = null;
            for (var current = error; current is not null; current = current.InnerException)
            {
                var candidate = current.Message?.Trim();
                if (!string.IsNullOrWhiteSpace(candidate) && candidate.StartsWith("BF-", StringComparison.Ordinal) &&
                    candidate.Length <= 96 && candidate.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                {
                    code = candidate;
                    break;
                }
            }
            if (string.IsNullOrWhiteSpace(code) || !code.StartsWith("BF-", StringComparison.Ordinal) ||
                code.Length > 96 || code.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch == '-')))
                code = "BF-CLIENT-CONNECT-FAILED";
#if BIFROST_TEST_HARNESS
            var directory = Path.Combine(Path.GetTempPath(), "bifrost-test-diagnostics");
#else
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost");
#endif
            Directory.CreateDirectory(directory);
            var record = JsonSerializer.Serialize(new
            {
                schema = "BIFROST-CLIENT-CONNECT-DIAGNOSTIC-1",
                code,
                phase,
                exception_type = error.GetType().Name,
                service_code = error is ServiceException serviceError ? serviceError.Code : null,
                timestamp = DateTimeOffset.UtcNow.ToString("O")
            });
            File.WriteAllText(Path.Combine(directory, "last-connect-error.json"), record + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { }
    }

    public async Task<bool> RefreshAsync()
    {
        if (!TryBeginBusy()) return false;
        try
        {
            var before = _coordinator.LastConfigVersion;
            var previousNodeFingerprint = _coordinator.NodeConfigurationFingerprint;
            var result = await _coordinator.RefreshAsync(_lifetime.Token);
            if (!result.Ok)
            {
                Update(_state with { IsEnrolled = false, UpdateText = "没有可用的已验证配置，请先完成设备激活" });
                return false;
            }
            ApplyOptions(_coordinator.GetUiConfigOptions());
            Update(_state with { IsEnrolled = true, UpdateText = $"节点更新：{result.Message}（配置版本 {result.ConfigVersion}）", ConfigText = $"配置：签名有效 v{result.ConfigVersion}" });
            NotifyNodeConfigurationUpdated(before, result.ConfigVersion, previousNodeFingerprint, _coordinator.NodeConfigurationFingerprint);
            if (_coordinator.IsLocalEvaluation) await RefreshServiceReadinessAsync();
            if (_probeLifecycleStarted)
            {
                MarkCandidateProbePending(Source, clearExisting: true);
                _probeLifecycle.ConfigurationRefreshed(Source, _coordinator.LastConfigVersion);
                _probeLifecycle.TriggerManual();
            }
            return result.Ok;
        }
        catch (Exception error) { Update(_state with { UpdateText = UiErrorMapper.ToUserMessage(error, "刷新") }); return false; }
        finally { EndBusy(); }
    }

    public Task CheckProgramUpdateAsync() => CheckProgramUpdateCoreAsync(automatic: false);

    private async Task CheckProgramUpdateCoreAsync(bool automatic)
    {
        if (_updatePromotionRunning) return;
        if (Interlocked.Exchange(ref _updateOperationRunning, 1) != 0) return;
        long notifySequence = 0;
        if (!automatic) SetUpdateFeedback(0, "checking", "正在检查更新", "正在连接更新服务…");
        try
        {
            IProgress<ReleaseUpdateProgress>? progress = automatic ? null : new Progress<ReleaseUpdateProgress>(report =>
            {
                // Progress<T> posts back to the WPF synchronization context.
                // A very fast terminal result can therefore finish before an
                // earlier "checking" callback is dequeued. Never let a late
                // progress notification overwrite a completed/failed state.
                if (!IsUpdateChecking) return;
                var title = report.Stage switch
                {
                    "checking" => "正在检查更新",
                    "verifying" or "verified" => "正在验证更新",
                    "downloading" => "正在下载更新",
                    "finalizing" => "正在准备安装",
                    "current" => "已是最新版本",
                    "staged" => "更新已准备完成",
                    "unavailable" => "暂无可用更新",
                    _ => "正在处理更新",
                };
                SetUpdateFeedback(report.Percent, report.Stage, title, report.Message);
            });
            var result = automatic
                ? await _coordinator.DiscoverProgramUpdateAsync(_lifetime.Token)
                : await _coordinator.CheckProgramUpdateAsync(progress, _lifetime.Token);
            if (_coordinator.IsEnrolled && !_state.IsEnrolled)
            {
                ApplyOptions(_coordinator.GetUiConfigOptions());
                Update(_state with
                {
                    IsEnrolled = true,
                    ConfigText = $"配置：签名有效 v{_coordinator.LastConfigVersion}"
                }, persist: true);
                StartProbeLifecycleIfReady();
                EnsureConfigRefreshLoopStarted();
                EnsureProgramUpdateLoopStarted();
            }
            switch (result?.State)
            {
                case "available":
                    SetUpdateFeedback(0, "available", "发现新版本", "确认后将自动下载、验证并安装更新");
                    notifySequence = result.Sequence;
                    break;
                case "up-to-date":
                    // A transient manual failure (for example while Control is
                    // being restarted) must not remain pinned in the settings
                    // UI after a later automatic check proves the release
                    // channel healthy again.
                    SetUpdateFeedback(100, "current", "已是最新版本",
                        result.Sequence > 0 ? $"当前已是最新签名版本 · 发布序列 {result.Sequence}" : "当前已是最新签名版本");
                    break;
                case "staged":
                    if (automatic)
                    {
                        SetUpdateFeedback(100, "available", "发现新版本，请及时更新",
                            result.Sequence > 0
                                ? $"新版本已下载并验证 · 发布序列 {result.Sequence} · 请点击“立即更新”完成安装"
                                : "新版本已下载并验证，请点击“立即更新”完成安装");
                        notifySequence = result.Sequence;
                        break;
                    }
                    SetUpdateFeedback(96, "installing", "正在安全安装更新",
                        result.Sequence > 0 ? $"新版本已下载并验证 · 发布序列 {result.Sequence} · 正在切换版本" : "新版本已下载并验证，正在切换版本");
                    ProgramUpdatePreparing?.Invoke(result.Sequence, _state.IsProtected);
                    _updatePromotionRunning = true;
                    var apply = await _coordinator.ApplyProgramUpdateAsync(_lifetime.Token).ConfigureAwait(false);
                    if (!apply.Ok || !string.Equals(apply.State, "update_scheduled", StringComparison.Ordinal))
                        throw new ServiceException(apply.Code ?? "BF-UPDATE-APPLY", "update installer was not scheduled");
                    SetUpdateFeedback(98, "installing", "更新正在安装",
                        result.Sequence > 0
                            ? $"安全更新已启动 · 发布序列 {result.Sequence} · 安装成功后将自动重启 Bifrost"
                            : "安全更新已启动，安装成功后将自动重启 Bifrost");
                    // LocalSystem owns the privileged promotion but session 0
                    // cannot safely relaunch the interactive desktop client.
                    // Keep this UI alive until the transaction result is known.
                    _dispatcher.Post(() => ProgramUpdateScheduled?.Invoke(result.Sequence));
                    break;
                case "verified":
                    if (!automatic) SetUpdateFeedback(100, "success", "更新验证完成", result.Message);
                    break;
                case "unavailable":
                    if (!automatic) SetUpdateFeedback(100, "warning", "暂无可用更新", "更新服务当前没有发布可安装的新版本");
                    break;
                case "disabled":
                    if (!automatic) SetUpdateFeedback(0, "warning", "当前无法检查", "当前发行环境未启用程序更新检查");
                    break;
                case null:
                    if (!automatic) SetUpdateFeedback(0, "warning", "当前无法检查", "当前发行环境未提供程序更新检查");
                    break;
                default:
                    if (!automatic)
                        SetUpdateFeedback(100, "success", "更新检查完成",
                            $"{result.Message}{(result.Sequence > 0 ? $" · 发布序列 {result.Sequence}" : string.Empty)}");
                    break;
            }
        }
        catch (TimeoutException)
        {
            if (!automatic) SetUpdateFeedback(0, "failed", "检查更新超时", "更新服务在 60 秒内没有响应，请稍后重试");
        }
        catch (InvalidOperationException error) when (error.Message == "BF-RELEASE-ORIGIN")
        {
            if (!automatic) SetUpdateFeedback(0, "warning", "当前无法检查", "当前为本地评估版，未接入正式 HTTPS 签名更新源");
        }
        catch (Exception error)
        {
            _updatePromotionRunning = false;
            if (!automatic) SetUpdateFeedback(0, "failed", "检查更新失败", UiErrorMapper.ToUserMessage(error, "检查更新"));
        }
        finally
        {
            Volatile.Write(ref _updateOperationRunning, 0);
            NotifyUpdateOperationChanged();
            if (notifySequence > 0 && notifySequence != _lastPromptedUpdateSequence)
            {
                _lastPromptedUpdateSequence = notifySequence;
                _dispatcher.Post(() => ProgramUpdateAvailable?.Invoke(notifySequence));
            }
        }
    }

    internal async Task ResumeAfterUpdateAsync()
    {
        var revision = Volatile.Read(ref _connectionActionRevision);
        try
        {
            if (_startupTask is not null) await _startupTask.WaitAsync(TimeSpan.FromSeconds(45), _lifetime.Token);
            if (revision != Volatile.Read(ref _connectionActionRevision) || _state.IsBusy) return;
            var status = await _coordinator.GetStatusAsync(_lifetime.Token);
            if (revision != Volatile.Read(ref _connectionActionRevision) || _state.IsBusy) return;
            ApplyStatus(status);
            if (_state.IsProtected) return;
            if (_state.Presentation.State == UiConnectionState.Blocked)
                ApplyStatus(await _coordinator.DisconnectAsync(_lifetime.Token));
            if (revision == Volatile.Read(ref _connectionActionRevision)) await ConnectAsync();
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            SetUpdateFeedback(100, "warning", "更新已完成", "连接尚未恢复，请点击连接重试。原有线路和设置已保留。");
        }
    }

    private void NotifyUpdateOperationChanged()
    {
        if (!_dispatcher.CheckAccess)
        {
            _dispatcher.Post(NotifyUpdateOperationChanged);
            return;
        }
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsUpdateChecking)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UpdateActionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UpdateProgressIndeterminate)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UpdateProgressText)));
        foreach (var name in new[] { nameof(CanInteract), nameof(CanEditConnectionSettings), nameof(CanUsePrimaryAction), nameof(CanConnect) })
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        CommandManager.InvalidateRequerySuggested();
    }

    private void SetUpdateFeedback(int percent, string kind, string title, string message)
    {
        if (!_dispatcher.CheckAccess)
        {
            _dispatcher.Post(() => SetUpdateFeedback(percent, kind, title, message));
            return;
        }
        _updateProgress = Math.Clamp(percent, 0, 100);
        _updateStatusKind = kind;
        _updateStatusTitle = title;
        _updateStatusMessage = message;
        foreach (var name in new[] { nameof(UpdateStatusMessage), nameof(IsUpdateChecking), nameof(UpdateProgress),
            nameof(UpdateProgressIndeterminate), nameof(UpdateProgressText), nameof(UpdateStatusKind),
            nameof(UpdateStatusTitle), nameof(UpdateActionLabel) })
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    internal void ApplyStatus(ServiceStatus status)
    {
        var presentation = UiPresentationReducer.FromServiceStatus(status);
        ApplyRuntimeSnapshot(status, presentation, _tunnelTelemetry.Capture(presentation.IsProtected));
    }

    private void ApplyMihomoReadback(ServiceStatus status)
    {
        if (status.Mihomo is not { } mihomo || string.IsNullOrWhiteSpace(status.Source))
        {
            if (!status.Connected && _state.CandidateMode == "auto") _autoCandidateLabel = "";
            return;
        }
        var measuredAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var candidates = mihomo.Candidates.Select(candidate => new CandidateProbeStatus(
            candidate.Name,
            candidate.Alive && candidate.DelayMs is > 0,
            candidate.DelayMs,
            candidate.Alive ? 0 : 100,
            measuredAt,
            candidate.Alive ? null : "BF-CANDIDATE-UNAVAILABLE")).ToArray();
        _candidateProbesBySource[status.Source] = candidates.ToDictionary(candidate => candidate.Code, StringComparer.OrdinalIgnoreCase);
        _pendingCandidateProbeSources.Remove(status.Source);
        _candidateProbeProgressBySource.Remove(status.Source);
        _autoCandidateLabel = mihomo.ActiveCandidate;
        _lastAutomaticMeasurement = new CandidateProbeSnapshot(status.Source, mihomo.ActiveCandidate, candidates);
        _lastAutomaticCandidateAttempts.Clear();
        _lastAutomaticCandidateAttempts.Add(mihomo.ActiveCandidate);
    }
    internal void SetUpdateMessage(string message) => Update(_state with { UpdateText = message });

    internal void SetProgramUpdateCompletionFeedback(bool success, string title, string message)
    {
        if (!success) _updatePromotionRunning = false;
        NotifyUpdateOperationChanged();
        SetUpdateFeedback(success ? 100 : 0, success ? "success" : "failed", title, message);
    }
    private void SetServiceReady(bool value)
    {
        if (_serviceReady == value) return;
        _serviceReady = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanConnect)));
    }

    private async Task RefreshServiceReadinessAsync(bool applyPresentation = true)
    {
        if (!_coordinator.IsLocalEvaluation) return;
        try
        {
            var status = await _coordinator.GetStatusAsync(_lifetime.Token);
            var recoverableBlocked = string.Equals(status.State, "blocked", StringComparison.OrdinalIgnoreCase);
            SetServiceReady(status.Ok || recoverableBlocked);
            if (applyPresentation) ApplyStatus(status);
        }
        catch
        {
            SetServiceReady(false);
            if (applyPresentation) Update(_state with { StatusText = "本机服务未就绪" });
        }
    }

    private async Task PollServiceStatusAsync()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            UiPresentationState? observedPresentation = null;
            try
            {
                // Keep one-second fault visibility while the tunnel is live,
                // but do not burn an authenticated pipe round-trip every
                // second while the application is merely sitting idle.
                var cadence = _state.Presentation.State switch
                {
                    UiConnectionState.Protected or UiConnectionState.Preparing or UiConnectionState.Reconnecting => TimeSpan.FromSeconds(1),
                    UiConnectionState.Blocked or UiConnectionState.Error => TimeSpan.FromSeconds(2),
                    _ => TimeSpan.FromSeconds(4),
                };
                await Task.Delay(cadence, _lifetime.Token).ConfigureAwait(false);
                if (_state.IsBusy) continue;
                observedPresentation = _state.Presentation;
                var status = await _coordinator.GetStatusAsync(_lifetime.Token).ConfigureAwait(false);
                var presentation = UiPresentationReducer.FromServiceStatus(status);
                var telemetry = _tunnelTelemetry.Capture(presentation.IsProtected);
                _dispatcher.Post(() =>
                {
                    if (Volatile.Read(ref _disposed) != 0 || _state.IsBusy ||
                        !ReferenceEquals(_state.Presentation, observedPresentation)) return;
                    if (_coordinator.IsLocalEvaluation)
                    {
                        var recoverableBlocked = string.Equals(status.State, "blocked", StringComparison.OrdinalIgnoreCase);
                        SetServiceReady(status.Ok || recoverableBlocked);
                    }
                    var keepRecentOperationError = _lastOperationErrorAt is { } at &&
                        DateTimeOffset.UtcNow - at < TimeSpan.FromSeconds(12) &&
                        _state.Presentation.State == UiConnectionState.Error &&
                        presentation.State == UiConnectionState.Idle;
                    ApplyRuntimeSnapshot(status, presentation, telemetry, preservePresentation: keepRecentOperationError);
                    // The service owns recovery even while this window is closed.
                    // A competing UI disconnect/reconnect would cancel that intent.
                });
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { return; }
            catch (Exception error)
            {
                _dispatcher.Post(() => ApplyRuntimeReadFailure(observedPresentation, error));
            }
        }
    }

    private async Task TryAutomaticCandidateFailoverAsync()
    {
        if (Interlocked.Exchange(ref _automaticFailoverRunning, 1) != 0) return;
        try
        {
            if (!CanAutomaticallyRecoverConnection() ||
                _state.Presentation.State != UiConnectionState.Blocked || _state.IsBusy)
                return;
            await ConnectCoreAsync(automaticRecovery: true);
            if (_state.Presentation.IsProtected)
            {
                _automaticFailoverSuppressedSource = null;
                _automaticFailoverSuppressedVersion = 0;
            }
            else
            {
                // ConnectAsync has measured and attempted every usable
                // candidate in this source. Keep the fail-closed result until
                // the user retries, the signed config changes, or the network
                // changes; never spin an infinite reconnect loop.
                _automaticFailoverSuppressedSource = _state.Source;
                _automaticFailoverSuppressedVersion = _coordinator.LastConfigVersion;
            }
        }
        finally { Volatile.Write(ref _automaticFailoverRunning, 0); }
    }

    private bool CanAutomaticallyRecoverConnection() =>
        _state.CandidateMode == "auto" &&
        (!IsSmartGateMode || HasSelectedSmartGateNode) &&
        _state.Mode is ProtocolCodes.ModeSmart or ProtocolCodes.ModeGlobal or ProtocolCodes.ModePerApp or ProtocolCodes.ModeSmartGate;

    private static bool IsHostCutoverFailure(Exception error) =>
        IsHostCutoverFailure(error is ServiceException serviceError ? serviceError.Code : UiErrorMapper.ExtractCode(error));

    private static bool IsHostCutoverFailure(string? code) => code is
        "BF-TUN-ESTABLISH" or
        "BF-CONNECTION-TEARDOWN" or
        "BF-NETWORK-BOUNDARY" or
        "BF-TUN-NOT-READY" or
        "BF-TUN-CONFIGURE" or
        "BF-TUN-ALREADY-OPEN" or
        "BF-TUN-COEXIST-CUTOVER-UNSAFE" or
        "BF-TRANSPORT-UPSTREAM-OWNER";

    private void EnsureConfigRefreshLoopStarted()
    {
        if (_configRefreshTask is null && _coordinator.IsEnrolled)
            _configRefreshTask = PollControlConfigAsync();
    }

    private void NotifyNodeConfigurationUpdated(long before, long after, string? previousFingerprint, string? currentFingerprint)
    {
        if (!NodeConfigurationNotifications.ShouldNotify(before, after, _lastNotifiedNodeVersion, previousFingerprint, currentFingerprint)) return;
        _lastNotifiedNodeVersion = after;
        NodeConfigurationUpdated?.Invoke(after);
    }

    private async Task PollControlConfigAsync()
    {
        var cadence = _coordinator.IsLocalEvaluation ? TimeSpan.FromSeconds(5) : TimeSpan.FromSeconds(30);
        while (!_lifetime.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(cadence, _lifetime.Token).ConfigureAwait(false);
                if (!_coordinator.IsEnrolled || _state.IsBusy) continue;

                var before = _coordinator.LastConfigVersion;
            var previousNodeFingerprint = _coordinator.NodeConfigurationFingerprint;
                var result = await _coordinator.RefreshAsync(_lifetime.Token).ConfigureAwait(false);
                var after = _coordinator.LastConfigVersion;
                if (!result.Ok || after <= before) continue;

                var options = _coordinator.GetUiConfigOptions();
                var currentNodeFingerprint = _coordinator.NodeConfigurationFingerprint;
                _dispatcher.Post(() =>
                {
                    if (Volatile.Read(ref _disposed) != 0) return;
                    ApplyOptions(options);
                    Update(_state with
                    {
                        IsEnrolled = true,
                        UpdateText = $"配置已自动同步：v{after}",
                        ConfigText = $"配置：签名有效 v{after}"
                    });
                    NotifyNodeConfigurationUpdated(before, after, previousNodeFingerprint, currentNodeFingerprint);
                    if (_probeLifecycleStarted)
                    {
                        MarkCandidateProbePending(Source, clearExisting: true);
                        _probeLifecycle.ConfigurationRefreshed(Source, after);
                        if (!_state.IsProtected) _probeLifecycle.TriggerManual();
                    }
                });
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { return; }
            catch
            {
                // Background refresh is deliberately quiet. A transient control-plane
                // failure must not overwrite a working LKG UI or interrupt the tunnel;
                // explicit Refresh/Connect continues to surface actionable errors.
            }
        }
    }

    private void AppendLiveEvent(ServiceStatus status, UiPresentationState presentation)
    {
        var route = presentation.IsProtected ? $"{SelectedSourceDisplay} · {EffectiveCandidateLabel}" : SelectedSourceDisplay;
        // Only retain bounded diagnostic codes, never arbitrary server text
        // which could contain an endpoint, credential or local file path.
        var diagnostic = status.Message is { Length: > 0 and <= 160 } message &&
            message.StartsWith("BF-", StringComparison.Ordinal) &&
            message.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '+')
            ? message : null;
        var signature = $"{status.State}|{status.Code}|{diagnostic}|{status.Source}|{status.Core}|{route}";
        if (string.Equals(signature, _lastLiveEventSignature, StringComparison.Ordinal)) return;
        _lastLiveEventSignature = signature;
        var eventName = presentation.State switch
        {
            UiConnectionState.Protected => "隧道已建立",
            UiConnectionState.Preparing => "正在连接",
            UiConnectionState.Blocked => "安全边界阻断",
            UiConnectionState.Error => "服务异常",
            _ => "隧道未连接",
        };
        var detail = status.Code is { Length: > 0 } ? status.Code : presentation.StatusText;
        if (diagnostic is not null) detail += $" · {diagnostic}";
        LiveEvents.Insert(0, new UiLiveEvent(DateTime.Now.ToString("HH:mm:ss"), eventName, route, detail));
        while (LiveEvents.Count > 4) LiveEvents.RemoveAt(LiveEvents.Count - 1);
    }
    private void OnNetworkProbeInvalidated()
    {
        _automaticFailoverSuppressedSource = null;
        _automaticFailoverSuppressedVersion = 0;
        if (_probeLifecycleStarted && _coordinator.IsEnrolled)
            _probeLifecycle.NetworkInvalidated(_coordinator.LastConfigVersion);
    }
    private void SetSource(string value)
    {
        value ??= "";
        if (string.Equals(_state.Source, value, StringComparison.Ordinal)) return;
        _autoCandidateLabel = "";
        _automaticFailoverSuppressedSource = null;
        _automaticFailoverSuppressedVersion = 0;
        var candidates = Options.CandidatesBySource is not null && Options.CandidatesBySource.TryGetValue(value, out var sourceCandidates)
            ? sourceCandidates
            : Array.Empty<UiOption>();
        var candidateLabel = _state.CandidateMode == "manual" && ContainsOption(candidates, _state.CandidateLabel)
            ? _state.CandidateLabel
            : "";
        if (Update(_state with { Source = value, CandidateLabel = candidateLabel }, persist: true))
        {
            if (_probeLifecycleStarted)
            {
                MarkCandidateProbePending(value);
                _probeLifecycle.SourceChanged(value, _coordinator.LastConfigVersion);
            }
        }
    }

    private void PublishProbeOutcome(ProbeLifecycleOutcome outcome)
    {
        _dispatcher.Post(() =>
        {
            if (!string.Equals(outcome.Source, Source, StringComparison.OrdinalIgnoreCase)) return;
            if (outcome.IsPartial)
            {
                var merged = _candidateProbesBySource.TryGetValue(outcome.Source, out var existing) && existing is Dictionary<string, CandidateProbeStatus> mutable
                    ? mutable
                    : new Dictionary<string, CandidateProbeStatus>(StringComparer.OrdinalIgnoreCase);
                foreach (var candidate in outcome.Candidates ?? Array.Empty<CandidateProbeStatus>())
                    if (!string.IsNullOrWhiteSpace(candidate.Code)) merged[candidate.Code] = candidate;
                _candidateProbesBySource[outcome.Source] = merged;
                _candidateProbeProgressBySource[outcome.Source] = (Math.Max(0, outcome.Completed), Math.Max(0, outcome.Total));
                _pendingCandidateProbeSources.Add(outcome.Source);
                _candidateProbeUiRevision++;
                var now = Environment.TickCount64;
                if (outcome.Completed > 1 && outcome.Completed < outcome.Total && now - _lastProbeUiPaintTick < 100) return;
                _lastProbeUiPaintTick = now;
                Update(_state with
                {
                    UpdateText = outcome.Total > 0
                        ? $"线路测速中：{outcome.Completed}/{outcome.Total}"
                        : "线路测速中"
                });
                return;
            }
            _pendingCandidateProbeSources.Remove(outcome.Source);
            _candidateProbeProgressBySource.Remove(outcome.Source);
            if (_candidateProbeStartedBySource.Remove(outcome.Source, out var started))
                _candidateProbeDurationBySource[outcome.Source] = DateTimeOffset.UtcNow - started;
            var finalCandidates = (outcome.Candidates ?? Array.Empty<CandidateProbeStatus>())
                .Where(candidate => !string.IsNullOrWhiteSpace(candidate.Code)).ToArray();
            // A batch may fail after several streamed rows have already been
            // measured. Keep those completed, truthful measurements visible
            // instead of erasing them just because the final frame failed.
            if (finalCandidates.Length > 0)
                _candidateProbesBySource[outcome.Source] = finalCandidates
                    .GroupBy(candidate => candidate.Code, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(group => group.Key, group => group.Last(), StringComparer.OrdinalIgnoreCase);
            else if (!_candidateProbesBySource.ContainsKey(outcome.Source))
                // A terminal batch error with no streamed rows is still a
                // completed round. Keep an empty result map so every listed
                // route renders as failed instead of falling back to the
                // misleading pre-run "waiting for test" state.
                _candidateProbesBySource[outcome.Source] = new Dictionary<string, CandidateProbeStatus>(StringComparer.OrdinalIgnoreCase);
            _autoCandidateLabel = outcome.Success ? outcome.SelectedCandidateLabel ?? "" : "";
            if (!outcome.Success && !string.IsNullOrWhiteSpace(outcome.ErrorCode))
                RecordStableProbeFailure(outcome.ErrorCode);
            Update(_state with
            {
                UpdateText = outcome.Success
                    ? $"节点探测完成：{EffectiveCandidateLabel}"
                    : outcome.ErrorCode switch
                    {
                        "BF-IPC-JSON" => "线路测速失败：后台服务版本与当前客户端不兼容，请更新或重启 Bifrost 服务",
                        "BF-IPC-IO" => "线路测速失败：无法连接 Bifrost 后台服务",
                        "BF-IPC-TIMEOUT" => "线路测速失败：后台服务响应超时",
                        "BF-IPC-IDENTITY" => "线路测速失败：后台服务拒绝了客户端身份（BF-IPC-IDENTITY）",
                        _ => $"线路测速失败：{outcome.ErrorCode ?? "BF-PROBE-FAILED"}"
                    }
            });
        });
    }

    private static void RecordStableProbeFailure(string? errorCode)
    {
        try
        {
            var code = errorCode?.Trim() ?? string.Empty;
            if (code.Length is < 4 or > 96 || !code.StartsWith("BF-", StringComparison.Ordinal) ||
                code.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch == '-')))
                code = "BF-PROBE-FAILED";
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost");
            Directory.CreateDirectory(directory);
            var record = JsonSerializer.Serialize(new
            {
                schema = "BIFROST-CLIENT-PROBE-DIAGNOSTIC-1",
                code,
                timestamp = DateTimeOffset.UtcNow.ToString("O")
            });
            File.WriteAllText(Path.Combine(directory, "last-probe-error.json"), record + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { }
    }

    private void MarkCandidateProbePending(string source, bool clearExisting = false)
    {
        if (string.IsNullOrWhiteSpace(source)) return;
        if (clearExisting)
        {
            _candidateProbesBySource.Remove(source);
            _candidateProbeDurationBySource.Remove(source);
        }
        var total = Options.CandidatesBySource is not null && Options.CandidatesBySource.TryGetValue(source, out var candidates)
            ? candidates.Count
            : 0;
        _candidateProbeProgressBySource[source] = (0, total);
        _candidateProbeStartedBySource[source] = DateTimeOffset.UtcNow;
        _pendingCandidateProbeSources.Add(source);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateRoutes)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeSummaryText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsCandidateProbeRunning)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanRefreshCandidateProbes)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeProgressPercent)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeActionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeAutomationName)));
    }

    private string CandidateProbeDurationText(string source)
    {
        if (!_candidateProbeDurationBySource.TryGetValue(source, out var duration)) return string.Empty;
        return duration.TotalSeconds < 10
            ? $" · 用时 {duration.TotalSeconds:0.0} 秒"
            : $" · 用时 {Math.Round(duration.TotalSeconds):0} 秒";
    }

    private void ApplyOptions(UiConfigOptions options)
    {
        if (!_dispatcher.CheckAccess)
        {
            _dispatcher.Post(() => ApplyOptions(options));
            return;
        }
        Options = options;
        var next = _state;
        // A verified config with usable sources should never leave the client
        // in an unselectable state. Pick the first signed source as a safe
        // deterministic default instead of presenting an enabled Connect
        // button that can only fail with BF-SOURCE-SELECTION-REQUIRED.
        if (options.Sources.Count > 0 && !ContainsOption(options.Sources, _state.Source))
            next = next with { Source = options.Sources[0].Code };
        if (next.Mode == ProtocolCodes.ModeSmartGate)
        {
            if (!ContainsOption(options.Countries, next.Country)) next = next with { Country = "" };
        }
        else if (!string.Equals(next.Country, "default", StringComparison.Ordinal) || next.FrontSource != "auto")
            next = next with { Country = "default", FrontSource = "auto" };

        // SmartGate is customer-directed: a published node must be selected
        // explicitly.  Refreshes may preserve a still-valid selection, but
        // they never silently choose the first country/egress on the user's
        // behalf or fall back to a direct/default profile.
        if (options.FrontSources.Count > 0 && !ContainsOption(options.FrontSources, _state.FrontSource)) next = next with { FrontSource = "" };
        var candidateOptions = options.CandidatesBySource is not null && options.CandidatesBySource.TryGetValue(next.Source, out var selectedCandidates)
            ? selectedCandidates
            : Array.Empty<UiOption>();
        if (!string.IsNullOrWhiteSpace(_autoCandidateLabel) && !ContainsOption(candidateOptions, _autoCandidateLabel))
            _autoCandidateLabel = "";
        if (next.CandidateMode == "manual" && !ContainsOption(candidateOptions, next.CandidateLabel))
            next = next with { CandidateMode = "auto", CandidateLabel = "" };
        if (!ReferenceEquals(next, _state)) Update(next, persist: true);
        else NotifyOptionsChanged();
    }

    private static bool ContainsOption(IReadOnlyList<UiOption> options, string value) =>
        !string.IsNullOrWhiteSpace(value) && options.Any(option => string.Equals(option.Code, value, StringComparison.OrdinalIgnoreCase));

    private void NotifyOptionsChanged()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Options)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SourceOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(FrontSourceOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CountryOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SourceRouteGroups)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateRoutes)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateDetailTitle)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeSummaryText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsCandidateProbeRunning)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanRefreshCandidateProbes)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeProgressPercent)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeActionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateProbeAutomationName)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasCountryOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(NoCountryOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasCandidateOptions)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasSelectedSmartGateNode)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanUseSmartGateAction)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateNodeSummary)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateNodeAvailabilityText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateStatus)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateActionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateManualStatus)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateManualActionLabel)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SmartGateManualFailoverStatus)));
    }

    private bool TryBeginBusy() { if (_state.IsBusy) return false; Update(_state with { IsBusy = true }, persist: false); return true; }
    private void EndBusy() => Update(_state with { IsBusy = false }, persist: false);
    private bool Update(UiShellState next, bool persist = false, [CallerMemberName] string? _ = null)
    {
        if (!_dispatcher.CheckAccess)
        {
            _dispatcher.Post(() => Update(next, persist));
            return false;
        }
        var previous = _state;
        _state = next;
        if (persist && !Persist(previous)) return false;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(State)));
        return true;
    }

    private bool Persist(UiShellState previous)
    {
        try
        {
            _persistence.Save(_state);
            return true;
        }
        catch
        {
            _state = previous with { UpdateText = "界面设置未保存：安全存储不可用" };
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(State)));
            return false;
        }
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _coordinator.NetworkProbeInvalidated -= OnNetworkProbeInvalidated;
        _probeLifecycle.Dispose();
        _tunnelTelemetry.Dispose();
        _lifetime.Cancel(); _lifetime.Dispose(); _coordinator.Dispose();
    }

    private static string[] SplitApplications(string value)
    {
        if (string.IsNullOrEmpty(value)) return Array.Empty<string>();
        var normalized = value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var parts = normalized.Split(new[] { ',', ';', '\n' }, StringSplitOptions.None);
        if (parts.Any(string.IsNullOrWhiteSpace)) throw new InvalidDataException("BF-APP-ID");
        return parts.Select(part => part.Trim()).ToArray();
    }

    private static UiShellState NormalizePersistedApplicationPolicy(UiShellState state)
    {
        var appPolicyEnabled = state.AppPolicyEnabled;
        var clearInvalidPolicy = false;
        if (appPolicyEnabled)
        {
            try
            {
                var include = SplitApplications(state.IncludeApps);
                var exclude = SplitApplications(state.ExcludeApps);
                var valid = state.AppPolicy == "allow"
                    ? include.Length > 0 && exclude.Length == 0
                    : state.AppPolicy == "exclude" && exclude.Length > 0 && include.Length == 0;
                if (!valid) { appPolicyEnabled = false; clearInvalidPolicy = true; }
            }
            catch { appPolicyEnabled = false; clearInvalidPolicy = true; }
        }

        // connection_type/route_mode are derived authority, not independent
        // user choices.  Historical protected UI records could contain empty
        // strings for these newly-added fields while still carrying a valid
        // presentation mode.  Reconstruct the exact typed pair on every load
        // and persist the repaired state before Connect can parse it.
        var typed = ConnectionRouteSelection.FromPresentation(state.Mode, appPolicyEnabled);
        var normalized = state with
        {
            AppPolicyEnabled = appPolicyEnabled,
            ConnectionType = typed.ConnectionTypeCode,
            RouteMode = typed.RouteModeCode,
            Country = typed.ConnectionType == global::Bifrost.ConnectionType.SmartGate && state.Country is not ("default" or "auto") ? state.Country : typed.ConnectionType == global::Bifrost.ConnectionType.SmartGate ? "" : "default",
            FrontSource = typed.ConnectionType == global::Bifrost.ConnectionType.SmartGate ? state.FrontSource : "auto",
        };
        return clearInvalidPolicy
            ? normalized with { IncludeApps = "", ExcludeApps = "" }
            : normalized;
    }

    private static UiShellState LoadInitialState(IUiShellPersistence persistence)
    {
        try { return persistence.Load(); }
        catch { return new UiShellState(UpdateText: "界面设置未读取：安全存储不可用"); }
    }
}

public sealed class AsyncCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private int _running;
    public AsyncCommand(Func<object?, Task> execute) => _execute = execute;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => Volatile.Read(ref _running) == 0;
    public async void Execute(object? parameter)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) return;
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        try { await _execute(parameter); } finally { Volatile.Write(ref _running, 0); CanExecuteChanged?.Invoke(this, EventArgs.Empty); }
    }
}

public sealed class AsyncResultCommand<TRequest, TResult> : ICommand
{
    private readonly Func<TRequest, Task<TResult>> _execute;
    private int _running;
    public AsyncResultCommand(Func<TRequest, Task<TResult>> execute) => _execute = execute;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => parameter is TRequest && Volatile.Read(ref _running) == 0;
    public Task<TResult?> ExecuteAsync(TRequest request)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) return Task.FromResult<TResult?>(default);
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        return ExecuteCoreAsync(request);
    }
    private async Task<TResult?> ExecuteCoreAsync(TRequest request)
    {
        try { return await _execute(request).ConfigureAwait(true); }
        finally { Volatile.Write(ref _running, 0); CanExecuteChanged?.Invoke(this, EventArgs.Empty); }
    }
    public async void Execute(object? parameter)
    {
        if (parameter is TRequest request) await ExecuteAsync(request);
    }
}
