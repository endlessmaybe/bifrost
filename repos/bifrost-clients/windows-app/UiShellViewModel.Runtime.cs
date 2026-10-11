using System.ComponentModel;
using System.Collections.Immutable;
using Bifrost.ClientService;

namespace Bifrost;

/// <summary>
/// Applies background readback without invalidating persisted settings,
/// navigation, artwork, application rules or signed route collections.
/// Connection authority still comes exclusively from UiPresentationReducer.
/// </summary>
public sealed partial class UiShellViewModel
{
    private sealed record RuntimeBinding(string Name, Func<UiShellViewModel, object?> Read);

    // Explicit dependencies keep this high-frequency path separate from the
    // broad notifications used for user choices and configuration replacement.
    private static readonly RuntimeBinding[] RuntimeBindings =
    [
        new(nameof(StatusText), vm => vm.StatusText),
        new(nameof(DashboardStatusTitle), vm => vm.DashboardStatusTitle),
        new(nameof(DashboardStatusDetail), vm => vm.DashboardStatusDetail),
        new(nameof(DashboardProtectionDetail), vm => vm.DashboardProtectionDetail),
        new(nameof(DashboardModeHint), vm => vm.DashboardModeHint),
        new(nameof(IsProtected), vm => vm.IsProtected),
        new(nameof(IsTestState), vm => vm.IsTestState),
        new(nameof(PrimaryActionLabel), vm => vm.PrimaryActionLabel),
        new(nameof(CanEditConnectionSettings), vm => vm.CanEditConnectionSettings),
        new(nameof(CanUsePrimaryAction), vm => vm.CanUsePrimaryAction),
        new(nameof(CanConnect), vm => vm.CanConnect),
        new(nameof(CanUseSmartGateAction), vm => vm.CanUseSmartGateAction),
        new(nameof(StateIcon), vm => vm.StateIcon),
        new(nameof(SourceSummary), vm => vm.SourceSummary),
        new(nameof(RouteSummary), vm => vm.RouteSummary),
        new(nameof(CoreSummary), vm => vm.CoreSummary),
        new(nameof(DownloadMetric), vm => vm.DownloadMetric),
        new(nameof(UploadMetric), vm => vm.UploadMetric),
        new(nameof(SessionMetric), vm => vm.SessionMetric),
        new(nameof(DurationMetric), vm => vm.DurationMetric),
        new(nameof(LatencyMetric), vm => vm.LatencyMetric),
        new(nameof(PacketLossMetric), vm => vm.PacketLossMetric),
        new(nameof(SessionSummary), vm => vm.SessionSummary),
        new(nameof(TelemetryAvailabilityText), vm => vm.TelemetryAvailabilityText),
        new(nameof(HasSamples), vm => vm.HasSamples),
        new(nameof(NoSamples), vm => vm.NoSamples),
        new(nameof(LiveUploadSamples), vm => vm.LiveUploadSamples),
        new(nameof(LiveDownloadSamples), vm => vm.LiveDownloadSamples),
        new(nameof(NetworkQualityStatus), vm => vm.NetworkQualityStatus),
        new(nameof(ConnectionStateDetail), vm => vm.ConnectionStateDetail),
        new(nameof(NetworkProtectionStatus), vm => vm.NetworkProtectionStatus),
        new(nameof(SmartGateStatus), vm => vm.SmartGateStatus),
        new(nameof(SmartGateActionLabel), vm => vm.SmartGateActionLabel),
        new(nameof(SmartGateManualStatus), vm => vm.SmartGateManualStatus),
        new(nameof(SmartGateManualActionLabel), vm => vm.SmartGateManualActionLabel),
        new(nameof(SmartGateManualFailoverStatus), vm => vm.SmartGateManualFailoverStatus),
        new(nameof(EffectiveCandidateLabel), vm => vm.EffectiveCandidateLabel),
        new(nameof(CandidateProbeSummaryText), vm => vm.CandidateProbeSummaryText),
        new(nameof(IsCandidateProbeRunning), vm => vm.IsCandidateProbeRunning),
        new(nameof(CanRefreshCandidateProbes), vm => vm.CanRefreshCandidateProbes),
        new(nameof(CandidateProbeProgressPercent), vm => vm.CandidateProbeProgressPercent),
        new(nameof(CandidateProbeActionLabel), vm => vm.CandidateProbeActionLabel),
        new(nameof(CandidateProbeAutomationName), vm => vm.CandidateProbeAutomationName),
    ];

    private static readonly RuntimeBinding[] TelemetryBindings = RuntimeBindings.Where(binding => binding.Name is
        nameof(DownloadMetric) or nameof(UploadMetric) or nameof(SessionMetric) or nameof(DurationMetric) or
        nameof(SessionSummary) or nameof(TelemetryAvailabilityText) or nameof(HasSamples) or nameof(NoSamples) or
        nameof(LiveUploadSamples) or nameof(LiveDownloadSamples)).ToArray();

    private bool _runtimeReadUnavailable;

    internal void ApplyRuntimeReadFailure(UiPresentationState? observed, Exception error)
    {
        if (Volatile.Read(ref _disposed) != 0 || _state.IsBusy || observed is null ||
            !ReferenceEquals(_state.Presentation, observed)) return;
        if (!_runtimeReadUnavailable) UiLifecycleTrace.Write("service-status-unavailable", error);
        _runtimeReadUnavailable = true;
        var mayHaveLiveConnection = observed.State is UiConnectionState.Protected or
            UiConnectionState.Preparing or UiConnectionState.Reconnecting;
        const string message = "本机连接状态暂不可读，正在重新确认";
        var next = mayHaveLiveConnection
            ? new UiPresentationState(UiConnectionState.Reconnecting, message, observed.Source,
                observed.Route, observed.Country, observed.Core, "—", "—", observed.SessionTraffic,
                observed.Duration, ImmutableArray<double>.Empty)
            : UiPresentationState.Error(message);
        // A pipe failure is neither proof that the tunnel stopped nor proof
        // that it is protected. Keep polling; do not submit a new connection.
        Update(_state with { Presentation = next, StatusText = message });
    }

    internal void ApplyRuntimeSnapshot(ServiceStatus status, UiPresentationState presentation, UiTunnelTelemetry telemetry, bool preservePresentation = false)
    {
        if (!_dispatcher.CheckAccess)
        {
            _dispatcher.Post(() => ApplyRuntimeSnapshot(status, presentation, telemetry, preservePresentation));
            return;
        }
        if (Volatile.Read(ref _disposed) != 0) return;
        if (_runtimeReadUnavailable) UiLifecycleTrace.Write("service-status-restored");
        _runtimeReadUnavailable = false;
        var previous = _state.Presentation;
        var presentationChanged = !preservePresentation && (!SamePresentation(previous, presentation) || _state.StatusText != presentation.StatusText);
        var candidatesChanged = HasMihomoReadbackChanges(status);
        var bindings = presentationChanged || candidatesChanged ? RuntimeBindings : TelemetryBindings;
        var values = presentationChanged || candidatesChanged || _telemetry != telemetry
            ? bindings.Select(binding => binding.Read(this)).ToArray()
            : null;
        var previousLiveText = LiveStatusText;

        if (candidatesChanged) ApplyMihomoReadback(status);
        _telemetry = telemetry;
        _lastStatusUpdated = DateTimeOffset.Now;
        AppendLiveEvent(status, presentation);
        if (presentationChanged) _state = _state with { Presentation = presentation, StatusText = presentation.StatusText };

        if (values is not null)
            for (var i = 0; i < bindings.Length; i++)
                if (!Equals(values[i], bindings[i].Read(this)))
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(bindings[i].Name));
        if (candidatesChanged) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CandidateRoutes)));
        if (previousLiveText != LiveStatusText) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(LiveStatusText)));
        if (presentationChanged)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Presentation)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(State)));
        }
    }

    private bool HasMihomoReadbackChanges(ServiceStatus status)
    {
        if (status.Mihomo is not { } mihomo || string.IsNullOrWhiteSpace(status.Source))
            return !status.Connected && _state.CandidateMode == "auto" && _autoCandidateLabel.Length != 0;
        if (_autoCandidateLabel != mihomo.ActiveCandidate || _pendingCandidateProbeSources.Contains(status.Source) ||
            !_candidateProbesBySource.TryGetValue(status.Source, out var probes) || probes.Count != mihomo.Candidates.Count)
            return true;
        return mihomo.Candidates.Any(candidate => !probes.TryGetValue(candidate.Name, out var probe) ||
            probe.Success != (candidate.Alive && candidate.DelayMs is > 0) || probe.RttMs != candidate.DelayMs);
    }

    private static bool SamePresentation(UiPresentationState left, UiPresentationState right) =>
        left.State == right.State && left.StatusText == right.StatusText && left.Source == right.Source &&
        left.Route == right.Route && left.Country == right.Country && left.Core == right.Core &&
        left.IsTestState == right.IsTestState && left.Download == right.Download && left.Upload == right.Upload &&
        left.SessionTraffic == right.SessionTraffic && left.Duration == right.Duration &&
        left.Samples.Equals(right.Samples) && left.UploadSamples.Equals(right.UploadSamples);
}
