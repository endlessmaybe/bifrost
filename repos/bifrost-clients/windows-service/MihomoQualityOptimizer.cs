using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal sealed record MihomoQualityLane(string Group, int Port, string Password);
internal sealed record MihomoQualityRuntime(MihomoCompiledPackage Package, int Port, string Password)
{
    internal IReadOnlyList<MihomoQualityLane> StartupLanes { get; init; } = [];
}

/// <summary>
/// Private quality optimizer. Native Mihomo URLTest owns startup and hard
/// failure recovery; confirmed body-throughput winners own subsequent new
/// flows until health recovery clears the short-lived manual selection.
/// </summary>
internal sealed class MihomoQualityOptimizer : IDisposable
{
    internal const string ProbeGroup = "BIFROST-QUALITY";
    internal const int StartupLaneCount = 6;
    internal const int ProbeBytes = 128 * 1024;
    // 128/256 KiB is still inside TCP/WS/TLS ramp-up for some otherwise much
    // faster paths.  A-131 is the concrete regression: it loses to A-06 at
    // 128 KiB, is roughly tied at 256 KiB, then is ~2.5x faster by 1 MiB.
    // Pairwise winner decisions therefore need a body large enough to measure
    // steady transfer rather than handshake/slow-start shape.
    internal const int ComparisonBytes = 1 * 1024 * 1024;
    internal const int LongFormBytes = 5 * 1024 * 1024;
    private const int ProbeObjectBytes = 512 * 1024;
    private const int SustainedMaximumBytes = 2 * 1024 * 1024;
    internal static readonly TimeSpan StableSweepInterval = TimeSpan.FromHours(1);
    internal static readonly TimeSpan StableRecheckInterval = TimeSpan.FromMinutes(2);
    // Monitoring is only a drop detector, not a winner election. Keep it
    // lightweight even though full winner comparisons now use 1 MiB bodies.
    internal const int StableRecheckBytes = 256 * 1024;
    // A full sweep is deliberately exhaustive, but a single transient dip can
    // still make a genuinely fast node lose its one pairwise challenge. Keep
    // the strongest observed challengers and re-run the same repeated,
    // dual-target 5 MiB reliability gate used for live switch confirmation.
    // This prevents a short peak from bypassing long-flow reliability at the
    // very end of an otherwise exhaustive sweep.
    internal const int EndOfSweepFinalistCount = 4;
    // Startup rough screening must cross the observed A-131/A-06 crossover
    // instead of eliminating a slow-start winner on a 128 KiB prefix.
    internal const int StartupScreenBytes = ComparisonBytes;
    // Finalists must complete four 5 MiB transfers, alternating between two
    // independent public targets. A candidate that fails any required body is
    // not a startup winner even if one short transfer has a higher peak.
    internal const int StartupFinalBytes = LongFormBytes;
    internal const int StartupLongFormPasses = 4;
    internal const int RuntimeLongFormPasses = 4;
    // Startup samples a bounded spread of the catalogue and current network.
    // The lifetime optimizer continues through the remaining signed provider
    // after route cutover, so a large catalogue cannot block one connection.
    // Keep the startup candidate ceiling aligned with the controller's
    // verified-cohort contract. The screen itself has a separate time budget,
    // so a large source can no longer consume the entire qualification window
    // before the throughput finalists are measured.
    internal const int StartupCohortSize = 64;
    // Spend the heavier long-form budget only on a small finalist set.
    internal const int StartupFinalistCount = 5;
    internal const int StartupSecondPassCount = StartupFinalistCount;
    // A remembered winner is useful as an incumbent, not as permanent proof
    // of capacity. Edge congestion can change within minutes, so reconnects
    // run a smaller qualification against the head of the signed ranking
    // instead of blindly reusing a merely reachable candidate for 15 minutes.
    // A remembered winner is only the incumbent. Reconnects still need enough
    // breadth to discover a much faster path instead of blindly comparing the
    // first handful of provider entries.
    internal const int StartupReuseCohortSize = 39;
    internal const int StartupReuseFinalistCount = 3;
    internal const int StartupReuseSecondPassCount = StartupReuseFinalistCount;
    internal const double StartupThroughputToleranceRatio = .03;
    internal static readonly TimeSpan StartupQualificationTimeout = TimeSpan.FromSeconds(240);
    internal static readonly TimeSpan StartupReuseQualificationTimeout = TimeSpan.FromSeconds(150);
    internal static readonly TimeSpan StartupScreenBudget = TimeSpan.FromSeconds(32);
    internal static readonly TimeSpan StartupReuseScreenBudget = TimeSpan.FromSeconds(18);
    internal static readonly TimeSpan StartupScreenCandidateBudget = TimeSpan.FromSeconds(6);
    internal static readonly TimeSpan StartupReuseScreenCandidateBudget = TimeSpan.FromMilliseconds(5500);
    internal static readonly TimeSpan StartupFinalBudget = StartupQualificationTimeout - StartupScreenBudget;
    internal static readonly TimeSpan StartupReuseFinalBudget = StartupReuseQualificationTimeout - StartupReuseScreenBudget;
    internal static readonly TimeSpan StartupFinalSampleBudget = TimeSpan.FromSeconds(24);
    internal static readonly TimeSpan StartupReuseFinalSampleBudget = TimeSpan.FromSeconds(20);
    // Independent public test files keep the final decision from depending on
    // one CDN or one route shape.
    internal const string ProbeUrl = "https://cachefly.cachefly.net/10mb.test";
    internal const string SustainedProbeUrl = "https://proof.ovh.net/files/10Mb.dat";
    internal static string LongFormProbeUrl(int pass) => pass % 2 == 0 ? ProbeUrl : SustainedProbeUrl;
    private readonly CancellationTokenSource _stop = new();
    private readonly NodeQualityRecoveryGate _trafficGate = new();
    private readonly NodeQualityProbeBudget _probeBudget = new();
    private string _network = "";
    private readonly MihomoControllerClient _controller;
    private readonly MihomoQualityRuntime _runtime;
    private readonly Task _worker;
    private readonly string _underlayInterface;
    private System.Net.NetworkInformation.NetworkInterface? _trafficAdapter;
    private readonly Action<string> _trace;
    private readonly Action<string>? _confirmedWinner;
    private string _exploration = "";
    private enum RoundStep { Continue, Completed, Retry }
    private string? _confirmedCandidate;
    private double _confirmedBytesPerSecond;
    private readonly Dictionary<string, double> _roundObservedRates = new(StringComparer.OrdinalIgnoreCase);

    internal static MihomoQualityRuntime Prepare(MihomoCompiledPackage package)
    {
        // Called only after signed package validation; this local-only addition
        // uses exactly its allowed provider and preserves all user routing rules.
        if (!package.ActiveGroup.StartsWith("BIFROST-SMART-", StringComparison.Ordinal) &&
            !package.ActiveGroup.StartsWith("BIFROST-SMARTGATE-", StringComparison.Ordinal)) return new(package, 0, "");
        var main = JsonNode.Parse(package.MainConfig)!.AsObject();
        if (main["listeners"] is not null) throw new InvalidDataException("BF-QUALITY-CONFIG");
        var lanes = new List<MihomoQualityLane>(StartupLaneCount);
        var listeners = new JsonArray();
        for (var index = 0; index < StartupLaneCount; index++)
        {
            var group = index == 0 ? ProbeGroup : $"{ProbeGroup}-{index + 1}";
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            lanes.Add(new(group, port, password));
            main["proxy-groups"]!.AsArray().Add(new JsonObject { ["name"] = group, ["type"] = "select", ["use"] = new JsonArray(package.ProviderName), ["empty-fallback"] = "REJECT" });
            listeners.Add(new JsonObject {
                ["name"] = $"bifrost-quality-{index + 1}", ["type"] = "mixed", ["listen"] = "127.0.0.1", ["port"] = port,
                ["proxy"] = group, ["udp"] = false,
                ["users"] = new JsonArray(new JsonObject { ["username"] = "quality", ["password"] = password })
            });
        }
        main["listeners"] = listeners;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(main);
        var digest = Convert.ToHexString(SHA256.HashData(bytes.Concat(package.Provider).ToArray())).ToLowerInvariant();
        return new(package with { MainConfig = bytes, Digest = digest }, lanes[0].Port, lanes[0].Password)
        { StartupLanes = lanes };
    }

    internal MihomoQualityOptimizer(MihomoQualityRuntime runtime, Uri controller, string secret,
        Action<string>? trace = null, Action<string>? confirmedWinner = null)
    {
        _runtime = runtime;
        _underlayInterface = JsonNode.Parse(runtime.Package.MainConfig)?["interface-name"]?.GetValue<string>() ?? "";
        _trace = trace ?? (_ => { });
        _confirmedWinner = confirmedWinner;
        _controller = new MihomoControllerClient(controller, secret, TimeSpan.FromSeconds(30));
        _worker = Task.Run(RunAsync);
    }

    /// <summary>
    /// Refines Mihomo's first low-latency URLTest winner with real aggregate
    /// payload throughput before the TUN becomes the host's default route.
    /// This closes the old race where the background optimizer immediately
    /// yielded to a user's first download and the low-RTT/low-bandwidth node
    /// could remain selected for the whole transfer.
    /// </summary>
    internal static async Task<MihomoGroupState> QualifyStartupAsync(
        MihomoQualityRuntime runtime,
        MihomoControllerClient controller,
        MihomoGroupState initialGroup,
        Action<string>? trace,
        CancellationToken cancellationToken,
        Action<string>? confirmedWinner = null,
        bool compactReconnect = false)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(controller);
        ArgumentNullException.ThrowIfNull(initialGroup);
        trace ??= _ => { };
        if (runtime.Port <= 0 || !runtime.Package.AllowedCandidates.Contains(initialGroup.Now)) return initialGroup;

        var package = runtime.Package;
        // The signed catalogue is a membership list, not a speed ranking.
        // Mix its spread with current-network latency results, then let real
        // body downloads determine the finalists. The lifetime sweep covers
        // members that do not fit into this bounded startup window.
        var preferred = package.PreferredCandidates ?? Array.Empty<string>();
        var cohortSize = compactReconnect ? StartupReuseCohortSize : StartupCohortSize;
        var finalistCount = compactReconnect ? StartupReuseFinalistCount : StartupFinalistCount;
        var secondPassCount = compactReconnect ? StartupReuseSecondPassCount : StartupSecondPassCount;
        var screenBudget = compactReconnect ? StartupReuseScreenBudget : StartupScreenBudget;
        var finalBudget = compactReconnect ? StartupReuseFinalBudget : StartupFinalBudget;
        var finalSampleBudget = compactReconnect ? StartupReuseFinalSampleBudget : StartupFinalSampleBudget;
        var localFallback = initialGroup.Candidates
            .Where(candidate => candidate.Alive && NodeQualityPolicy.IsUsableDelay(candidate.DelayMs))
            .OrderBy(candidate => candidate.DelayMs)
            .ThenBy(candidate => candidate.Name, StringComparer.Ordinal)
            .Select(candidate => candidate.Name)
            .ToArray();
        var cohort = StartupScreenOrder(initialGroup.Now, preferred, localFallback,
            package.AllowedCandidates, cohortSize);
        if (cohort.Length <= 1) return initialGroup;

        var startupPolicy = new NodeQualityPolicy();
        var finalSamples = new Dictionary<string, List<NodeQualitySample>>(StringComparer.OrdinalIgnoreCase);
        var healthy = new Dictionary<string, MihomoProxyHealth>(StringComparer.OrdinalIgnoreCase);
        string[] startupFinalists = [];
        CancellationTokenSource? qualificationDeadline = null;
        try
        {
            // A payload transfer proves reachability as well as throughput.
            // A five-second health shortlist previously consumed the screen
            // budget and excluded every node outside its first eight entries.
            using var screenDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            screenDeadline.CancelAfter(screenBudget);
            healthy = initialGroup.Candidates
                .Where(candidate => package.AllowedCandidates.Contains(candidate.Name) &&
                    candidate.Alive && NodeQualityPolicy.IsUsableDelay(candidate.DelayMs))
                .ToDictionary(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase);
            if (!healthy.ContainsKey(initialGroup.Now))
                trace($"quality-startup-incumbent-unhealthy candidate={initialGroup.Now}");
            var startupSamples = new Dictionary<string, NodeQualitySample>(StringComparer.OrdinalIgnoreCase);
            var candidateBudget = compactReconnect ? StartupReuseScreenCandidateBudget : StartupScreenCandidateBudget;
            var lanes = runtime.StartupLanes.Count == 0
                ? [new MihomoQualityLane(ProbeGroup, runtime.Port, runtime.Password)]
                : runtime.StartupLanes.ToArray();
            async Task<List<(string Tag, NodeQualitySample Sample)>> ScreenLaneAsync(MihomoQualityLane lane, int laneIndex)
            {
                var results = new List<(string Tag, NodeQualitySample Sample)>();
                for (var index = laneIndex; index < cohort.Length; index += lanes.Length)
                {
                    var tag = cohort[index];
                    using var candidateDeadline = CancellationTokenSource.CreateLinkedTokenSource(screenDeadline.Token);
                    candidateDeadline.CancelAfter(candidateBudget);
                    try
                    {
                        await controller.SelectAsync(lane.Group, tag, candidateDeadline.Token).ConfigureAwait(false);
                        var sample = await MeasureAsync(lane.Port, lane.Password, candidateDeadline.Token,
                            StartupScreenBytes, index, adaptive: true, excludeWarmup: true).ConfigureAwait(false);
                        results.Add((tag, sample));
                        trace($"quality-startup-rough candidate={tag} ok={sample.Ok} bps={sample.BytesPerSecond:F0}");
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested &&
                        !screenDeadline.IsCancellationRequested && candidateDeadline.IsCancellationRequested)
                    { trace($"quality-startup-rough-time-slice candidate={tag} budget_ms={candidateBudget.TotalMilliseconds:F0}"); }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && screenDeadline.IsCancellationRequested)
                    { break; }
                    catch (Exception error) when (error is not OperationCanceledException)
                    { trace($"quality-startup-rough-failed candidate={tag} type={error.GetType().Name}"); }
                }
                return results;
            }
            var screened = await Task.WhenAll(lanes.Select(ScreenLaneAsync)).ConfigureAwait(false);
            foreach (var (tag, sample) in screened.SelectMany(result => result))
            {
                if (sample.Ok && !healthy.ContainsKey(tag) && NodeQualityPolicy.IsUsableDelay(sample.LatencyMs))
                    healthy[tag] = new MihomoProxyHealth(tag, true, (int)Math.Ceiling(sample.LatencyMs));
                startupSamples[tag] = sample with { LatencyMs = healthy.GetValueOrDefault(tag)?.DelayMs ?? sample.LatencyMs };
            }
            trace($"quality-startup-screen-complete measured={startupSamples.Count} eligible={cohort.Length} lanes={lanes.Length}");
            var incumbentRoughUsable = startupSamples.TryGetValue(initialGroup.Now, out var incumbentRough) && incumbentRough.Ok;
            if (!incumbentRoughUsable)
                trace($"quality-startup-incumbent-rough-unusable candidate={initialGroup.Now}");
            startupFinalists = startupSamples
                    .Where(pair => pair.Value.Ok)
                    .OrderByDescending(pair => pair.Value.BytesPerSecond)
                    .ThenBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair => pair.Key)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(finalistCount)
                .ToArray();
            if (startupFinalists.Length == 0) return initialGroup;

            qualificationDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            qualificationDeadline.CancelAfter(finalBudget);
            var token = qualificationDeadline.Token;

            // Rough screening may run on independent lanes for breadth, but
            // finalists are measured one candidate at a time. Each finalist
            // must complete repeated 5 MiB bodies against two independent
            // public targets. A single 1 MiB peak is no longer sufficient to
            // become the startup winner.
            var firstPass = new Dictionary<string, NodeQualitySample>(StringComparer.OrdinalIgnoreCase);
            async Task<(string Tag, NodeQualitySample Sample)> SampleFinalAsync(string tag, int pass)
            {
                var finalistIndex = Array.IndexOf(startupFinalists, tag);
                var lane = lanes[finalistIndex % lanes.Length];
                await controller.SelectAsync(lane.Group, tag, token).ConfigureAwait(false);
                var sample = await MeasureStartupFinalAsync(lane.Port, lane.Password, token,
                    finalSampleBudget, pass, 100 + pass * 100 + finalistIndex).ConfigureAwait(false);
                sample = sample with { LatencyMs = healthy.GetValueOrDefault(tag)?.DelayMs ?? sample.LatencyMs };
                return (tag, sample);
            }
            foreach (var tag in startupFinalists)
            {
                var measured = await SampleFinalAsync(tag, 0).ConfigureAwait(false);
                var sample = measured.Sample;
                firstPass[tag] = sample;
                RecordStartupFinal(startupPolicy, finalSamples, tag, sample);
                trace($"quality-startup-final candidate={tag} pass=1 ok={sample.Ok} bps={sample.BytesPerSecond:F0}");
            }

            var secondPass = firstPass
                .Where(pair => pair.Value.Ok && double.IsFinite(pair.Value.BytesPerSecond) && pair.Value.BytesPerSecond > 0)
                .OrderByDescending(pair => pair.Value.BytesPerSecond)
                .ThenBy(pair => pair.Key, StringComparer.Ordinal)
                .Take(secondPassCount)
                .Select(pair => pair.Key)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            foreach (var tag in secondPass)
            {
                var measured = await SampleFinalAsync(tag, 1).ConfigureAwait(false);
                var sample = measured.Sample;
                RecordStartupFinal(startupPolicy, finalSamples, tag, sample);
                trace($"quality-startup-final candidate={tag} pass=2 ok={sample.Ok} bps={sample.BytesPerSecond:F0}");
            }

            // Two more alternating-target passes turn the final decision into
            // a four-body reliability gate. Candidates that fail either CDN
            // are not allowed to win merely because another transfer peaked.
            var remaining = secondPass.ToHashSet(StringComparer.OrdinalIgnoreCase);
            for (var pass = 2; pass < StartupLongFormPasses; pass++)
            {
                foreach (var tag in startupFinalists.Where(remaining.Contains))
                {
                    var measured = await SampleFinalAsync(tag, pass).ConfigureAwait(false);
                    var sample = measured.Sample;
                    RecordStartupFinal(startupPolicy, finalSamples, tag, sample);
                    trace($"quality-startup-final candidate={tag} pass={pass + 1} ok={sample.Ok} bps={sample.BytesPerSecond:F0}");
                    if (!sample.Ok) remaining.Remove(tag);
                }
            }
            return await FinishStartupQualificationAsync(runtime, controller, initialGroup, startupFinalists,
                healthy, startupPolicy, finalSamples, trace, confirmedWinner, cancellationToken, partial: false,
                requiredSamples: StartupLongFormPasses)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested &&
            qualificationDeadline is not null && qualificationDeadline.IsCancellationRequested)
        {
            // A global deadline must bound connection setup, not erase every
            // completed measurement.  If at least one finalist already has two
            // successful confirmations, use that fully-qualified evidence.
            trace("quality-startup-timeout-using-completed-results");
            try
            {
                return await FinishStartupQualificationAsync(runtime, controller, initialGroup, startupFinalists,
                    healthy, startupPolicy, finalSamples, trace, confirmedWinner, cancellationToken, partial: true,
                    requiredSamples: StartupLongFormPasses)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error)
            {
                // The throughput refinement remains advisory. A controller
                // readback failure while salvaging a timed-out round must not
                // turn an already healthy native URLTest connection into a
                // failed connect operation.
                trace($"quality-startup-partial-finalize-failed type={error.GetType().Name}");
                return initialGroup;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            // Throughput refinement is an optimization, not reachability
            // authority.  Keep the already verified native URLTest winner if
            // the private benchmark endpoint or controller has a transient
            // problem; normal health/failover remains available.
            trace($"quality-startup-failed type={error.GetType().Name}");
            return initialGroup;
        }
        finally
        {
            qualificationDeadline?.Dispose();
        }
    }

    private static async Task<NodeQualitySample> MeasureStartupFinalAsync(int port, string password,
        CancellationToken token, TimeSpan sampleBudget, int pass, int sampleIndex)
    {
        using var sampleDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        sampleDeadline.CancelAfter(sampleBudget);
        try
        {
            return await MeasureAsync(port, password, sampleDeadline.Token,
                StartupFinalBytes, sampleIndex, adaptive: false, excludeWarmup: true,
                probeUrl: LongFormProbeUrl(pass)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && sampleDeadline.IsCancellationRequested)
        {
            return new NodeQualitySample(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), false, 0, 0, 0);
        }
    }

    private static void RecordStartupFinal(NodeQualityPolicy policy,
        Dictionary<string, List<NodeQualitySample>> finalSamples, string tag, NodeQualitySample sample)
    {
        policy.Record(tag, sample);
        if (!finalSamples.TryGetValue(tag, out var samples)) finalSamples[tag] = samples = [];
        samples.Add(sample);
    }

    internal static string? SelectStartupWinner(
        IEnumerable<(string Tag, double Score, double StallMs, double DelayMs)> candidates)
    {
        var valid = candidates.Where(item => !string.IsNullOrWhiteSpace(item.Tag) &&
                double.IsFinite(item.Score) && item.Score > 0 &&
                double.IsFinite(item.StallMs) && item.StallMs >= 0 &&
                double.IsFinite(item.DelayMs) && item.DelayMs > 0)
            .ToArray();
        if (valid.Length == 0) return null;
        var peak = valid.Max(item => item.Score);
        // Inside the 3% throughput noise band, prefer the path that stalls
        // less and then the lower-latency path.  A tiny benchmark advantage
        // must not buy a visibly worse interactive connection.
        return valid.Where(item => item.Score >= peak * (1 - StartupThroughputToleranceRatio))
            .OrderBy(item => item.StallMs)
            .ThenBy(item => item.DelayMs)
            .ThenByDescending(item => item.Score)
            .ThenBy(item => item.Tag, StringComparer.Ordinal)
            .First().Tag;
    }

    internal static string[] StartupScreenOrder(string incumbent, IEnumerable<string> preferred,
        IEnumerable<string> fallback, IReadOnlySet<string> allowed, int count)
    {
        if (count <= 0 || string.IsNullOrWhiteSpace(incumbent)) return [];
        var challengers = preferred
            .Where(allowed.Contains)
            .Where(tag => !string.Equals(tag, incumbent, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var local = fallback
            .Where(allowed.Contains)
            .Where(tag => !string.Equals(tag, incumbent, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var result = new List<string>(count);
        void Add(string? tag)
        {
            if (result.Count >= count || string.IsNullOrWhiteSpace(tag) || !allowed.Contains(tag) ||
                result.Contains(tag, StringComparer.OrdinalIgnoreCase)) return;
            result.Add(tag);
        }

        // Use the current connection and fresh local reachability first.
        // Reserve roughly one quarter for a deterministic catalogue spread;
        // signed order and node labels contain no speed information.
        Add(incumbent);
        var spreadCount = Math.Max(1, count / 4);
        var spreadSource = challengers;
        var spread = new List<string>(spreadCount);
        if (spreadSource.Length > 0)
        {
            for (var index = 0; index < spreadCount; index++)
            {
                var position = spreadCount == 1 ? spreadSource.Length - 1
                    : (int)Math.Round(index * (spreadSource.Length - 1d) / (spreadCount - 1d));
                var tag = spreadSource[position];
                if (!spread.Contains(tag, StringComparer.OrdinalIgnoreCase)) spread.Add(tag);
            }
        }
        var localIndex = 0;
        var spreadIndex = 0;
        while (result.Count < count && (localIndex < local.Length || spreadIndex < spread.Count))
        {
            // Three fresh-network candidates for every one catalogue-spread
            // candidate keeps the screen local while retaining breadth.
            for (var slot = 0; slot < 3 && localIndex < local.Length && result.Count < count; slot++)
                Add(local[localIndex++]);
            if (spreadIndex < spread.Count && result.Count < count) Add(spread[spreadIndex++]);
        }
        foreach (var tag in local) Add(tag);
        foreach (var tag in challengers) Add(tag);
        return result.ToArray();
    }

    private static async Task<MihomoGroupState> FinishStartupQualificationAsync(
        MihomoQualityRuntime runtime,
        MihomoControllerClient controller,
        MihomoGroupState initialGroup,
        IReadOnlyList<string> finalists,
        IReadOnlyDictionary<string, MihomoProxyHealth> healthy,
        NodeQualityPolicy policy,
        IReadOnlyDictionary<string, List<NodeQualitySample>> finalSamples,
        Action<string> trace,
        Action<string>? confirmedWinner,
        CancellationToken cancellationToken,
        bool partial,
        int requiredSamples = 2)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var ranked = finalists.Select(tag =>
        {
            var score = policy.ReliableScore(tag, now, requiredSamples);
            var samples = finalSamples.GetValueOrDefault(tag, []).TakeLast(requiredSamples).ToArray();
            var stall = samples.Length == requiredSamples && samples.All(sample => sample.Ok && double.IsFinite(sample.StallMs))
                ? samples.Max(sample => sample.StallMs) : double.PositiveInfinity;
            var delay = healthy.TryGetValue(tag, out var health) && NodeQualityPolicy.IsUsableDelay(health.DelayMs)
                ? health.DelayMs!.Value : double.PositiveInfinity;
            return (Tag: tag, Score: score, StallMs: stall, DelayMs: delay);
        }).Where(item => item.Score.HasValue)
            .Select(item => (item.Tag, Score: item.Score!.Value, item.StallMs, item.DelayMs))
            .ToArray();
        var winner = SelectStartupWinner(ranked);
        if (string.IsNullOrWhiteSpace(winner))
        {
            trace(partial ? "quality-startup-partial-no-stable-result" : "quality-startup-no-stable-result");
            return initialGroup;
        }
        var winnerScore = ranked.First(item => string.Equals(item.Tag, winner, StringComparison.OrdinalIgnoreCase)).Score;
        trace($"quality-startup-stable-winner candidate={winner} score={winnerScore:F0} partial={partial}");
        if (string.Equals(winner, initialGroup.Now, StringComparison.OrdinalIgnoreCase))
        {
            trace($"quality-startup-stable-keep candidate={initialGroup.Now}");
            confirmedWinner?.Invoke(winner);
            return initialGroup;
        }

        var package = runtime.Package;
        // Body evidence may precede the provider's URLTest history. Confirm
        // this exact member is currently reachable before changing user flows.
        var freshWinner = await controller.MeasureStartupCandidatesAsync(package.ProviderName,
            [winner], package.AllowedCandidates, cancellationToken).ConfigureAwait(false);
        if (freshWinner.Count != 1 || !freshWinner[0].Alive ||
            !NodeQualityPolicy.IsUsableDelay(freshWinner[0].DelayMs))
        {
            trace($"quality-startup-selection-health-failed candidate={winner}");
            return initialGroup;
        }
        await controller.SelectAsync(package.ActiveGroup, winner, cancellationToken).ConfigureAwait(false);
        var selected = await controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, cancellationToken,
            package.AllowedCandidates).ConfigureAwait(false);
        if (!string.Equals(selected.Now, winner, StringComparison.OrdinalIgnoreCase) ||
            !selected.Candidates.Any(candidate => string.Equals(candidate.Name, winner, StringComparison.OrdinalIgnoreCase) &&
                candidate.Alive && NodeQualityPolicy.IsUsableDelay(candidate.DelayMs)))
        {
            trace($"quality-startup-selection-readback-failed candidate={winner}");
            return initialGroup;
        }
        trace($"quality-startup-throughput-selected from={initialGroup.Now} to={winner} partial={partial}");
        confirmedWinner?.Invoke(winner);
        return selected;
    }
    private async Task RunAsync()
    {
        var token = _stop.Token;
        try
        {
            // Prime controller state only. Native Mihomo URLTest owns startup
            // selection; forcing the first provider entry here defeats
            // Clash-style automatic selection.
            try {
                _ = await _controller.ReadGroupAsync(_runtime.Package.ActiveGroup, _runtime.Package.ProviderName, token);
                _trace("quality-native-urltest-startup-owner");
            } catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch { /* A transient first IPC failure must not disable future rounds. */ }
            if ((_runtime.Package.PreferredCandidates?.Count ?? 0) > 0)
                _trace("quality-catalogue-loaded");
            // Start throughput qualification before a foreground transfer can
            // occupy the connection for minutes. Readiness, controller health
            // and foreground-traffic gates below already fail closed, so a
            // short settle is sufficient and an unready core simply retries.
            await Task.Delay(TimeSpan.FromMilliseconds(350), token);
            await RunRoundsAsync(RunRoundAsync, WaitForNextRoundAsync, token, _trace);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception) { }
    }
    internal static async Task RunRoundsAsync(Func<HashSet<string>, CancellationToken, Task<bool>> round,
        Func<TimeSpan, CancellationToken, Task> delay, CancellationToken token, Action<string>? trace = null)
    {
        // A foreground transfer or controller timeout pauses the same sweep.
        // Dropping its visited set on each retry makes a large provider loop
        // forever without reaching the stable-network quiet period.
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var retrySeconds = 15;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var complete = false;
            var visitedBefore = visited.Count;
            try
            {
                trace?.Invoke("quality-round-start");
                complete = await round(visited, token).ConfigureAwait(false);
                trace?.Invoke(complete ? "quality-round-completed" : "quality-round-incomplete-retry");
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (NodeQualityForegroundInterruptedException) { trace?.Invoke("quality-foreground-yield"); }
            catch (Exception error) { trace?.Invoke($"quality-round-failed-retry type={error.GetType().Name}"); }
            var progressed = visited.Count > visitedBefore;
            if (complete)
            {
                visited.Clear(); retrySeconds = 15;
            }
            if (!complete && !progressed) trace?.Invoke("quality-round-no-progress-backoff");
            await delay(complete ? StableSweepInterval : TimeSpan.FromSeconds(retrySeconds), token).ConfigureAwait(false);
            if (!complete)
            {
                retrySeconds = progressed ? 15 : Math.Min(120, retrySeconds * 2);
            }
        }
    }

    private async Task<bool> RunRoundAsync(HashSet<string> visited, CancellationToken token)
    {
        while (true)
        {
            var recovery = await WaitForProbeSlotAsync(token);
            var step = await OptimizeAsync(visited, recovery, token);
            if (step != RoundStep.Continue) return step == RoundStep.Completed;
            // Do not add an artificial 15-second gap between healthy
            // candidates.  The comparison itself is sequential and the
            // traffic guard cancels immediately if user traffic resumes.
            await Task.Delay(TimeSpan.FromMilliseconds(250), token);
        }
    }

    private Task WaitForNextRoundAsync(TimeSpan interval, CancellationToken token) =>
        WaitForRetryOrMonitoringAsync(interval, Task.Delay, MonitorNextRoundAsync, token);

    internal static Task WaitForRetryOrMonitoringAsync(TimeSpan interval,
        Func<TimeSpan, CancellationToken, Task> delay,
        Func<TimeSpan, CancellationToken, Task> monitor, CancellationToken token) =>
        interval < TimeSpan.FromHours(1) ? delay(interval, token) : monitor(interval, token);

    private async Task MonitorNextRoundAsync(TimeSpan interval, CancellationToken token)
    {
        var started = Stopwatch.GetTimestamp();
        var lastQualityCheck = started;
        while (Stopwatch.GetElapsedTime(started) < interval)
        {
            await Task.Delay(TimeSpan.FromSeconds(15), token);
            if (NetworkFingerprint() != _network) return;
            try
            {
                var package = _runtime.Package;
                var group = await _controller.ReadMonitoredGroupAsync(package.ActiveGroup, package.ProviderName,
                    package.AllowedCandidates, token);
                // A selected node that fell outside the existing quality gate
                // needs another payload comparison before the next full sweep.
                // This never switches on latency alone or restarts the core.
                if (!group.Candidates.Any(item => item.Name == group.Now && item.Alive && NodeQualityPolicy.IsUsableDelay(item.DelayMs))) return;
                if (_confirmedCandidate != group.Now) return;
                if (Stopwatch.GetElapsedTime(lastQualityCheck) < StableRecheckInterval) continue;
                if (!_trafficGate.TryAdmit(Environment.TickCount64, await ReadTrafficRateAsync(token), out var recovery)) continue;
                if (recovery) { _trace("quality-sustained-low-traffic-recovery"); return; }
                if (!_probeBudget.TrySpend(Environment.TickCount64, 2L * StableRecheckBytes)) continue;
                // The HTTP 204 watchdog establishes reachability, not useful
                // throughput. Recheck a quiet incumbent with two bounded body
                // transfers; a sustained drop can reopen comparison early.
                lastQualityCheck = Stopwatch.GetTimestamp();
                var samples = new List<NodeQualitySample>();
                for (var pass = 0; pass < 2; pass++)
                {
                    if (!NodeQualityRecoveryGate.CanContinue(await ReadTrafficRateAsync(token), false)) break;
                    await _controller.SelectAsync(ProbeGroup, group.Now, token);
                    samples.Add(await MeasureForegroundAsync(StableRecheckBytes, pass, false, token));
                }
                if (NodeQualityPolicy.HasSustainedDrop(samples, _confirmedBytesPerSecond)) return;
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch { return; }
        }
    }

    private async Task<RoundStep> OptimizeAsync(HashSet<string> visited, bool recovery, CancellationToken token)
    {
        var network = NetworkFingerprint();
        if (_network != network) { _network = network; _confirmedCandidate = null; _confirmedBytesPerSecond = 0; _roundObservedRates.Clear(); visited.Clear(); }
        var package = _runtime.Package;
        var group = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token);
        if (!package.AllowedCandidates.Contains(group.Now)) return RoundStep.Retry;
        var healthyCandidates = ThroughputEligible(group.Candidates, package.AllowedCandidates);
        if (healthyCandidates.Count == 0) return RoundStep.Retry;
        var preferred = package.PreferredCandidates ?? Array.Empty<string>();
        var contender = NodeQualityPolicy.AdaptiveContender(
            preferred, group.Candidates, package.AllowedCandidates, visited, group.Now, _exploration);
        if (contender is null && visited.Contains(group.Now))
        {
            return await FinalizeSweepAsync(group, recovery, network, token).ConfigureAwait(false);
        }
        var tags = new[] { group.Now, contender ?? group.Now }.Distinct().ToArray();
        // Validate and probe only the next pair. A 600-node health sweep must
        // never stand between a stalled incumbent and its first alternative.
        var health = (await _controller.MeasureVerifiedCandidatesAsync(package.ProviderName, tags,
            package.AllowedCandidates, token)).ToDictionary(item => item.Name, StringComparer.Ordinal);
        if (contender is not null && (!health[contender].Alive || !NodeQualityPolicy.IsUsableDelay(health[contender].DelayMs)))
        {
            visited.Add(contender); _exploration = contender;
            _trace($"quality-candidate-unavailable candidate={contender}");
            return RoundStep.Continue;
        }
        // Recovery used to fall back to 128 KiB probes exactly when a user was
        // watching a slow stream. That recreates the A-131/A-06 failure mode:
        // the faster path loses during TCP/WS/TLS ramp-up and therefore never
        // reaches confirmation. A recovery slot is already rare and bounded,
        // so use the same 1 MiB steady-state evidence as an ordinary decision.
        const int comparisonBytes = ComparisonBytes;
        if (!_probeBudget.TrySpend(Environment.TickCount64, 2L * tags.Length * comparisonBytes))
            return RoundStep.Retry;
        var policy = await MeasurePairAsync(tags, async (tag, pass, ct) => {
            await _controller.SelectAsync(ProbeGroup, tag, ct);
            var sample = await MeasureForegroundAsync(comparisonBytes, pass, recovery, ct);
            return sample with { LatencyMs = health[tag].DelayMs ?? 0 };
        }, async ct => NetworkFingerprint() == network &&
            NodeQualityRecoveryGate.CanContinue(await ReadTrafficRateAsync(ct), recovery), token);
        if (policy is null) { _trace("quality-comparison-yielded"); return RoundStep.Retry; }
        var current = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token);
        if (current.Now != group.Now || NetworkFingerprint() != network) return RoundStep.Retry;
        var alive = ThroughputEligible(current.Candidates, package.AllowedCandidates);
        var at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        RememberRoundRates(policy, tags, at);
        var winner = policy.Choose(package.AllowedCandidates, alive, current.Now, at);
        if (winner is not null)
        {
            if (!_probeBudget.TrySpend(Environment.TickCount64,
                RuntimeLongFormPasses * 2L * LongFormBytes)) return RoundStep.Retry;
            // Every prospective switch must survive repeated long-form bodies
            // across both independent targets. This blocks intermittent nodes
            // that can post a high 1 MiB peak but fail normal sustained flows.
            var confirmation = await MeasurePairAsync(new[] { current.Now, winner }, async (tag, pass, ct) => {
                await _controller.SelectAsync(ProbeGroup, tag, ct);
                var sample = await MeasureForegroundLongAsync(pass, recovery, ct);
                return sample with { LatencyMs = health[tag].DelayMs ?? 0 };
            }, async ct => NetworkFingerprint() == network &&
                NodeQualityRecoveryGate.CanContinue(await ReadTrafficRateAsync(ct), recovery), token,
                RuntimeLongFormPasses);
            if (confirmation is null) return RoundStep.Retry;
            var readback = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token);
            if (readback.Now != current.Now || NetworkFingerprint() != network) return RoundStep.Retry;
            alive = ThroughputEligible(readback.Candidates, package.AllowedCandidates);
            at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            RememberRoundRates(confirmation, new[] { current.Now, winner }, at);
            var confirmed = ConfirmLongFormWinner(confirmation, current.Now, winner, at, RuntimeLongFormPasses);
            if (confirmed != winner) _trace($"quality-switch-unconfirmed incumbent={current.Now} candidate={winner}");
            winner = confirmed == winner ? winner : null;
            policy = confirmation;
        }
        if (winner is not null)
        {
            var previous = current.Now;
            // A confirmed payload winner must own new user flows; otherwise
            // this worker is only telemetry and URLTest keeps the low-RTT node
            // even when it has much lower sustained bandwidth. PUT pins the
            // measured winner, while CoreRuntime's existing failure recovery
            // DELETEs the URLTest selection cache before automatic failover.
            await _controller.SelectAsync(package.ActiveGroup, winner, token);
            var selected = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token,
                package.AllowedCandidates);
            if (!string.Equals(selected.Now, winner, StringComparison.Ordinal) ||
                !selected.Candidates.Any(candidate => string.Equals(candidate.Name, winner, StringComparison.Ordinal) &&
                    candidate.Alive && NodeQualityPolicy.IsUsableDelay(candidate.DelayMs)))
            {
                _trace($"quality-throughput-selection-readback-failed candidate={winner}");
                _ = await _controller.WaitForFirstUsableAutomaticGroupAsync(package.ActiveGroup, package.ProviderName,
                    package.AllowedCandidates, TimeSpan.FromSeconds(5), token);
                return RoundStep.Retry;
            }
            current = selected;
            // Selector changes affect only new connections. During a bounded
            // slow-stream recovery, reconnect only established media flows
            // that are still chained through the old active candidate so a
            // long-lived YouTube/GoogleVideo QUIC or HTTP session can actually
            // benefit from the measured winner. Other long-lived sessions
            // (notably ChatGPT affinity and arbitrary downloads) are preserved.
            if (recovery && !string.Equals(previous, winner, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var closed = await _controller.CloseConnectionsUsingProxyAsync(
                        package.ActiveGroup, previous, IsRecoverableMediaHost, token).ConfigureAwait(false);
                    _trace($"quality-media-connections-restarted count={closed} from={previous} to={winner}");
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception error)
                {
                    // Connection draining is an acceleration hint. A controller
                    // snapshot race must never roll back a verified node switch.
                    _trace($"quality-media-restart-skipped type={error.GetType().Name}");
                }
            }
            _trace($"quality-throughput-selected candidate={winner} incumbent_bps={policy.Score(group.Now, at):F0} candidate_bps={policy.Score(winner, at):F0} recovery={recovery}");
        }
        else _trace($"quality-compared incumbent={current.Now} candidate={contender ?? current.Now} incumbent_bps={policy.Score(current.Now, at):F0} candidate_bps={policy.Score(contender ?? current.Now, at):F0} recovery={recovery}");
        _confirmedCandidate = current.Now;
        _confirmedBytesPerSecond = policy.Score(current.Now, at) ?? 0;
        visited.UnionWith(tags);
        if (contender is not null) _exploration = contender;
        var completed = package.AllowedCandidates.All(visited.Contains) && _confirmedBytesPerSecond > 0;
        return completed
            ? await FinalizeSweepAsync(current, recovery, network, token).ConfigureAwait(false)
            : RoundStep.Continue;
    }

    private void RememberRoundRates(NodeQualityPolicy policy, IEnumerable<string> tags, long now)
    {
        foreach (var tag in tags.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var score = policy.Score(tag, now);
            if (!score.HasValue || !double.IsFinite(score.Value) || score.Value <= 0) continue;
            if (!_roundObservedRates.TryGetValue(tag, out var previous) || score.Value > previous)
                _roundObservedRates[tag] = score.Value;
        }
    }

    private async Task<RoundStep> FinalizeSweepAsync(MihomoGroupState group, bool recovery, string network,
        CancellationToken token)
    {
        // End-of-sweep confirmation intentionally uses the full 512 KiB body
        // pair. Do not run it inside a low-throughput recovery slot; preserve
        // the completed visited set and retry when the foreground is quiet.
        if (recovery)
        {
            _trace("quality-finalists-deferred-foreground");
            return RoundStep.Retry;
        }

        var package = _runtime.Package;
        var current = group;
        var confirmedRate = _roundObservedRates.GetValueOrDefault(current.Now, _confirmedBytesPerSecond);
        var finalists = NodeQualityPolicy.RoundFinalists(_roundObservedRates, package.AllowedCandidates,
            current.Now, EndOfSweepFinalistCount);
        foreach (var challenger in finalists)
        {
            if (NetworkFingerprint() != network) return RoundStep.Retry;
            var tags = new[] { current.Now, challenger };
            var health = (await _controller.MeasureVerifiedCandidatesAsync(package.ProviderName, tags,
                package.AllowedCandidates, token).ConfigureAwait(false))
                .ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
            if (!health.TryGetValue(current.Now, out var incumbentHealth) || !incumbentHealth.Alive ||
                !NodeQualityPolicy.IsUsableDelay(incumbentHealth.DelayMs) ||
                !health.TryGetValue(challenger, out var challengerHealth) || !challengerHealth.Alive ||
                !NodeQualityPolicy.IsUsableDelay(challengerHealth.DelayMs))
            {
                _trace($"quality-finalist-unavailable candidate={challenger}");
                continue;
            }
            var championshipBytes = RuntimeLongFormPasses * 2L * LongFormBytes;
            if (!_probeBudget.TrySpend(Environment.TickCount64, championshipBytes)) return RoundStep.Retry;
            var confirmation = await MeasurePairAsync(tags, async (tag, pass, ct) => {
                await _controller.SelectAsync(ProbeGroup, tag, ct).ConfigureAwait(false);
                var sample = await MeasureForegroundLongAsync(pass, false, ct).ConfigureAwait(false);
                return sample with { LatencyMs = health[tag].DelayMs ?? 0 };
            }, async ct => NetworkFingerprint() == network &&
                NodeQualityRecoveryGate.CanContinue(await ReadTrafficRateAsync(ct).ConfigureAwait(false), false), token,
                RuntimeLongFormPasses)
                .ConfigureAwait(false);
            if (confirmation is null) return RoundStep.Retry;

            var readback = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token)
                .ConfigureAwait(false);
            if (!string.Equals(readback.Now, current.Now, StringComparison.Ordinal) || NetworkFingerprint() != network)
                return RoundStep.Retry;
            var alive = ThroughputEligible(readback.Candidates, package.AllowedCandidates);
            var at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            RememberRoundRates(confirmation, tags, at);
            var winner = ConfirmLongFormWinner(confirmation, current.Now, challenger, at, RuntimeLongFormPasses);
            if (!string.Equals(winner, challenger, StringComparison.Ordinal))
            {
                confirmedRate = confirmation.Score(current.Now, at) ?? confirmedRate;
                _trace($"quality-finalist-unconfirmed incumbent={current.Now} candidate={challenger}");
                continue;
            }

            await _controller.SelectAsync(package.ActiveGroup, challenger, token).ConfigureAwait(false);
            var selected = await _controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, token,
                package.AllowedCandidates).ConfigureAwait(false);
            if (!string.Equals(selected.Now, challenger, StringComparison.Ordinal) ||
                !selected.Candidates.Any(candidate => string.Equals(candidate.Name, challenger, StringComparison.Ordinal) &&
                    candidate.Alive && NodeQualityPolicy.IsUsableDelay(candidate.DelayMs)))
            {
                _trace($"quality-finalist-selection-readback-failed candidate={challenger}");
                return RoundStep.Retry;
            }
            current = selected;
            confirmedRate = confirmation.Score(challenger, at) ?? confirmedRate;
            _trace($"quality-finalist-selected candidate={challenger} bps={confirmedRate:F0}");
        }

        if (confirmedRate <= 0 || !double.IsFinite(confirmedRate))
        {
            _trace("quality-round-unqualified-reset");
            _roundObservedRates.Clear();
            return RoundStep.Retry;
        }
        _confirmedCandidate = current.Now;
        _confirmedBytesPerSecond = confirmedRate;
        _roundObservedRates.Clear();
        _confirmedWinner?.Invoke(current.Now);
        _trace($"quality-round-finalized candidate={current.Now} bps={confirmedRate:F0}");
        return RoundStep.Completed;
    }

    internal static HashSet<string> NativeLatencyWindow(
        IReadOnlyList<MihomoProxyHealth> candidates,
        IReadOnlySet<string> allowed)
    {
        var usable = candidates.Where(item =>
                allowed.Contains(item.Name) &&
                item.Alive &&
                NodeQualityPolicy.IsUsableDelay(item.DelayMs))
            .ToArray();
        if (usable.Length == 0) return new HashSet<string>(StringComparer.Ordinal);
        var bestDelay = usable.Min(item => item.DelayMs!.Value);
        return usable
            .Where(item => item.DelayMs!.Value <= bestDelay + MihomoPolicyCompiler.AutoSelectToleranceMs)
            .Select(item => item.Name)
            .ToHashSet(StringComparer.Ordinal);
    }

    internal static HashSet<string> ThroughputEligible(
        IReadOnlyList<MihomoProxyHealth> candidates,
        IReadOnlySet<string> allowed) => candidates.Where(item =>
            allowed.Contains(item.Name) && item.Alive && NodeQualityPolicy.IsUsableDelay(item.DelayMs))
            .Select(item => item.Name).ToHashSet(StringComparer.Ordinal);

    internal static string? ConfirmLongFormWinner(NodeQualityPolicy policy, string incumbent, string challenger,
        long now, int requiredSamples = RuntimeLongFormPasses)
    {
        var challengerScore = policy.ReliableScore(challenger, now, requiredSamples);
        if (!challengerScore.HasValue) return null;
        var incumbentScore = policy.ReliableScore(incumbent, now, requiredSamples);
        if (!incumbentScore.HasValue || challengerScore.Value > incumbentScore.Value * (1 + StartupThroughputToleranceRatio))
            return challenger;
        return null;
    }

    internal static bool IsRecoverableMediaHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        host = host.Trim().TrimEnd('.');
        if (BifrostServiceRouting.YoutubeDomains.Contains(host, StringComparer.OrdinalIgnoreCase)) return true;
        return BifrostServiceRouting.YoutubeSuffixes.Any(suffix =>
            host.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase));
    }

    // Four bounded transfers are one decision. If traffic or the network
    // changes, discard the pair instead of aging half a comparison in a wait.
    internal static async Task<NodeQualityPolicy?> MeasurePairAsync(IReadOnlyList<string> tags,
        Func<string, int, CancellationToken, Task<NodeQualitySample>> measure,
        Func<CancellationToken, Task<bool>> canContinue, CancellationToken token, int passes = 2)
    {
        if (passes < 2 || passes > 8) throw new ArgumentOutOfRangeException(nameof(passes));
        var policy = new NodeQualityPolicy();
        for (var pass = 0; pass < passes; pass++) foreach (var tag in tags)
        {
            token.ThrowIfCancellationRequested();
            if (!await canContinue(token)) return null;
            policy.Record(tag, await measure(tag, pass, token));
        }
        return policy;
    }
    private string NetworkFingerprint()
    {
        var name = _underlayInterface;
        var nic = WindowsInterfaceReadback.Read().FirstOrDefault(item => item.Name == name || item.Id == name);
        if (nic is null) return "unavailable";
        return nic.Id + ":" + nic.OperationalStatus +
            ":addr=" + string.Join(",", nic.UnicastAddresses.Select(item => item.ToString()).Order()) +
            ":dns=" + string.Join(",", nic.DnsAddresses.Select(item => item.ToString()).Order());
    }
    private async Task<double> ReadTrafficRateAsync(CancellationToken token)
    {
        try {
            // Only Bifrost foreground traffic should postpone its optimizer.
            // Physical NIC counters also include other VPNs and applications,
            // which previously starved the sweep indefinitely on this host.
            var name = MihomoWindowsContract.TunInterfaceName;
            var current = WindowsInterfaceReadback.Read().FirstOrDefault(item => item.Name == name || item.Id == name);
            if (current is null || current.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) return double.PositiveInfinity;
            // Cache only the statistics handle. Identity/state/addresses above
            // remain fresh, and GetIPStatistics reads live kernel counters.
            var nic = _trafficAdapter;
            if (nic?.Id != current.Id || nic.GetIPProperties().GetIPv4Properties()?.Index != current.InterfaceIndex)
                _trafficAdapter = nic = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(item => item.Id == current.Id);
            if(nic is null) return double.PositiveInfinity;
            var before = nic.GetIPStatistics(); var total = before.BytesReceived + before.BytesSent;
            var started = Stopwatch.GetTimestamp();
            await Task.Delay(500,token);
            var after = nic.GetIPStatistics();
            return Math.Max(0, after.BytesReceived + after.BytesSent - total) / Stopwatch.GetElapsedTime(started).TotalSeconds;
        } catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch { return double.PositiveInfinity; }
    }
    private async Task<bool> WaitForProbeSlotAsync(CancellationToken token)
    {
        while (true)
        {
            if (!_probeBudget.CanStart(Environment.TickCount64))
            { await Task.Delay(TimeSpan.FromSeconds(30), token); continue; }
            if (_trafficGate.TryAdmit(Environment.TickCount64, await ReadTrafficRateAsync(token), out var recovery))
                return recovery;
            await Task.Delay(TimeSpan.FromSeconds(10), token);
        }
    }

    internal static async Task WaitForIdleAsync(Func<CancellationToken, Task<bool>> isBusy,
        Func<TimeSpan, CancellationToken, Task> delay, CancellationToken token)
    {
        // Recheck after every wait. A single fixed delay used to launch a full
        // download cohort even while the user was still streaming video.
        while (await isBusy(token).ConfigureAwait(false))
            await delay(TimeSpan.FromSeconds(10), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
    }
    private Task<NodeQualitySample> MeasureForegroundAsync(int bytes, int pass, bool recovery, CancellationToken token) =>
        NodeQualityForegroundGuard.RunAsync(NodeQualityForegroundGuard.TunnelReader(),
            ct => MeasureAsync(_runtime.Port, _runtime.Password, ct, bytes, pass, adaptive: false,
                sustained: bytes == ProbeObjectBytes && pass == 0), recovery, token);

    private Task<NodeQualitySample> MeasureForegroundLongAsync(int pass, bool recovery, CancellationToken token) =>
        NodeQualityForegroundGuard.RunAsync(NodeQualityForegroundGuard.TunnelReader(),
            ct => MeasureAsync(_runtime.Port, _runtime.Password, ct, LongFormBytes, 700 + pass,
                adaptive: false, excludeWarmup: true, probeUrl: LongFormProbeUrl(pass)), recovery, token);

    private Task<NodeQualitySample> MeasureForegroundParallelAsync(int bytes, int streams, int sampleIndex,
        bool recovery, CancellationToken token) =>
        NodeQualityForegroundGuard.RunAsync(NodeQualityForegroundGuard.TunnelReader(),
            ct => MeasureCompositeAsync(_runtime.Port, _runtime.Password, ct, bytes, streams, sampleIndex),
            recovery, token);

    internal static async Task<NodeQualitySample> MeasureAsync(int port, string password, CancellationToken token,
        int bytes = ProbeBytes, int sampleIndex = 0, bool adaptive = true, bool excludeWarmup = true,
        bool sustained = false, string? probeUrl = null)
    {
        if (bytes is not (ProbeBytes or ComparisonBytes or ProbeObjectBytes or LongFormBytes))
            throw new ArgumentOutOfRangeException(nameof(bytes));
        if (sustained && bytes is not (ComparisonBytes or ProbeObjectBytes)) throw new ArgumentOutOfRangeException(nameof(bytes));
        var requested = sustained ? SustainedMaximumBytes : adaptive && bytes == ProbeBytes ? ProbeObjectBytes : bytes;
        var at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(requested >= LongFormBytes ? TimeSpan.FromSeconds(30) :
            requested >= ComparisonBytes ? TimeSpan.FromSeconds(12) : TimeSpan.FromSeconds(6));
        using var handler = new SocketsHttpHandler {
            UseProxy = true, Proxy = new WebProxy($"http://127.0.0.1:{port}") { Credentials = new NetworkCredential("quality", password) },
            AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None, ConnectTimeout = TimeSpan.FromSeconds(3)
        };
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            var probe = probeUrl ?? (sustained ? SustainedProbeUrl : ProbeUrl);
            using var request = new HttpRequestMessage(HttpMethod.Get, probe);
            // CacheFly's public test object returns a tiny placeholder for
            // clients without a User-Agent. Explicit identity is required
            // before a 206 response can count as payload evidence.
            request.Headers.UserAgent.ParseAdd("BifrostQuality/1.0");
            var offset = RandomNumberGenerator.GetInt32(0, 10 * 1024 * 1024 - requested + 1);
            request.Headers.Range = new RangeHeaderValue(offset, offset + requested - 1);
            request.Headers.AcceptEncoding.ParseAdd("identity");
            var timer = Stopwatch.StartNew();
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.StatusCode != HttpStatusCode.PartialContent ||
                response.Content.Headers.ContentRange?.From != offset ||
                response.Content.Headers.ContentRange?.To != offset + requested - 1 ||
                response.Content.Headers.ContentEncoding.Count != 0 ||
                response.Content.Headers.ContentLength != requested)
                throw new IOException("BF-QUALITY-RESPONSE");
            var latency = timer.Elapsed.TotalMilliseconds;
            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            var bodyAt = timer.Elapsed.TotalSeconds; var last = bodyAt; var stall = 0.0; var count = 0; var warmup = 0;
            var buffer = new byte[16 * 1024];
            while (count < requested) {
                var n = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, requested - count)), deadline.Token);
                if (n <= 0) throw new IOException("BF-QUALITY-TRUNCATED");
                var now = timer.Elapsed.TotalSeconds; stall = Math.Max(stall, (now - last) * 1000); last = now; count += n;
                // Exclude the first TLS/body buffer; bytes already waiting when
                // headers arrive must not inflate measured download goodput.
                if (excludeWarmup && warmup < 16 * 1024) { warmup = count; bodyAt = now; }
                if (sustained && count >= bytes && now - bodyAt >= .75) break;
                if (adaptive && bytes == ProbeBytes && !NodeQualityPolicy.ContinueDownload(count, now - bodyAt)) break;
            }
            if (sustained ? count < bytes : !HasRequiredPayload(count, requested, bytes, adaptive))
                throw new IOException("BF-QUALITY-TRUNCATED");
            var goodput = NodeQualityPolicy.BodyGoodput(count, warmup, Math.Max(0, last - bodyAt));
            return new(at, goodput > 0, latency, goodput, stall);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception) { return new(at, false, 0, 0, 0); }
    }

    internal static bool HasRequiredPayload(int receivedBytes, int requestedBytes, int logicalBytes, bool adaptive) =>
        receivedBytes >= (adaptive && logicalBytes == ProbeBytes ? logicalBytes : requestedBytes);

    internal static int RequiredParallelSuccesses(int streams) => Math.Max(2, (streams * 3 + 3) / 4);

    internal static int CapacityStreams(double sustainedBytesPerSecond, int maximum) =>
        maximum <= 2 || sustainedBytesPerSecond * 8 < 4_000_000 ? 2 : maximum;

    internal static NodeQualitySample CombineSustainedAndCapacity(NodeQualitySample sustained,
        NodeQualitySample capacity)
    {
        if (!sustained.Ok || !capacity.Ok || !double.IsFinite(sustained.BytesPerSecond) ||
            !double.IsFinite(capacity.BytesPerSecond) || sustained.BytesPerSecond <= 0 ||
            capacity.BytesPerSecond <= 0)
            return new NodeQualitySample(Math.Max(sustained.At, capacity.At), false, 0, 0, 0);
        // The single stream catches stalls hidden by four concurrent flows;
        // capacity still receives most of the weight for large downloads.
        var score = Math.Pow(sustained.BytesPerSecond, .35) * Math.Pow(capacity.BytesPerSecond, .65);
        return new NodeQualitySample(Math.Max(sustained.At, capacity.At), true,
            Math.Max(sustained.LatencyMs, capacity.LatencyMs), score,
            Math.Max(sustained.StallMs, capacity.StallMs));
    }

    internal static NodeQualitySample ScoreStartupCapacity(IEnumerable<NodeQualitySample> samples, long at)
    {
        var completed = samples.Where(sample => sample.Ok && double.IsFinite(sample.BytesPerSecond) &&
                sample.BytesPerSecond > 0 && NodeQualityPolicy.IsUsableDelay(sample.LatencyMs))
            .OrderBy(sample => sample.BytesPerSecond).ToArray();
        if (completed.Length < 2) return new(at, false, 0, 0, 0);
        var conservative = completed.Take(2).ToArray();
        return new(at, true, conservative.Max(sample => sample.LatencyMs),
            conservative.Sum(sample => sample.BytesPerSecond),
            conservative.Max(sample => sample.StallMs));
    }

    internal static async Task<NodeQualitySample> MeasureCompositeAsync(int port, string password,
        CancellationToken token, int bytes, int streams, int sampleIndex)
    {
        var sustained = await MeasureAsync(port, password, token, bytes, sampleIndex,
            adaptive: false, sustained: true).ConfigureAwait(false);
        if (!sustained.Ok) return sustained;
        var capacity = await MeasureParallelAsync(port, password, token, bytes,
            CapacityStreams(sustained.BytesPerSecond, streams),
            sampleIndex + 1).ConfigureAwait(false);
        return CombineSustainedAndCapacity(sustained, capacity);
    }

    internal static async Task<NodeQualitySample> MeasureParallelAsync(int port, string password,
        CancellationToken token, int bytes = ProbeObjectBytes, int streams = 4, int sampleIndex = 0)
    {
        if (streams is < 2 or > 8) throw new ArgumentOutOfRangeException(nameof(streams));
        if (bytes is not (ProbeBytes or ComparisonBytes or ProbeObjectBytes))
            throw new ArgumentOutOfRangeException(nameof(bytes));
        var at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var samples = await Task.WhenAll(Enumerable.Range(0, streams)
            .Select(index => MeasureAsync(port, password, token, bytes, sampleIndex + index, adaptive: false)))
            .ConfigureAwait(false);
        var successful = samples.Where(sample => sample.Ok && double.IsFinite(sample.BytesPerSecond) && sample.BytesPerSecond > 0).ToArray();
        // A capacity sample must remain reliable across most of its bounded
        // connections; a 50% success rate is not suitable for auto-selection.
        if (successful.Length < RequiredParallelSuccesses(streams)) return new NodeQualitySample(at, false, 0, 0, 0);
        var latencies = successful.Select(sample => sample.LatencyMs).Where(double.IsFinite).Order().ToArray();
        var latency = latencies.Length == 0 ? 0 : latencies[latencies.Length / 2];
        return new NodeQualitySample(at, true, latency,
            successful.Sum(sample => sample.BytesPerSecond),
            successful.Max(sample => sample.StallMs));
    }
    public void Dispose()
    {
        _stop.Cancel();
        try { _worker.GetAwaiter().GetResult(); } catch { }
        _controller.Dispose(); _stop.Dispose();
    }
}
