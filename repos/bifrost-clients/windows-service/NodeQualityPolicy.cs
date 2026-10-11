namespace Bifrost.ClientService;

internal sealed record NodeQualitySample(long At, bool Ok, double LatencyMs, double BytesPerSecond, double StallMs);

// Keep arithmetic and decision thresholds identical to Android BifrostNodeQuality.
internal sealed class NodeQualityPolicy
{
    // URLTest includes the HTTP response. Valid slow responses still qualify
    // for throughput measurement; failed/unknown delays remain ineligible.
    internal static bool IsUsableDelay(double? delayMs) => delayMs is > 0 && double.IsFinite(delayMs.Value);
    internal static bool HasSustainedDrop(IReadOnlyList<NodeQualitySample> samples, double baseline) =>
        samples.Count == 2 && (samples.All(sample => !sample.Ok) ||
            double.IsFinite(baseline) && baseline > 0 && samples.All(sample => sample.Ok &&
                double.IsFinite(sample.BytesPerSecond) && sample.BytesPerSecond > 0 && sample.BytesPerSecond < baseline * .5));
    // Keep room for the end-of-sweep capacity championship in addition to the
    // per-node pairwise comparisons. The runtime budget is the authoritative
    // limiter; this bound exists so fixtures catch accidental unbounded probe
    // amplification when the full-pool algorithm changes.
    internal static long MaximumRoundPayloadBytes(int nodes) => checked(nodes * 3L * 1024 * 1024 + 32L * 1024 * 1024);
    internal static bool ContinueDownload(int bytes, double bodySeconds) => bytes < 512 * 1024 && (bytes < 128 * 1024 || bodySeconds < .25);
    internal static double BodyGoodput(int bytes, int warmupBytes, double bodySeconds)
    {
        if (bytes <= warmupBytes || warmupBytes < 0 || !double.IsFinite(bodySeconds) || bodySeconds <= 0) return 0;
        return (bytes - warmupBytes) / Math.Max(.001, bodySeconds);
    }
    internal static string[] Finalists(IReadOnlyDictionary<string,double> rates, IReadOnlySet<string> healthy, string incumbent) =>
        new[] { incumbent }.Concat(rates.Where(pair => healthy.Contains(pair.Key) && double.IsFinite(pair.Value) && pair.Value > 0)
            .OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key, StringComparer.Ordinal).Take(8).Select(pair => pair.Key)).Distinct().ToArray();
    // The cursor follows stable identifiers, never the moving latency leaderboard.
    internal static string[] Cohort(IEnumerable<string> eligible, IReadOnlySet<string> visited, string incumbent, string cursor, int count) =>
        eligible.Where(tag => tag != incumbent && !visited.Contains(tag)).Distinct(StringComparer.Ordinal)
            .OrderBy(tag => string.CompareOrdinal(tag, cursor) > 0 ? 0 : 1).ThenBy(tag => tag, StringComparer.Ordinal).Take(count).ToArray();
    internal static string[] RoundFinalists(IReadOnlyDictionary<string, double> observed,
        IReadOnlySet<string> allowed, string incumbent, int count) => observed
        .Where(pair => allowed.Contains(pair.Key) &&
            !string.Equals(pair.Key, incumbent, StringComparison.OrdinalIgnoreCase) &&
            double.IsFinite(pair.Value) && pair.Value > 0)
        .OrderByDescending(pair => pair.Value)
        .ThenBy(pair => pair.Key, StringComparer.Ordinal)
        .Take(Math.Max(0, count))
        .Select(pair => pair.Key)
        .ToArray();

    internal static string? AdaptiveContender(
        IEnumerable<string> catalogue,
        IReadOnlyList<MihomoProxyHealth> candidates,
        IReadOnlySet<string> allowed,
        IReadOnlySet<string> visited,
        string incumbent,
        string cursor)
    {
        // Catalogue order is not evidence of throughput. Use local
        // reachability, then a stable identifier cursor for full coverage.
        _ = catalogue;
        var completedChallengers = visited.Count - (visited.Contains(incumbent) ? 1 : 0);
        if (completedChallengers % 4 != 3)
        {
            var local = candidates
                .Where(candidate => allowed.Contains(candidate.Name) &&
                    !string.Equals(candidate.Name, incumbent, StringComparison.OrdinalIgnoreCase) &&
                    !visited.Contains(candidate.Name) &&
                    candidate.Alive && IsUsableDelay(candidate.DelayMs))
                .OrderBy(candidate => candidate.DelayMs)
                .ThenBy(candidate => candidate.Name, StringComparer.Ordinal)
                .Select(candidate => candidate.Name)
                .FirstOrDefault();
            if (local is not null) return local;
        }
        return Cohort(allowed, visited, incumbent, cursor, 1).FirstOrDefault();
    }
    private readonly Dictionary<string, List<NodeQualitySample>> _history = new(StringComparer.Ordinal);
    internal void Record(string tag, NodeQualitySample sample)
    {
        if (!_history.TryGetValue(tag, out var entries)) _history[tag] = entries = [];
        entries.RemoveAll(item => sample.At - item.At is < 0 or > 3_600_000);
        entries.Add(sample);
        while (entries.Count > 8) entries.RemoveAt(0);
    }
    internal double? Score(string tag, long now)
    {
        // Delay is the native candidate URLTest result, not download TTFB.
        // Compare only two recent completed transfers. A single burst cannot win.
        var samples = _history.GetValueOrDefault(tag, []).TakeLast(2).ToArray();
        if (samples.Length != 2 || samples.Any(item => !item.Ok || now - item.At is < 0 or > 120_000 ||
            !IsUsableDelay(item.LatencyMs) ||
            !double.IsFinite(item.BytesPerSecond) || item.BytesPerSecond <= 0)) return null;
        return samples.Min(item => item.BytesPerSecond);
    }

    internal double? StableScore(string tag, long now)
    {
        // Startup qualification has no established user-flow incumbent yet,
        // so rank the fully downloaded two-sample finalists by the same
        // stability-weighted throughput objective as Control pipeline v10.
        // The slower run dominates, while the faster run can still separate
        // otherwise similar candidates without letting a single burst win.
        var samples = _history.GetValueOrDefault(tag, []).TakeLast(2).ToArray();
        // Startup qualification is short and bounded. Leave a generous
        // finalization/readback margin so a completed pair is not discarded
        // merely because controller readback finishes later.
        if (samples.Length != 2 || samples.Any(item => !item.Ok || now - item.At is < 0 or > 360_000 ||
            !IsUsableDelay(item.LatencyMs) ||
            !double.IsFinite(item.BytesPerSecond) || item.BytesPerSecond <= 0)) return null;
        var speeds = samples.Select(item => item.BytesPerSecond).Order().ToArray();
        var worst = speeds[0];
        var median = speeds[speeds.Length / 2];
        var average = speeds.Average();
        return worst * .55 + median * .30 + average * .15;
    }

    internal double? ReliableScore(string tag, long now, int requiredSamples)
    {
        if (requiredSamples < 2 || requiredSamples > 8) throw new ArgumentOutOfRangeException(nameof(requiredSamples));
        var samples = _history.GetValueOrDefault(tag, []).TakeLast(requiredSamples).ToArray();
        if (samples.Length != requiredSamples || samples.Any(item => !item.Ok || now - item.At is < 0 or > 360_000 ||
            !IsUsableDelay(item.LatencyMs) || !double.IsFinite(item.BytesPerSecond) || item.BytesPerSecond <= 0)) return null;
        var speeds = samples.Select(item => item.BytesPerSecond).Order().ToArray();
        var worst = speeds[0];
        var median = speeds[speeds.Length / 2];
        var average = speeds.Average();
        // Long-form qualification is intentionally conservative: a node must
        // complete every required transfer, and its slowest completed body has
        // the largest influence. This prevents intermittent high peaks from
        // outranking a path that repeatedly sustains useful throughput.
        return worst * .60 + median * .25 + average * .15;
    }
    internal string? Choose(IReadOnlySet<string> allowed, IReadOnlySet<string> healthy, string? incumbent, long now)
    {
        var ranked = allowed.Intersect(healthy).Select(tag => (Tag: tag, Score: Score(tag, now))).Where(item => item.Score.HasValue)
            .OrderByDescending(item => item.Score).ThenBy(item => item.Tag, StringComparer.Ordinal).ToArray();
        if (ranked.Length == 0) return null;
        var best = ranked[0];
        var confirmation = _history[best.Tag].TakeLast(2).ToArray();
        if (confirmation.Length < 2 || confirmation.Any(item => !item.Ok || now - item.At is < 0 or > 120_000)) return null;
        if (incumbent is null || !healthy.Contains(incumbent)) return best.Tag;
        var previous = _history.GetValueOrDefault(incumbent, []).TakeLast(2).ToArray();
        var failed = previous.Length == 2 && previous.All(item => !item.Ok && now - item.At is >= 0 and <= 120_000);
        var current = Score(incumbent, now) ?? (failed ? 0 : (double?)null);
        // Compare the challenger's slower transfer with the incumbent's faster
        // transfer. Requiring both challenger samples to clear both incumbent
        // samples already provides the noise guard; an extra percentage band
        // would deliberately keep a slower path.
        var baseline = failed ? 0 : previous.Where(item => item.Ok).Select(item => item.BytesPerSecond).DefaultIfEmpty(double.PositiveInfinity).Max();
        if (!current.HasValue || best.Tag == incumbent || best.Score <= baseline) return null;
        return best.Tag;
    }
}
