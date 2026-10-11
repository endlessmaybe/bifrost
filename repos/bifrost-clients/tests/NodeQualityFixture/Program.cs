using System.Text.Json.Nodes;
using Bifrost.ClientService;

var fixture = JsonNode.Parse(File.ReadAllText(args[0]))!.AsObject();
var now = fixture["now"]!.GetValue<long>();
var count = 0;
foreach(var test in fixture["cases"]!.AsArray().OfType<JsonObject>()) {
    var policy = new NodeQualityPolicy();
    foreach(var pair in test["samples"]!.AsObject()) {
        var rows = pair.Value!.AsArray();
        for(var j=0;j<rows.Count;j++) {
            var r = rows[j]!.AsArray();
            policy.Record(pair.Key, new(now-1000+j, r[0]!.GetValue<bool>(),r[1]!.GetValue<double>(),r[2]!.GetValue<double>(),r[3]!.GetValue<double>()));
        }
    }
    HashSet<string> Names(string key) => test[key]!.AsArray().Select(x=>x!.GetValue<string>()).ToHashSet();
    var actual = policy.Choose(Names("allowed"),Names("healthy"),test["incumbent"]!.GetValue<string>(),now);
    if(actual != test["expected"]?.GetValue<string>()) throw new Exception("Failed: "+test["name"]);
    if(policy.Choose(Names("allowed"),Names("healthy"),test["incumbent"]!.GetValue<string>(),now+3_600_001) is not null) throw new Exception("Expired history selected");
    count++;
}
Console.WriteLine($"NODE-QUALITY PASS {count} shared cases and expiry");
{
    var single = new NodeQualitySample(now, true, 120, 1_000_000, 40);
    var parallel = new NodeQualitySample(now, true, 80, 4_000_000, 25);
    var combined = MihomoQualityOptimizer.CombineSustainedAndCapacity(single, parallel);
    if (!combined.Ok || combined.BytesPerSecond <= single.BytesPerSecond ||
        combined.BytesPerSecond >= parallel.BytesPerSecond || combined.StallMs != 40 ||
        MihomoQualityOptimizer.CombineSustainedAndCapacity(single, parallel with { Ok = false }).Ok ||
        MihomoQualityOptimizer.CapacityStreams(499_999, 4) != 2 ||
        MihomoQualityOptimizer.CapacityStreams(500_000, 4) != 4)
        throw new Exception("Sustained and adaptive multi-flow capacity evidence was not combined safely");
}
Console.WriteLine("NODE-QUALITY independent sustained and adaptive multi-flow evidence PASS");
{
    var completed = new[] {
        new NodeQualitySample(now, true, 110, 400_000, 20),
        new NodeQualitySample(now, false, 0, 0, 0),
        new NodeQualitySample(now, true, 130, 500_000, 35),
    };
    var score = MihomoQualityOptimizer.ScoreStartupCapacity(completed, now);
    if (!score.Ok || score.BytesPerSecond != 900_000 || score.StallMs != 35 ||
        MihomoQualityOptimizer.ScoreStartupCapacity(completed.Take(2), now).Ok ||
        MihomoQualityOptimizer.ScoreStartupCapacity(completed.Append(new(now, true, 90, 9_000_000, 5)), now).BytesPerSecond != 900_000)
        throw new Exception("Startup final must retain two completed bodies through one stream failure without counting a burst");
}
Console.WriteLine("NODE-QUALITY startup final tolerates one failed stream and conservatively scores completed bodies PASS");
if (MihomoQualityOptimizer.StartupFinalBytes < 5 * 1024 * 1024 ||
    MihomoQualityOptimizer.StartupLongFormPasses < 4 ||
    MihomoQualityOptimizer.RuntimeLongFormPasses < 4 ||
    MihomoQualityOptimizer.LongFormProbeUrl(0) == MihomoQualityOptimizer.LongFormProbeUrl(1) ||
    MihomoQualityOptimizer.LongFormProbeUrl(0) != MihomoQualityOptimizer.LongFormProbeUrl(2))
    throw new Exception("Long-form qualification no longer repeats large bodies across two independent targets");
Console.WriteLine("NODE-QUALITY 5 MiB repeated dual-target long-form qualification PASS");
if (new double?[] { null, 0, -1, double.NaN, double.PositiveInfinity }.Any(NodeQualityPolicy.IsUsableDelay) ||
    new double?[] { 1, 299, 300, 301, 1500, 15_000, 65_535 }.Any(delay => !NodeQualityPolicy.IsUsableDelay(delay)))
    throw new Exception("A valid URLTest response was excluded by a latency ceiling or an invalid result was admitted");
Console.WriteLine("NODE-QUALITY successful high-latency responses remain eligible; invalid and unknown delays excluded PASS");
if (MihomoQualityOptimizer.StartupScreenBytes < 1024 * 1024 ||
    MihomoQualityOptimizer.ComparisonBytes < 1024 * 1024)
    throw new Exception("A-131 regression: short 128/256 KiB samples can rank a slow-start path below A-06 before sustained throughput is visible");
{
    // Real A-131/A-06 crossover shape reproduced from the isolated local
    // proxy benchmark: A-131 can lose the tiny transfer, then pull far ahead
    // once the body is large enough to leave TCP/WS/TLS startup behind.
    var crossover = new NodeQualityPolicy();
    crossover.Record("A-06", new(now - 2, true, 70, 156_036, 0));
    crossover.Record("A-06", new(now - 1, true, 70, 200_168, 0));
    crossover.Record("A-131", new(now - 2, true, 110, 510_053, 0));
    crossover.Record("A-131", new(now - 1, true, 110, 526_664, 0));
    var allowed = new HashSet<string>(new[] { "A-06", "A-131" }, StringComparer.OrdinalIgnoreCase);
    if (crossover.Choose(allowed, allowed, "A-06", now) != "A-131")
        throw new Exception("A-131 regression: longer-body evidence did not replace the slower A-06 incumbent");
}
Console.WriteLine("NODE-QUALITY A-131/A-06 real 1 MiB crossover selects the sustained winner PASS");
{
    var candidates = new[]
    {
        new MihomoProxyHealth("A-1", true, 100),
        new MihomoProxyHealth("A-2", true, 145),
        new MihomoProxyHealth("A-3", true, 151),
        new MihomoProxyHealth("A-4", false, 1),
        new MihomoProxyHealth("foreign", true, 1),
    };
    var window = MihomoQualityOptimizer.NativeLatencyWindow(
        candidates,
        new HashSet<string>(new[] { "A-1", "A-2", "A-3", "A-4" }, StringComparer.Ordinal));
    if (!window.SetEquals(new[] { "A-1", "A-2" }))
        throw new Exception("Throughput optimizer escaped the native URLTest tolerance window");
}
Console.WriteLine("NODE-QUALITY throughput refinement stays inside native 50ms URLTest window PASS");
if (!NodeQualityPolicy.ContinueDownload(128 * 1024, .005) || NodeQualityPolicy.ContinueDownload(128 * 1024, .30) ||
    !NodeQualityPolicy.ContinueDownload(64 * 1024, .30) || NodeQualityPolicy.ContinueDownload(512 * 1024, .005))
    throw new Exception("Adaptive measurement stopped at a buffered prefix or exceeded its cap");
{
    var rates = new Dictionary<string,double> { ["current"] = 10, ["burst"] = 100, ["fast"] = 80, ["foreign"] = 999 };
    var allowed = new HashSet<string> { "current", "burst", "fast" };
    var finalists = NodeQualityPolicy.Finalists(rates, allowed, "current");
    if (!finalists.SequenceEqual(new[] { "current", "burst", "fast" })) throw new Exception("Final comparison omitted runner-up or admitted foreign member");
    var verified = new NodeQualityPolicy();
    var trueRates = new Dictionary<string,double> { ["current"] = 10, ["burst"] = 5, ["fast"] = 50 };
    foreach (var tag in finalists) for (var pass = 0; pass < 2; pass++) verified.Record(tag, new(1000 + pass, true, 180, trueRates[tag], 0));
    if (verified.Choose(allowed, allowed, "current", 2000) != "fast") throw new Exception("Noisy champion hid the faster runner-up");
}
Console.WriteLine("NODE-QUALITY adaptive body duration and noisy-champion final comparison PASS");
{
    var stable = new NodeQualityPolicy();
    stable.Record("repeatable", new(now - 2, true, 180, 100, 0));
    stable.Record("repeatable", new(now - 1, true, 180, 100, 0));
    stable.Record("bursty", new(now - 2, true, 180, 80, 0));
    stable.Record("bursty", new(now - 1, true, 180, 120, 0));
    if (!(stable.StableScore("repeatable", now) > stable.StableScore("bursty", now)))
        throw new Exception("Startup stable score let one fast burst outrank repeatable throughput");
}
Console.WriteLine("NODE-QUALITY startup stable-throughput score PASS");
{
    var reliable = new NodeQualityPolicy();
    foreach (var rate in new[] { 2_900_000d, 2_400_000d, 2_700_000d, 2_300_000d })
        reliable.Record("A-131", new(now, true, 100, rate, 20));
    reliable.Record("A-129", new(now, true, 90, 3_500_000, 10));
    reliable.Record("A-129", new(now, false, 0, 0, 0));
    reliable.Record("A-129", new(now, true, 90, 3_600_000, 10));
    reliable.Record("A-129", new(now, true, 90, 2_100_000, 10));
    if (!reliable.ReliableScore("A-131", now, 4).HasValue ||
        reliable.ReliableScore("A-129", now, 4).HasValue ||
        MihomoQualityOptimizer.ConfirmLongFormWinner(reliable, "A-129", "A-131", now, 4) != "A-131" ||
        MihomoQualityOptimizer.ConfirmLongFormWinner(reliable, "A-131", "A-129", now, 4) is not null)
        throw new Exception("Intermittent peak node still passed the long-form reliability gate");
}
Console.WriteLine("NODE-QUALITY intermittent high peak cannot beat 4/4 sustained long-form success PASS");
{
    var boundary = new NodeQualityPolicy();
    boundary.Record("edge", new(now - 359_999, true, 80, 100, 0));
    boundary.Record("edge", new(now - 359_998, true, 80, 100, 0));
    if (!boundary.StableScore("edge", now).HasValue || boundary.StableScore("edge", now + 2) is not null)
        throw new Exception("Startup stable evidence did not preserve the deadline finalization margin or expired too late");
}
Console.WriteLine("NODE-QUALITY startup finalization grace window PASS");
{
    var allowed = new HashSet<string>(new[] { "A-08" }, StringComparer.OrdinalIgnoreCase);
    var root = Path.Combine(Path.GetTempPath(), "bifrost-quality-memory-" + Guid.NewGuid().ToString("N"));
    var path = Path.Combine(root, "memory.json");
    try
    {
        var memory = new MihomoConnectionMemory(path);
        var key = new string('a', 64);
        memory.Remember(key, "A-08", now);
        if (memory.RecallFresh(key, allowed, now + MihomoConnectionMemory.FastReuseMs) != "A-08" ||
            memory.RecallFresh(key, allowed, now + MihomoConnectionMemory.FastReuseMs + 1) is not null ||
            memory.Recall(key, allowed, now + MihomoConnectionMemory.FastReuseMs + 1) != "A-08")
            throw new Exception("A stale throughput winner incorrectly bypassed requalification or was discarded from retained history");
    }
    finally { try { Directory.Delete(root, true); } catch { } }
}
Console.WriteLine("NODE-QUALITY remembered winner has a bounded fast-reuse window PASS");
{
    var winner = MihomoQualityOptimizer.SelectStartupWinner(new[]
    {
        (Tag: "peak-but-stalled", Score: 100.0, StallMs: 400.0, DelayMs: 40.0),
        (Tag: "near-peak-clean", Score: 98.5, StallMs: 20.0, DelayMs: 70.0),
        (Tag: "outside-band", Score: 96.0, StallMs: 1.0, DelayMs: 1.0),
    });
    if (winner != "near-peak-clean") throw new Exception("Startup ranking ignored the throughput noise band or transfer stability");
    winner = MihomoQualityOptimizer.SelectStartupWinner(new[]
    {
        (Tag: "higher-delay", Score: 100.0, StallMs: 20.0, DelayMs: 90.0),
        (Tag: "lower-delay", Score: 99.0, StallMs: 20.0, DelayMs: 40.0),
    });
    if (winner != "lower-delay") throw new Exception("Startup ranking ignored latency inside the throughput noise band");
}
Console.WriteLine("NODE-QUALITY startup throughput band, stall and latency tie-break PASS");
if (MihomoQualityOptimizer.StartupCohortSize < 29 ||
    MihomoQualityOptimizer.StartupReuseCohortSize < 12 ||
    MihomoQualityOptimizer.StartupScreenBudget >= MihomoQualityOptimizer.StartupQualificationTimeout ||
    MihomoQualityOptimizer.StartupReuseScreenBudget >= MihomoQualityOptimizer.StartupReuseQualificationTimeout ||
    MihomoQualityOptimizer.StartupScreenCandidateBudget >= MihomoQualityOptimizer.StartupScreenBudget / 2 ||
    MihomoQualityOptimizer.StartupReuseScreenCandidateBudget >= MihomoQualityOptimizer.StartupReuseScreenBudget / 2 ||
    MihomoQualityOptimizer.StartupScreenOrder("I", new[] { "P1", "P2" }, new[] { "I" }, new HashSet<string> { "I", "P1", "P2" }, 3)[0] != "I")
    throw new Exception("Startup screening bounds regressed");
Console.WriteLine("NODE-QUALITY startup screening bounds PASS");
{
    var allowed = new HashSet<string>(new[] { "I", "P1", "P2", "P3", "P4", "L1", "L2", "L3", "L4" },
        StringComparer.OrdinalIgnoreCase);
    var ordered = MihomoQualityOptimizer.StartupScreenOrder("I",
        new[] { "P1", "P2", "P3", "P4" },
        new[] { "L1", "L2", "L3", "L4" }, allowed, 7);
    if (ordered[0] != "I" ||
        !ordered.Take(7).Contains("L1") || !ordered.Take(7).Contains("L2"))
        throw new Exception("Startup screen still lets the complete provider ranking hide local-network candidates");
}
Console.WriteLine("NODE-QUALITY startup screen blends control-plane seeds with current-network candidates PASS");
{
    var allowed = new HashSet<string>(new[] { "I", "P1", "P2", "P3", "LOCAL" }, StringComparer.OrdinalIgnoreCase);
    var health = new[]
    {
        new MihomoProxyHealth("P1", true, 900),
        new MihomoProxyHealth("P2", true, 800),
        new MihomoProxyHealth("P3", true, 700),
        new MihomoProxyHealth("LOCAL", true, 35),
    };
    var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (NodeQualityPolicy.AdaptiveContender(new[] { "P1", "P2", "P3", "LOCAL" }, health, allowed, visited, "I", "") != "LOCAL")
        throw new Exception("Fresh current-network ranking remained shadowed by catalogue order");
    visited.Add("LOCAL");
    if (NodeQualityPolicy.AdaptiveContender(new[] { "P1", "P2", "P3", "LOCAL" }, health, allowed, visited, "I", "") != "P3")
        throw new Exception("The next reachable candidate was skipped after the local winner");
}
Console.WriteLine("NODE-QUALITY runtime sweep leaves stale provider order after two seeds PASS");
{
    var allowed = new HashSet<string>(new[] { "incumbent", "fast-but-dipped", "runner-up", "slow" },
        StringComparer.OrdinalIgnoreCase);
    var observed = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
    {
        ["incumbent"] = 80,
        ["fast-but-dipped"] = 140,
        ["runner-up"] = 120,
        ["slow"] = 40,
        ["foreign"] = 1000,
    };
    var finalists = NodeQualityPolicy.RoundFinalists(observed, allowed, "incumbent",
        MihomoQualityOptimizer.EndOfSweepFinalistCount);
    if (!finalists.SequenceEqual(new[] { "fast-but-dipped", "runner-up", "slow" }))
        throw new Exception("End-of-sweep finalist retry omitted the strongest observed challengers or admitted foreign/incumbent nodes");
}
Console.WriteLine("NODE-QUALITY end-of-sweep strongest-challenger retry set PASS");
{
    if (MihomoQualityOptimizer.EndOfSweepFinalistCount != 4 ||
        MihomoQualityOptimizer.LongFormBytes != 5 * 1024 * 1024 ||
        MihomoQualityOptimizer.RuntimeLongFormPasses != 4)
        throw new Exception("End-of-sweep confirmation regressed to a short or single-target sample");
    var championshipPayload = MihomoQualityOptimizer.EndOfSweepFinalistCount *
        MihomoQualityOptimizer.RuntimeLongFormPasses * 2L * MihomoQualityOptimizer.LongFormBytes;
    if (championshipPayload != 160L * 1024 * 1024 ||
        NodeQualityPolicy.MaximumRoundPayloadBytes(600) < championshipPayload)
        throw new Exception("End-of-sweep long-form championship is missing from the bounded payload model");
}
Console.WriteLine("NODE-QUALITY end-of-sweep repeated dual-target 5 MiB championship PASS");
if (MihomoQualityOptimizer.StartupLaneCount < MihomoQualityOptimizer.StartupFinalistCount ||
    MihomoQualityOptimizer.StartupScreenBudget + MihomoQualityOptimizer.StartupFinalBudget != MihomoQualityOptimizer.StartupQualificationTimeout ||
    MihomoQualityOptimizer.StartupReuseScreenBudget + MihomoQualityOptimizer.StartupReuseFinalBudget != MihomoQualityOptimizer.StartupReuseQualificationTimeout ||
    MihomoQualityOptimizer.StartupFinalSampleBudget * MihomoQualityOptimizer.StartupLongFormPasses >= MihomoQualityOptimizer.StartupFinalBudget ||
    MihomoQualityOptimizer.StartupReuseFinalSampleBudget * MihomoQualityOptimizer.StartupLongFormPasses >= MihomoQualityOptimizer.StartupReuseFinalBudget ||
    MihomoQualityOptimizer.StartupSecondPassCount != MihomoQualityOptimizer.StartupFinalistCount ||
    MihomoQualityOptimizer.StartupReuseSecondPassCount != MihomoQualityOptimizer.StartupReuseFinalistCount)
    throw new Exception("Startup final confirmation no longer has a reserved completion margin");
Console.WriteLine("NODE-QUALITY startup screen/final budgets preserve the bounded connection envelope and final confirmation margin PASS");
if (!MihomoQualityOptimizer.HasRequiredPayload(128 * 1024, 512 * 1024, 128 * 1024, adaptive: true) ||
    MihomoQualityOptimizer.HasRequiredPayload(128 * 1024 - 1, 512 * 1024, 128 * 1024, adaptive: true) ||
    MihomoQualityOptimizer.HasRequiredPayload(511 * 1024, 512 * 1024, 512 * 1024, adaptive: false) ||
    !MihomoQualityOptimizer.HasRequiredPayload(512 * 1024, 512 * 1024, 512 * 1024, adaptive: false) ||
    MihomoQualityOptimizer.HasRequiredPayload(5 * 1024 * 1024 - 1, 5 * 1024 * 1024, 5 * 1024 * 1024, adaptive: false) ||
    !MihomoQualityOptimizer.HasRequiredPayload(5 * 1024 * 1024, 5 * 1024 * 1024, 5 * 1024 * 1024, adaptive: false))
    throw new Exception("Adaptive payload completion still requires the entire backing object or accepts a truncated fixed transfer");
if (MihomoQualityOptimizer.RequiredParallelSuccesses(2) != 2 ||
    MihomoQualityOptimizer.RequiredParallelSuccesses(3) != 3 ||
    MihomoQualityOptimizer.RequiredParallelSuccesses(4) != 3 ||
    MihomoQualityOptimizer.RequiredParallelSuccesses(8) != 6)
    throw new Exception("Parallel capacity reliability threshold is incorrect");
Console.WriteLine("NODE-QUALITY adaptive completion and 75% parallel reliability PASS");
foreach (var size in new[] { 1, 30, 169, 300, 600 }) {
    var all = Enumerable.Range(1,size).Select(i => $"A-{i:000}").ToArray();
    var visited = new HashSet<string>(StringComparer.Ordinal);
    var incumbent = all[0]; var cursor = ""; var transfers = 0;
    for (var batch = 0; batch <= size; batch++) {
        // Moving delay order and an improved incumbent must not hide tail nodes.
        var cohort = NodeQualityPolicy.Cohort(all.Reverse(), visited, incumbent, cursor, 7);
        if (cohort.Length == 0 && visited.Contains(incumbent)) break;
        var members = new[] { incumbent }.Concat(cohort).Distinct().ToArray();
        visited.UnionWith(members); transfers += members.Length * 2;
        if (cohort.Length > 0) { cursor = cohort[^1]; incumbent = cohort[^1]; }
    }
    if (!visited.SetEquals(all)) throw new Exception($"Coverage incomplete: {size}");
    var maxTransfers = 2 * (size + (size + 6) / 7);
    if (transfers > maxTransfers) throw new Exception("Unbounded repeated downloads");
    if (transfers * 128L * 1024 + 8L * 1024 * 1024 > NodeQualityPolicy.MaximumRoundPayloadBytes(size)) throw new Exception("Payload estimate omitted a candidate");
}
Console.WriteLine("NODE-QUALITY all-node coverage PASS: 1/30/169/300/600, moving rankings and incumbent, bounded payload");
foreach (var size in new[] { 30, 169, 300, 600 })
{
    var all = Enumerable.Range(1, size).Select(i => $"A-{i:000}").ToArray();
    var allowed = all.ToHashSet(StringComparer.Ordinal);
    var best = all[Math.Max(2, size - 11)];
    var preferred = all.Where(tag => tag != best).Concat(new[] { best }).ToArray();
    var health = all.Select((tag, index) => new MihomoProxyHealth(tag, true,
        tag == best ? 5_000 : 20 + index % 200)).ToArray();
    var rates = all.ToDictionary(tag => tag, tag => tag == best ? 50_000_000d : 500_000d + Array.IndexOf(all, tag) * 1_000d,
        StringComparer.Ordinal);
    var visited = new HashSet<string>(StringComparer.Ordinal);
    var incumbent = all[0];
    var cursor = "";
    for (var step = 0; step < size * 2 && visited.Count < size; step++)
    {
        var contender = NodeQualityPolicy.AdaptiveContender(preferred, health, allowed, visited, incumbent, cursor);
        if (contender is null) break;
        var pair = new NodeQualityPolicy();
        var tags = new[] { incumbent, contender }.Distinct().ToArray();
        foreach (var tag in tags)
            for (var pass = 0; pass < 2; pass++)
                pair.Record(tag, new(10_000 + step * 10 + pass, true,
                    health.Single(item => item.Name == tag).DelayMs ?? 1, rates[tag], 0));
        var winner = pair.Choose(allowed, allowed, incumbent, 20_000 + step * 10);
        if (winner is not null) incumbent = winner;
        visited.UnionWith(tags);
        cursor = contender;
    }
    if (!visited.SetEquals(allowed) || incumbent != best)
        throw new Exception($"Full-pool throughput winner was not reached: {size}");
}
Console.WriteLine("NODE-QUALITY full-pool winner PASS: 30/169/300/600, stale seeds and high-latency fastest tail candidate");
var server = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback,0); server.Start();
using(var cancel = new CancellationTokenSource()) {
    var accepted = server.AcceptTcpClientAsync();
    var measurement = MihomoQualityOptimizer.MeasureAsync(((System.Net.IPEndPoint)server.LocalEndpoint).Port,"TEST-ONLY-password",cancel.Token);
    using var peer = await accepted.WaitAsync(TimeSpan.FromSeconds(2));
    cancel.Cancel();
    try { await measurement.WaitAsync(TimeSpan.FromSeconds(2)); throw new Exception("Cancellation swallowed"); }
    catch(OperationCanceledException) { }
    finally { server.Stop(); }
}
Console.WriteLine("NODE-QUALITY cancellation PASS");
{
    var checks = 0;
    var waits = 0;
    var probeStarted = false;
    await MihomoQualityOptimizer.WaitForIdleAsync(_ => Task.FromResult(++checks <= 3),
        (_, _) => { if (probeStarted) throw new Exception("Probe started during foreground video traffic"); waits++; return Task.CompletedTask; },
        CancellationToken.None);
    probeStarted = true;
    if (checks != 4 || waits != 3) throw new Exception("Busy network was only deferred once");
    using var cancel = new CancellationTokenSource();
    try {
        await MihomoQualityOptimizer.WaitForIdleAsync(_ => Task.FromResult(true),
            (_, token) => { cancel.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; }, cancel.Token);
        throw new Exception("Busy wait ignored disconnect cancellation");
    } catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
}
Console.WriteLine("NODE-QUALITY foreground streaming yield, repeated busy checks and cancellation PASS");
{
    var rounds = 0;
    var delays = new List<TimeSpan>();
    using var cancel = new CancellationTokenSource();
    try {
        await MihomoQualityOptimizer.RunRoundsAsync((_, _) => {
            rounds++;
            if (rounds == 1) throw new IOException("TEST-ONLY controller failure");
            return Task.FromResult(rounds == 3);
        }, (interval, token) => {
            delays.Add(interval);
            if (delays.Count == 3) { cancel.Cancel(); token.ThrowIfCancellationRequested(); }
            return Task.CompletedTask;
        }, cancel.Token);
    } catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
    if (rounds != 3 || !delays.SequenceEqual(new[] { TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30), MihomoQualityOptimizer.StableSweepInterval }))
        throw new Exception("Failed or incomplete optimization incorrectly consumed the stable-sweep cooldown");
}
Console.WriteLine("NODE-QUALITY interrupted rounds back off; completed rounds alone use stable-sweep cadence PASS");
{
    var rounds = 0;
    var delays = new List<TimeSpan>();
    using var cancel = new CancellationTokenSource();
    try
    {
        await MihomoQualityOptimizer.RunRoundsAsync((_, _) => {
            rounds++;
            return Task.FromResult(false);
        }, (interval, token) => {
            delays.Add(interval);
            if (delays.Count == 11) { cancel.Cancel(); token.ThrowIfCancellationRequested(); }
            return Task.CompletedTask;
        }, cancel.Token);
    }
    catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
    var expected = new[] { 15, 30, 60, 120, 120, 120, 120, 120, 120, 120, 120 }
        .Select(seconds => TimeSpan.FromSeconds(seconds));
    if (rounds != 11 || !delays.SequenceEqual(expected))
        throw new Exception("No-progress optimizer stayed on the short retry cadence indefinitely");
}
Console.WriteLine("NODE-QUALITY no-progress retries keep bounded retry cadence PASS");
{
    var waited = new List<TimeSpan>();
    var monitored = 0;
    foreach (var seconds in new[] { 15, 30, 60, 120 })
        await MihomoQualityOptimizer.WaitForRetryOrMonitoringAsync(TimeSpan.FromSeconds(seconds),
            (interval, _) => { waited.Add(interval); return Task.CompletedTask; },
            (_, _) => { monitored++; return Task.CompletedTask; }, CancellationToken.None);
    await MihomoQualityOptimizer.WaitForRetryOrMonitoringAsync(MihomoQualityOptimizer.StableSweepInterval,
        (interval, _) => { waited.Add(interval); return Task.CompletedTask; },
        (_, _) => { monitored++; return Task.CompletedTask; }, CancellationToken.None);
    if (!waited.SequenceEqual(new[] { 15, 30, 60, 120 }.Select(seconds => TimeSpan.FromSeconds(seconds))) || monitored != 1)
        throw new Exception("Runtime wait truncated retry backoff or bypassed completed-round monitoring");
    using var cancel = new CancellationTokenSource(); cancel.Cancel();
    try {
        await MihomoQualityOptimizer.WaitForRetryOrMonitoringAsync(TimeSpan.FromSeconds(120), Task.Delay,
            (_, _) => throw new Exception("Retry entered monitoring"), cancel.Token);
        throw new Exception("Retry ignored disconnect cancellation");
    } catch(OperationCanceledException) when(cancel.IsCancellationRequested) { }
}
Console.WriteLine("NODE-QUALITY runtime wait honors full retry duration and disconnect cancellation PASS");
{
    // Reproduce repeated foreground interruptions with a provider large enough
    // that no individual invocation can finish. The cursor wraps, but completed
    // members must never be downloaded twice before the stable-network pause.
    var all = Enumerable.Range(1, 169).Select(i => $"A-{i:000}").ToHashSet(StringComparer.Ordinal);
    var measurements = new HashSet<string>(StringComparer.Ordinal);
    var delays = new List<TimeSpan>();
    var cursor = "";
    var completed = false;
    using var cancel = new CancellationTokenSource();
    try {
        await MihomoQualityOptimizer.RunRoundsAsync((visited, _) => {
            if (completed) {
                if (visited.Count != 0) throw new Exception("The next stable sweep retained stale coverage");
                cancel.Cancel(); cancel.Token.ThrowIfCancellationRequested();
            }
            visited.Add("A-001");
            var next = NodeQualityPolicy.Cohort(all, visited, "A-001", cursor, 3);
            foreach (var tag in next) {
                if (!measurements.Add(tag)) throw new Exception("Interrupted sweep repeated a completed candidate");
                visited.Add(tag); cursor = tag;
            }
            completed = visited.SetEquals(all);
            if (!completed && measurements.Count % 6 == 0) throw new IOException("TEST-ONLY transient controller failure");
            return Task.FromResult(completed);
        }, (interval, _) => { delays.Add(interval); return Task.CompletedTask; }, cancel.Token);
    } catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
    if (!completed || measurements.Count != 168 || delays[^1] != MihomoQualityOptimizer.StableSweepInterval ||
        delays.Take(delays.Count - 1).Any(interval => interval < TimeSpan.FromSeconds(15) || interval > TimeSpan.FromSeconds(120)))
        throw new Exception("Interrupted provider sweep failed coverage, bounded backoff or stable-sweep cooldown");
}
Console.WriteLine("NODE-QUALITY 169-node interrupted sweep preserves progress, finishes and resets coverage PASS");
{
    if (MihomoQualityOptimizer.StableSweepInterval != TimeSpan.FromHours(1) ||
        MihomoQualityOptimizer.StableRecheckInterval != TimeSpan.FromMinutes(2) ||
        MihomoQualityOptimizer.StableRecheckBytes != 256 * 1024)
        throw new Exception("Stable maintenance cadence regressed");
    var checksPerHour = Math.Ceiling(TimeSpan.FromHours(1).TotalMilliseconds /
        MihomoQualityOptimizer.StableRecheckInterval.TotalMilliseconds);
    var payloadPerHour = checksPerHour * 2d * MihomoQualityOptimizer.StableRecheckBytes;
    if (payloadPerHour > 15.1 * 1024 * 1024)
        throw new Exception("Stable incumbent monitoring payload is too high");
}
Console.WriteLine("NODE-QUALITY original 1h sweep / 2min incumbent cadence restored; maintenance stays near 15 MiB/hour PASS");
{
    NodeQualitySample Sample(double rate, bool ok = true) => new(1000, ok, 100, rate, 0);
    if (!NodeQualityPolicy.HasSustainedDrop([Sample(100), Sample(120)], 1000) ||
        !NodeQualityPolicy.HasSustainedDrop([Sample(0, false), Sample(0, false)], 1000) ||
        NodeQualityPolicy.HasSustainedDrop([Sample(100)], 1000) ||
        NodeQualityPolicy.HasSustainedDrop([Sample(100), Sample(900)], 1000) ||
        NodeQualityPolicy.HasSustainedDrop([Sample(600), Sample(700)], 1000) ||
        NodeQualityPolicy.HasSustainedDrop([Sample(100), Sample(120)], 0))
        throw new Exception("Incumbent throughput degradation must be sustained and relative to a measured baseline");
}
Console.WriteLine("NODE-QUALITY sustained body-throughput degradation detection PASS");
{
    var gate = new NodeQualityRecoveryGate();
    if (gate.TryAdmit(0, 56 * 1024, out _) || gate.TryAdmit(29_999, 56 * 1024, out _) ||
        !gate.TryAdmit(30_000, 56 * 1024, out var recovery) || !recovery ||
        gate.TryAdmit(149_999, 56 * 1024, out _) || !gate.TryAdmit(150_000, 56 * 1024, out recovery) || !recovery)
        throw new Exception("A persistent slow stream must receive a bounded recovery slot every two minutes");
    if (gate.TryAdmit(151_000, 8 * 1024 * 1024, out _) || gate.TryAdmit(181_000, double.NaN, out _) ||
        gate.TryAdmit(211_000, double.PositiveInfinity, out _) || gate.TryAdmit(300_000, 56 * 1024, out _) ||
        !gate.TryAdmit(330_000, 56 * 1024, out recovery) || !recovery)
        throw new Exception("Healthy or unknown traffic must reset the sustained-low-traffic window");
    if (!gate.TryAdmit(330_100, 0, out recovery) || recovery ||
        !NodeQualityRecoveryGate.CanContinue(1024 * 1024, true) ||
        NodeQualityRecoveryGate.CanContinue(8 * 1024 * 1024, true) ||
        !NodeQualityRecoveryGate.CanContinue(56 * 1024, false) || !NodeQualityRecoveryGate.CanContinue(56 * 1024, true) ||
        NodeQualityRecoveryGate.CanContinue(192 * 1024, false))
        throw new Exception("Recovery must be bounded and must continue yielding to high throughput");
}
Console.WriteLine("NODE-QUALITY persistent slow-stream recovery, cooldown and high-traffic priority PASS");
{
    var gate = new NodeQualityRecoveryGate();
    if (gate.TryAdmit(0, 300 * 1024, out _) ||
        !gate.TryAdmit(30_000, 300 * 1024, out var recovery) || !recovery)
        throw new Exception("Low-bandwidth recovery ceiling regressed");

    var baseline = new NodeQualityTrafficCounters("tun-recovery", 1_000, 1_000);
    var after = baseline with { Sent = baseline.Sent + (long)(300 * 1024 * .25) };
    if (NodeQualityForegroundGuard.MustYield(baseline, after, .25, recovery))
        throw new Exception("A recovery slot admitted by NodeQualityRecoveryGate was immediately cancelled by the foreground guard");
}
Console.WriteLine("NODE-QUALITY low-bandwidth recovery admission and foreground guard agree PASS");
{
    var gate = new NodeQualityRecoveryGate();
    if (gate.TryAdmit(0, 64 * 1024, out _)) throw new Exception("Premature recovery");
    if (!gate.TryAdmit(10_000, 0, out var recovery) || recovery) throw new Exception("Idle gap must permit ordinary work");
    if (gate.TryAdmit(20_000, 64 * 1024, out _)) throw new Exception("Premature recovery");
    if (!gate.TryAdmit(30_000, 0, out recovery) || !recovery) throw new Exception("Bursty slow media never entered recovery");
    if (!gate.TryAdmit(40_000, 0, out recovery) || recovery) throw new Exception("Recovery cooldown ignored");
    if (!gate.TryAdmit(160_000, 0, out recovery) || recovery) throw new Exception("Stale slow evidence triggered recovery");
    if (gate.TryAdmit(170_000, 64 * 1024, out _) || gate.TryAdmit(180_000, 8 * 1024 * 1024, out _)) throw new Exception("Fast traffic was not respected");
    if (!gate.TryAdmit(210_000, 0, out recovery) || recovery) throw new Exception("Fast traffic failed to reset recovery");
}
Console.WriteLine("NODE-QUALITY burst gaps, stale evidence and recovery cooldown PASS");
{
    var gate = new NodeQualityRecoveryGate();
    if (gate.TryAdmit(0, 2 * 1024 * 1024, out _) ||
        !gate.TryAdmit(30_000, 2 * 1024 * 1024, out var recovery) || !recovery ||
        !NodeQualityRecoveryGate.CanContinue(2 * 1024 * 1024, recovery))
        throw new Exception("Ordinary video-rate foreground traffic still starves bounded recovery");
    if (!MihomoQualityOptimizer.IsRecoverableMediaHost("rr1---sn.googlevideo.com") ||
        !MihomoQualityOptimizer.IsRecoverableMediaHost("www.youtube.com") ||
        MihomoQualityOptimizer.IsRecoverableMediaHost("chatgpt.com"))
        throw new Exception("Media reconnection scope is too broad or misses YouTube delivery hosts");
}
Console.WriteLine("NODE-QUALITY video-rate recovery and media-only reconnect scope PASS");

{
    var calls = new List<string>();
    var at = now;
    var tags = new[] { "current", "challenger" };
    var pair = await MihomoQualityOptimizer.MeasurePairAsync(tags, (tag, pass, _) => {
        calls.Add(tag + pass); at += 6000;
        return Task.FromResult(new NodeQualitySample(at, true, 600, tag == "current" ? 40_000 : 400_000, 0));
    }, _ => Task.FromResult(true), CancellationToken.None);
    var allowed = tags.ToHashSet();
    if (pair?.Choose(allowed, allowed, "current", at) != "challenger" ||
        !calls.SequenceEqual(new[] { "current0", "challenger0", "current1", "challenger1" }))
        throw new Exception("The first fresh pair must decide without waiting for the remaining provider nodes");
    calls.Clear();
    var checks = 0;
    var interrupted = await MihomoQualityOptimizer.MeasurePairAsync(tags, (tag, pass, _) => {
        calls.Add(tag + pass); return Task.FromResult(new NodeQualitySample(now, true, 100, 1000, 0));
    }, _ => Task.FromResult(++checks <= 2), CancellationToken.None);
    if (interrupted is not null || calls.Count != 2) throw new Exception("A interrupted pair must be discarded, never retained across an indefinite traffic wait");
}
Console.WriteLine("NODE-QUALITY immediate paired decisions and discard on resumed foreground traffic PASS");
{
    var tags = new[] { "working", "slow-prefix" };
    var allowed = tags.ToHashSet();
    var shortProbe = new NodeQualityPolicy();
    for (var pass = 0; pass < 2; pass++) {
        shortProbe.Record("working", new(now, false, 200, 0, 0));
        shortProbe.Record("slow-prefix", new(now, true, 200, 23_000, 0));
    }
    if (shortProbe.Choose(allowed, allowed, "working", now) != "slow-prefix")
        throw new Exception("Fixture must reproduce ambiguous short-timeout promotion");
    var confirmed = await MihomoQualityOptimizer.MeasurePairAsync(tags, (tag, pass, _) =>
        Task.FromResult(new NodeQualitySample(now, tag == "working", 200, tag == "working" ? 160_000 : 0, 0)),
        _ => Task.FromResult(true), CancellationToken.None);
    if (confirmed?.Choose(allowed, allowed, "working", now) is not null)
        throw new Exception("A candidate that cannot complete real media bodies must not replace a working incumbent");
}
Console.WriteLine("NODE-QUALITY complete-body confirmation rejects misleading short-timeout winner PASS");
{
    var budget = new NodeQualityProbeBudget();
    for (long window = 0; window < 288; window++) {
        var at = window * NodeQualityProbeBudget.WindowMs;
        for (var sample = 0; sample < NodeQualityProbeBudget.MaximumBytes / (1024 * 1024); sample++)
            if (!budget.TrySpend(at + sample, 1024 * 1024)) throw new Exception("Diagnostic budget prematurely exhausted");
        if (budget.TrySpend(at + NodeQualityProbeBudget.MaximumBytes / (1024 * 1024), 1) || budget.CanStart(at + NodeQualityProbeBudget.WindowMs - 1))
            throw new Exception("A 24-hour sweep exceeded the diagnostic-only byte budget");
    }
}
Console.WriteLine($"NODE-QUALITY 24-hour scheduling simulation keeps diagnostic payload at {NodeQualityProbeBudget.MaximumBytes / (1024 * 1024)} MiB per five minutes PASS");
await ForegroundGuardFixture.Run();
if(args.Length > 1) await LiveQualityFixture.Run(args[1], args[2], args[3], args[4],
    args.Length > 5 ? args[5] : "A", args.Length > 6 ? args[6] : null);
