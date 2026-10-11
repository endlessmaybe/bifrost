using System.Net;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Bifrost.ClientService;

internal sealed class MihomoControllerClient : IDisposable
{
    private const int MaxResponseBytes = 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly TimeSpan _operationTimeout;
    private sealed record MihomoProxyHealthSample(MihomoProxyHealth Health, string HistoryVersion, bool HasMeasurement);
    private sealed record GroupSummary(string Name, string Now, IReadOnlyList<string> All);
    private sealed record ProviderSnapshot(string Provider, IReadOnlyList<MihomoProxyHealth> Candidates, long CapturedAt);
    private readonly SemaphoreSlim _monitorGate = new(1, 1);
    private readonly Dictionary<string, string> _monitoredSelections = new(StringComparer.Ordinal);
    private ProviderSnapshot? _monitoredProvider;
    internal static readonly TimeSpan ProviderReadbackInterval = TimeSpan.FromSeconds(15);

    internal MihomoControllerClient(Uri baseUri, string secret, TimeSpan operationTimeout)
    {
        if (baseUri is null || baseUri.Scheme != Uri.UriSchemeHttp || !IPAddress.TryParse(baseUri.Host, out var address) ||
            !IPAddress.IsLoopback(address) || baseUri.Port is < 1024 or > 65535 || baseUri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        if (string.IsNullOrWhiteSpace(secret) || secret.Length is < 32 or > 256 || secret.Any(char.IsControl))
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        if (operationTimeout < TimeSpan.FromMilliseconds(250) || operationTimeout > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        _baseUri = baseUri;
        _operationTimeout = operationTimeout;
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromMilliseconds(Math.Min(2000, operationTimeout.TotalMilliseconds)),
            MaxConnectionsPerServer = Math.Clamp(Environment.ProcessorCount, 4, 16),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(15),
        };
        _http = new HttpClient(handler) { BaseAddress = baseUri, Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("Bifrost-Service/2.1.0");
    }

    internal async Task WaitReadyAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow.Add(_operationTimeout);
        Exception? last = null;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var document = await ReadJsonAsync(HttpMethod.Get, "version", null, cancellationToken).ConfigureAwait(false);
                RequireExact(document.RootElement, "meta", "version");
                if (!Boolean(document.RootElement, "meta") || String(document.RootElement, "version") != "v1.19.30")
                    throw new InvalidDataException("BF-MIHOMO-VERSION");
                return;
            }
            catch (InvalidDataException error) when (error.Message == "BF-MIHOMO-CONTROLLER-AUTH") { throw; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) { last = error; }
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidDataException(last is InvalidDataException failure ? failure.Message : "BF-MIHOMO-CONTROLLER");
    }

    internal Task TriggerProviderHealthAsync(string provider, CancellationToken cancellationToken) =>
        ExpectNoContentAsync(HttpMethod.Get, $"providers/proxies/{Escape(provider)}/healthcheck", null, cancellationToken);

    internal Task RefreshProviderAsync(string provider, CancellationToken cancellationToken) =>
        ExpectNoContentAsync(HttpMethod.Put, $"providers/proxies/{Escape(provider)}", Array.Empty<byte>(), cancellationToken);

    internal Task SelectAsync(string group, string candidate, CancellationToken cancellationToken)
    {
        SafeName(group); SafeName(candidate);
        var body = JsonSerializer.SerializeToUtf8Bytes(new { name = candidate });
        return ExpectNoContentAsync(HttpMethod.Put, $"proxies/{Escape(group)}", body, cancellationToken);
    }

    internal async Task<int> CloseConnectionsUsingProxyAsync(
        string group,
        string candidate,
        Func<string, bool> shouldCloseHost,
        CancellationToken cancellationToken)
    {
        SafeName(group); SafeName(candidate);
        ArgumentNullException.ThrowIfNull(shouldCloseHost);
        using var document = await ReadJsonAsync(HttpMethod.Get, "connections", null, cancellationToken)
            .ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("connections", out var connections) ||
            connections.ValueKind != JsonValueKind.Array || connections.GetArrayLength() > 4096)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");

        // Do not use DELETE /connections: a throughput handoff must not tear
        // down unrelated authenticated sessions or downloads. Select only
        // large, established media flows that still traverse both the active
        // selector and its previous leaf candidate.
        var ids = new List<string>();
        foreach (var connection in connections.EnumerateArray())
        {
            if (connection.ValueKind != JsonValueKind.Object ||
                !connection.TryGetProperty("id", out var idNode) || idNode.ValueKind != JsonValueKind.String ||
                idNode.GetString() is not { Length: > 0 and <= 128 } id || id.Any(char.IsControl) ||
                id.Contains('/') || id.Contains('\\') ||
                !connection.TryGetProperty("download", out var downloadNode) ||
                !downloadNode.TryGetInt64(out var download) || download < 256 * 1024 ||
                !connection.TryGetProperty("chains", out var chainsNode) || chainsNode.ValueKind != JsonValueKind.Array ||
                !connection.TryGetProperty("metadata", out var metadata) || metadata.ValueKind != JsonValueKind.Object)
                continue;
            var chains = chainsNode.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Cast<string>()
                .ToArray();
            if (!chains.Contains(group, StringComparer.OrdinalIgnoreCase) ||
                !chains.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                continue;
            var host = metadata.TryGetProperty("host", out var hostNode) && hostNode.ValueKind == JsonValueKind.String
                ? hostNode.GetString() ?? "" : "";
            if (!shouldCloseHost(host)) continue;
            ids.Add(id);
            if (ids.Count >= 24) break;
        }

        var closed = 0;
        foreach (var id in ids)
        {
            await ExpectNoContentAsync(HttpMethod.Delete, $"connections/{Uri.EscapeDataString(id)}", null,
                cancellationToken).ConfigureAwait(false);
            closed++;
        }
        return closed;
    }

    internal async Task<MihomoGroupState> ReadGroupAsync(string group, string provider, CancellationToken cancellationToken,
        IReadOnlySet<string>? allowedCandidates = null, string? fixedCandidate = null)
    {
        SafeName(group); SafeName(provider);
        var summary = await ReadGroupSummaryAsync(group, cancellationToken).ConfigureAwait(false);
        if (allowedCandidates is not null) ValidateGroupMembership(summary, allowedCandidates, fixedCandidate);
        var candidates = await ReadCandidatesAsync(provider, allowedCandidates?.ToArray() ?? summary.All, cancellationToken).ConfigureAwait(false);
        return new MihomoGroupState(summary.Name, summary.Now, candidates);
    }

    private static void ValidateGroupMembership(GroupSummary summary, IReadOnlySet<string> allowed, string? fixedCandidate)
    {
        var matches = fixedCandidate is null ? allowed.SetEquals(summary.All)
            : allowed.Contains(fixedCandidate) && summary.All.Count == 1 && summary.All[0] == fixedCandidate && summary.Now == fixedCandidate;
        if (!matches) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
    }

    private async Task<GroupSummary> ReadGroupSummaryAsync(string group, CancellationToken cancellationToken)
    {
        SafeName(group);
        using var document = await ReadJsonAsync(HttpMethod.Get, $"proxies/{Escape(group)}", null, cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        var type = String(root, "type");
        // The pinned core's manual Selector omits expectedStatus/fixed. Those
        // fields belong to URLTest/Fallback; requiring them blocked global mode.
        if (type == "Selector")
            RequireExact(root, "alive", "all", "dialer-proxy", "emptyFallback", "extra", "hidden",
                "history", "icon", "interface", "mptcp", "name", "now", "provider-name", "routing-mark", "smux", "testUrl",
                "tfo", "type", "udp", "uot", "xudp");
        else if (type is "URLTest" or "Fallback")
            RequireExact(root, "alive", "all", "dialer-proxy", "emptyFallback", "expectedStatus", "extra", "fixed", "hidden",
                "history", "icon", "interface", "mptcp", "name", "now", "provider-name", "routing-mark", "smux", "testUrl",
                "tfo", "type", "udp", "uot", "xudp");
        else throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var name = String(root, "name");
        if (!string.Equals(name, group, StringComparison.Ordinal)) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var now = String(root, "now");
        if (now is "DIRECT" or "COMPATIBLE" or "REJECT" || string.IsNullOrWhiteSpace(now))
            throw new InvalidDataException("BF-MIHOMO-DIRECT-FALLBACK");
        var all = StringArray(root, "all");
        if (all.Count is < 1 or > 600 || all.Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Count ||
            !all.Contains(now, StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        return new GroupSummary(name, now, all);
    }

    // Monitoring shares one validated provider snapshot across the ordinary
    // and affinity groups. Startup and explicit measurements above remain fresh.
    // Selected/pinned members are read every tick, so the cache never hides a
    // failed active node for the full catalogue refresh interval.
    internal async Task<MihomoGroupState> ReadMonitoredGroupAsync(string group, string provider,
        IReadOnlySet<string> allowed, CancellationToken cancellationToken, bool force = false, string? pinnedCandidate = null,
        string? fixedCandidate = null)
    {
        SafeName(provider);
        await _monitorGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var summary = await ReadGroupSummaryAsync(group, cancellationToken).ConfigureAwait(false);
            ValidateGroupMembership(summary, allowed, fixedCandidate);
            if (pinnedCandidate is not null && !allowed.Contains(pinnedCandidate))
                throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
            var snapshot = _monitoredProvider;
            var selectionChanged = _monitoredSelections.TryGetValue(group, out var previous) && previous != summary.Now;
            if (force || selectionChanged || snapshot is null || snapshot.Provider != provider ||
                Stopwatch.GetElapsedTime(snapshot.CapturedAt) >= ProviderReadbackInterval ||
                !allowed.SetEquals(snapshot.Candidates.Select(candidate => candidate.Name)))
            {
                var candidates = await ReadCandidatesAsync(provider, allowed.ToArray(), cancellationToken).ConfigureAwait(false);
                snapshot = new ProviderSnapshot(provider, candidates, Stopwatch.GetTimestamp());
            }
            else
            {
                snapshot = await RefreshMemberAsync(snapshot, summary.Now, cancellationToken).ConfigureAwait(false);
            }
            if (pinnedCandidate is not null && pinnedCandidate != summary.Now)
                snapshot = await RefreshMemberAsync(snapshot, pinnedCandidate, cancellationToken).ConfigureAwait(false);
            _monitoredProvider = snapshot;
            _monitoredSelections[group] = summary.Now;
            return new MihomoGroupState(summary.Name, summary.Now, snapshot.Candidates);
        }
        catch
        {
            // An interrupted or invalid response is never reusable evidence.
            _monitoredProvider = null;
            throw;
        }
        finally { _monitorGate.Release(); }
    }

    private async Task<ProviderSnapshot> RefreshMemberAsync(ProviderSnapshot snapshot, string name, CancellationToken cancellationToken)
    {
        using var document = await ReadJsonAsync(HttpMethod.Get,
            $"providers/proxies/{Escape(snapshot.Provider)}/{Escape(name)}", null, cancellationToken).ConfigureAwait(false);
        var health = ParseProviderProxySample(document.RootElement, snapshot.Provider, includeHistoryVersion: false).Health;
        if (health.Name != name) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        var existing = snapshot.Candidates.FirstOrDefault(candidate => candidate.Name == name)
            ?? throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        return existing == health ? snapshot : snapshot with
        {
            Candidates = snapshot.Candidates.Select(candidate => candidate.Name == name ? health : candidate).ToArray()
        };
    }

    internal async Task<MihomoGroupState> WaitForFirstUsableAutomaticGroupAsync(
        string group, string provider, IReadOnlySet<string> allowedCandidates, TimeSpan deadline, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(deadline);
        var labels = allowedCandidates.Order(StringComparer.Ordinal).ToArray();
        while (true)
        {
            try
            {
                var samples = await ReadCandidatesAsync(provider, labels, bounded.Token).ConfigureAwait(false);
                if (samples.Any(candidate => candidate.Alive && candidate.DelayMs is > 0))
                {
                    // Reset URLTest's short-lived selection cache, without pinning
                    // a node or closing existing connections. Its own bounded
                    // health round continues to discover better members.
                    await ExpectNoContentAsync(HttpMethod.Delete, $"proxies/{Escape(group)}", null, bounded.Token).ConfigureAwait(false);
                    var state = await ReadGroupAsync(group, provider, bounded.Token).ConfigureAwait(false);
                    if (allowedCandidates.Contains(state.Now) && state.Candidates.Any(candidate => candidate.Name == state.Now && candidate.Alive && candidate.DelayMs is > 0))
                        return state;
                }
            }
            catch (InvalidDataException error) when (error.Message is "BF-MIHOMO-PROVIDER-NOT-READY" or "BF-MIHOMO-DIRECT-FALLBACK") { }
            await Task.Delay(150, bounded.Token).ConfigureAwait(false);
        }
    }

    internal async Task<MihomoGroupState> WaitForHealthyGroupAsync(
        string group,
        string provider,
        IReadOnlySet<string> allowedCandidates,
        TimeSpan deadline,
        CancellationToken cancellationToken, string? fixedCandidate = null)
    {
        if (allowedCandidates is null || allowedCandidates.Count is < 1 or > 600 ||
            deadline < TimeSpan.FromMilliseconds(250) || deadline > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("BF-MIHOMO-GROUP");
        var until = DateTime.UtcNow.Add(deadline);
        while (DateTime.UtcNow < until)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var state = await ReadGroupAsync(group, provider, cancellationToken, allowedCandidates, fixedCandidate).ConfigureAwait(false);
                if (!allowedCandidates.Contains(state.Now)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
                if (state.Candidates.Any(candidate => candidate.Alive && candidate.DelayMs is > 0 &&
                    string.Equals(candidate.Name, state.Now, StringComparison.OrdinalIgnoreCase))) return state;
            }
            catch (InvalidDataException failure) when (failure.Message == "BF-MIHOMO-DIRECT-FALLBACK")
            {
                // Mihomo initializes URLTest/Fallback groups with the empty
                // fallback before provider health is committed.  It is a wait
                // state while host routing is still untouched, not permission
                // to route DIRECT and not a terminal source failure.
            }
            catch (InvalidDataException failure) when (failure.Message == "BF-MIHOMO-PROVIDER-NOT-READY")
            {
                // The controller can publish the group before its file
                // provider has finished loading. Treat that narrow condition
                // as the same bounded startup wait instead of failing a
                // healthy source during asynchronous provider initialization.
            }
            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidDataException("BF-SOURCE-ALL-CANDIDATES-DEAD");
    }

    internal async Task<MihomoGroupState> WaitForOptimizedGroupAsync(
        string group,
        string provider,
        IReadOnlySet<string> allowedCandidates,
        IReadOnlyList<MihomoProxyHealth> measuredCandidates,
        int toleranceMilliseconds,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        if (allowedCandidates is null || measuredCandidates is null ||
            allowedCandidates.Count is < 1 or > 600 || measuredCandidates.Count != allowedCandidates.Count ||
            measuredCandidates.Select(candidate => candidate.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != measuredCandidates.Count ||
            !measuredCandidates.Select(candidate => candidate.Name).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(allowedCandidates) ||
            toleranceMilliseconds is < 0 or > 5000 ||
            deadline < TimeSpan.FromMilliseconds(250) || deadline > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("BF-MIHOMO-GROUP");

        var aliveMeasurements = measuredCandidates
            .Where(candidate => candidate.Alive && candidate.DelayMs is > 0)
            .ToArray();
        if (aliveMeasurements.Length == 0) throw new InvalidDataException("BF-SOURCE-ALL-CANDIDATES-DEAD");
        var bestDelay = aliveMeasurements.Min(candidate => candidate.DelayMs!.Value);
        var acceptable = aliveMeasurements
            .Where(candidate => candidate.DelayMs!.Value <= bestDelay + toleranceMilliseconds)
            .Select(candidate => candidate.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var until = DateTime.UtcNow.Add(deadline);
        while (DateTime.UtcNow < until)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var state = await ReadGroupAsync(group, provider, cancellationToken).ConfigureAwait(false);
                if (!allowedCandidates.Contains(state.Now)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
                if (acceptable.Contains(state.Now) && state.Candidates.Any(candidate => candidate.Alive &&
                    string.Equals(candidate.Name, state.Now, StringComparison.OrdinalIgnoreCase))) return state;
            }
            catch (InvalidDataException failure) when (failure.Message == "BF-MIHOMO-DIRECT-FALLBACK")
            {
                // Route ownership has not been committed yet. REJECT is the
                // safe startup state while URLTest publishes its measured
                // winner; it is never converted into first-item selection.
            }
            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidDataException("BF-MIHOMO-GROUP-NOT-OPTIMIZED");
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> ReadCandidatesAsync(
        string provider,
        IReadOnlyList<string> candidates,
        CancellationToken cancellationToken) =>
        (await ReadCandidateSamplesAsync(provider, candidates, cancellationToken, includeHistoryVersion: false).ConfigureAwait(false))
            .Select(sample => sample.Health).ToArray();

    private async Task<IReadOnlyList<MihomoProxyHealthSample>> ReadCandidateSamplesAsync(
        string provider,
        IReadOnlyList<string> candidates,
        CancellationToken cancellationToken, bool includeHistoryVersion = true)
    {
        SafeName(provider);
        if (candidates is null || candidates.Count is < 1 or > 600 ||
            candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        foreach (var candidate in candidates) SafeName(candidate);
        using var document = await ReadJsonAsync(HttpMethod.Get, $"providers/proxies/{Escape(provider)}", null, cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        RequireExact(root, "name", "type", "vehicleType", "proxies", "testUrl", "expectedStatus", "updatedAt");
        if (String(root, "name") != provider || String(root, "type") != "Proxy" || String(root, "vehicleType").Length == 0)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        if (!root.TryGetProperty("proxies", out var proxies) || proxies.ValueKind != JsonValueKind.Array || proxies.GetArrayLength() > 600)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var allowed = candidates.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<MihomoProxyHealthSample>();
        foreach (var proxy in proxies.EnumerateArray())
        {
            var parsed = ParseProviderProxySample(proxy, provider, includeHistoryVersion);
            if (!allowed.Contains(parsed.Health.Name)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
            result.Add(parsed);
        }
        var names = result.Select(item => item.Health.Name).ToArray();
        if (names.Distinct(StringComparer.OrdinalIgnoreCase).Count() != names.Length)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        if (result.Count != candidates.Count || !names.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(allowed))
            throw new InvalidDataException("BF-MIHOMO-PROVIDER-NOT-READY");
        return result;
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureCandidatesInBatchesAsync(
        string provider, IReadOnlyList<string> candidates, Func<MihomoProxyHealth, Task>? progress,
        CancellationToken cancellationToken, Func<CancellationToken, Task>? beforeBatch = null)
    {
        // Validate exact provider membership before addressing any proxy name.
        using var readyDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        readyDeadline.CancelAfter(TimeSpan.FromSeconds(5));
        while (true)
        {
            try { await ReadCandidatesAsync(provider, candidates, readyDeadline.Token).ConfigureAwait(false); break; }
            catch (InvalidDataException error) when (error.Message == "BF-MIHOMO-PROVIDER-NOT-READY")
            { await Task.Delay(100, readyDeadline.Token).ConfigureAwait(false); }
        }
        var completed = new Dictionary<string, MihomoProxyHealth>(StringComparer.OrdinalIgnoreCase);
        using var round = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        foreach (var batch in candidates.Chunk(12))
        {
            round.Token.ThrowIfCancellationRequested();
            if (beforeBatch is not null) await beforeBatch(round.Token).ConfigureAwait(false);
            var pending = batch.Select(candidate => MeasureCandidateAsync(provider, candidate, round.Token)).ToList();
            try
            {
                while (pending.Count > 0)
                {
                    var finished = await Task.WhenAny(pending).ConfigureAwait(false);
                    pending.Remove(finished);
                    var result = await finished.ConfigureAwait(false);
                    completed.Add(result.Name, result);
                    if (progress is not null) await progress(result).ConfigureAwait(false);
                }
            }
            finally
            {
                if (pending.Count > 0)
                {
                    round.Cancel();
                    try { await Task.WhenAll(pending).ConfigureAwait(false); } catch { }
                }
            }
        }
        return candidates.Select(candidate => completed[candidate]).ToArray();
    }

    internal async Task<MihomoProxyHealth> MeasureVerifiedCandidateAsync(string provider, string candidate,
        IReadOnlySet<string> allowedCandidates, CancellationToken cancellationToken)
    {
        if (!allowedCandidates.Contains(candidate)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        await ReadCandidatesAsync(provider, allowedCandidates.ToArray(), cancellationToken).ConfigureAwait(false);
        return await MeasureCandidateAsync(provider, candidate, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureVerifiedCandidatesAsync(string provider,
        IReadOnlyList<string> candidates, IReadOnlySet<string> allowedCandidates, CancellationToken cancellationToken)
    {
        // Startup throughput qualification deliberately covers the complete
        // current A/B source (29 endpoints) in one bounded cohort.  Keep this
        // ceiling aligned with that startup contract; the old 12-member limit
        // made every >12-node startup fail before the first payload sample.
        const int maximumVerifiedCohort = 32;
        if (candidates.Count is < 1 or > maximumVerifiedCohort ||
            candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count ||
            candidates.Any(candidate => !allowedCandidates.Contains(candidate)))
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        // One fresh, exact provider validation authorizes this bounded batch.
        // Do not download and parse all 600 histories again for each member
        // of the optimizer's current/challenger pair. Health probes themselves
        // remain fresh and sequential, so this adds no competing transfers.
        await ReadCandidatesAsync(provider, allowedCandidates.ToArray(), cancellationToken).ConfigureAwait(false);
        var results = new List<MihomoProxyHealth>(candidates.Count);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await MeasureCandidateAsync(provider, candidate, cancellationToken).ConfigureAwait(false));
        }
        return results;
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureStartupCandidatesAsync(string provider,
        IReadOnlyList<string> candidates, IReadOnlySet<string> allowedCandidates,
        CancellationToken cancellationToken)
    {
        // The first URLTest winner can arrive before the provider has populated
        // health histories for the rest of the catalogue. Verify membership
        // once, then check a small startup shortlist concurrently; serial
        // five-second checks would exhaust the entire qualification window.
        if (candidates.Count is < 1 or > 8 ||
            candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count ||
            candidates.Any(candidate => !allowedCandidates.Contains(candidate)))
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        await ReadCandidatesAsync(provider, allowedCandidates.ToArray(), cancellationToken).ConfigureAwait(false);
        return await Task.WhenAll(candidates.Select(candidate =>
            MeasureCandidateAsync(provider, candidate, cancellationToken))).ConfigureAwait(false);
    }

    private async Task<MihomoProxyHealth> MeasureCandidateAsync(string provider, string candidate, CancellationToken cancellationToken)
    {
        SafeName(candidate);
        var relative = $"providers/proxies/{Escape(provider)}/{Escape(candidate)}/healthcheck?url={Uri.EscapeDataString(MihomoWindowsContract.StartupProbeUrl)}&timeout=5000&expected={MihomoWindowsContract.StartupProbeExpectedStatus}";
        using var response = await SendAsync(HttpMethod.Get, relative, null, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-AUTH");
        if (response.StatusCode is HttpStatusCode.GatewayTimeout or HttpStatusCode.ServiceUnavailable)
            return new MihomoProxyHealth(candidate, false, null);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-STATUS");
        using var document = JsonDocument.Parse(await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false));
        RequireExact(document.RootElement, "delay");
        if (!document.RootElement.GetProperty("delay").TryGetInt32(out var delay) || delay is < 1 or > 65535)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        return new MihomoProxyHealth(candidate, true, delay);
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureGroupAsync(
        string group,
        IReadOnlyList<string> candidates,
        CancellationToken cancellationToken)
    {
        SafeName(group);
        if (candidates is null || candidates.Count is < 1 or > 600 ||
            candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        foreach (var candidate in candidates) SafeName(candidate);
        // Startup, provider health, and URLTest deliberately share one probe
        // target.  The production graph resolves www.gstatic.com through the
        // direct bootstrap DNS path, so startup does not depend on the group
        // that is still selecting its first winner.
        const string testUrl = MihomoWindowsContract.StartupProbeUrl;
        var relative = $"group/{Escape(group)}/delay?url={Uri.EscapeDataString(testUrl)}&timeout=5000&expected={MihomoWindowsContract.StartupProbeExpectedStatus}";
        using var response = await SendAsync(HttpMethod.Get, relative, null, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-AUTH");
        if (response.StatusCode == HttpStatusCode.GatewayTimeout)
            return candidates.Select(candidate => new MihomoProxyHealth(candidate, false, null)).ToArray();
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-STATUS");
        var responseBytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        JsonDocument document;
        try { document = JsonDocument.Parse(responseBytes); }
        catch (JsonException) { throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON"); }
        using (document)
        {
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var allowed = candidates.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var measured = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!allowed.Contains(property.Name) || property.Value.ValueKind != JsonValueKind.Number ||
                !property.Value.TryGetInt32(out var delay) || delay < 0 || delay > 65535 || !measured.TryAdd(property.Name, delay))
                throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        }
        return candidates.Select(candidate => measured.TryGetValue(candidate, out var delay) && delay > 0
            ? new MihomoProxyHealth(candidate, true, delay)
            : new MihomoProxyHealth(candidate, false, null)).ToArray();
        }
    }

    internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureGroupUntilUsableAsync(
        string group,
        string provider,
        IReadOnlyList<string> candidates,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        SafeName(group); SafeName(provider);
        if (deadline < TimeSpan.FromSeconds(1) || deadline > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("BF-MIHOMO-GROUP");
        using var startupDeadline = new CancellationTokenSource(deadline);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, startupDeadline.Token);
        IReadOnlyList<MihomoProxyHealth> last = candidates.Select(candidate => new MihomoProxyHealth(candidate, false, null)).ToArray();
        var baseline = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Task? healthRound = null;
        try
        {
            // Capture the provider history before triggering the new round. A
            // second manual test must not accept the previous round's positive
            // history as if it were a fresh measurement.
            try
            {
                var previous = await ReadCandidateSamplesAsync(provider, candidates, linked.Token).ConfigureAwait(false);
                foreach (var sample in previous) baseline[sample.Health.Name] = sample.HistoryVersion;
            }
            catch (InvalidDataException failure) when (failure.Message == "BF-MIHOMO-PROVIDER-NOT-READY")
            {
                // A fresh transient Mihomo process can expose /version before
                // its file provider has loaded. There is no reusable baseline
                // in that state; the first complete provider snapshot belongs
                // to this round.
            }

            // Use one official provider health round for every source. This is
            // route-neutral, uses the same signed test URL/timeout for A and B,
            // and preserves per-candidate partial failures instead of letting a
            // single slow member turn the group delay endpoint into one 504.
            // Mihomo can hold this request open until every queued member has
            // finished. Poll concurrently so one slow tail cannot discard all
            // successful rows when the batch deadline expires.
            healthRound = TriggerProviderHealthAsync(provider, linked.Token);
            while (true)
            {
                linked.Token.ThrowIfCancellationRequested();
                if (healthRound.IsCompleted) await healthRound.ConfigureAwait(false);
                IReadOnlyList<MihomoProxyHealthSample> samples;
                try { samples = await ReadCandidateSamplesAsync(provider, candidates, linked.Token).ConfigureAwait(false); }
                catch (InvalidDataException failure) when (failure.Message == "BF-MIHOMO-PROVIDER-NOT-READY")
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(100), linked.Token).ConfigureAwait(false);
                    continue;
                }
                last = samples.Select(sample => sample.HasMeasurement &&
                    (!baseline.TryGetValue(sample.Health.Name, out var old) || sample.HistoryVersion != old)
                        ? sample.Health : new MihomoProxyHealth(sample.Health.Name, false, null)).ToArray();
                var freshRound = samples.Count == candidates.Count && samples.All(sample =>
                    sample.HasMeasurement && (!baseline.TryGetValue(sample.Health.Name, out var previousVersion) ||
                    !string.Equals(sample.HistoryVersion, previousVersion, StringComparison.Ordinal)));
                if (freshRound) return last;
                await Task.Delay(TimeSpan.FromMilliseconds(100), linked.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && startupDeadline.IsCancellationRequested)
        {
            return last;
        }
        finally
        {
            startupDeadline.Cancel();
            if (healthRound is not null)
                try { await healthRound.ConfigureAwait(false); }
                catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        }
    }

    internal async Task<IReadOnlyList<MihomoRuleReadback>> ReadRulesAsync(CancellationToken cancellationToken)
    {
        using var document = await ReadJsonAsync(HttpMethod.Get, "rules", null, cancellationToken).ConfigureAwait(false);
        RequireExact(document.RootElement, "rules");
        if (!document.RootElement.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array || rules.GetArrayLength() > 4096)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var result = new List<MihomoRuleReadback>();
        foreach (var rule in rules.EnumerateArray())
        {
            RequireExact(rule, "type", "payload", "proxy", "size");
            result.Add(new MihomoRuleReadback(String(rule, "type"), String(rule, "payload"), String(rule, "proxy")));
        }
        return result;
    }

    private static MihomoProxyHealthSample ParseProviderProxySample(JsonElement root, string provider, bool includeHistoryVersion = true)
    {
        RequireExact(root, "alive", "dialer-proxy", "extra", "history", "id", "interface", "mptcp", "name",
            "provider-name", "routing-mark", "smux", "tfo", "type", "udp", "uot", "xudp");
        var candidate = String(root, "name");
        if (String(root, "type").Length == 0 || String(root, "provider-name") != provider)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        var alive = Boolean(root, "alive");
        if (!root.TryGetProperty("history", out var history) || history.ValueKind != JsonValueKind.Array || history.GetArrayLength() > 64)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        int? delay = null;
        var historyVersion = includeHistoryVersion ? new StringBuilder() : null;
        foreach (var item in history.EnumerateArray())
        {
            RequireExact(item, "time", "delay");
            var time = item.GetProperty("time");
            if (time.ValueKind != JsonValueKind.String || time.ValueEquals(""))
                throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
            if (!item.TryGetProperty("delay", out var delayNode) || delayNode.ValueKind != JsonValueKind.Number ||
                !delayNode.TryGetInt32(out var value) || value < 0 || value > 65535)
                throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
            historyVersion?.Append(time.GetString()).Append('\u001f').Append(value).Append('\u001e');
            if (value > 0) delay = value;
        }
        var health = new MihomoProxyHealth(candidate, alive, alive ? delay : null);
        // Alive is part of the version because Mihomo may flip availability
        // before a history append is visible through the provider endpoint.
        return new MihomoProxyHealthSample(health, includeHistoryVersion ? $"{alive}:{historyVersion}" : "", history.GetArrayLength() > 0);
    }

    private async Task ExpectNoContentAsync(HttpMethod method, string relative, byte[]? body, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(method, relative, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-AUTH");
        if (response.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-STATUS");
    }

    private async Task<JsonDocument> ReadJsonAsync(HttpMethod method, string relative, byte[]? body, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(method, relative, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-AUTH");
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-STATUS");
        var bytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 16 });
        }
        catch (JsonException) { throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON"); }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string relative, byte[]? body, CancellationToken cancellationToken)
    {
        if (relative.Contains("..", StringComparison.Ordinal) || relative.StartsWith('/')) throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_operationTimeout);
        var request = new HttpRequestMessage(method, new Uri(_baseUri, relative));
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        try { return await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new InvalidDataException("BF-MIHOMO-CONTROLLER"); }
        finally { request.Dispose(); }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaxResponseBytes) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-LIMIT");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (memory.Length + read > MaxResponseBytes) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-LIMIT");
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }

    private static void RequireExact(JsonElement element, params ReadOnlySpan<string> fields)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        ulong seen = 0;
        foreach (var property in element.EnumerateObject())
        {
            var index = 0;
            while (index < fields.Length && !property.NameEquals(fields[index])) index++;
            if (index == fields.Length || (seen & (1UL << index)) != 0)
                throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
            seen |= 1UL << index;
        }
        if (seen != (1UL << fields.Length) - 1)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
    }

    private static string String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text
            ? text : throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");

    private static bool Boolean(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean() : throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");

    private static IReadOnlyList<string> StringArray(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON");
        return value.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } text
            ? text : throw new InvalidDataException("BF-MIHOMO-CONTROLLER-JSON")).ToArray();
    }

    private static string Escape(string value) { SafeName(value); return Uri.EscapeDataString(value); }
    private static void SafeName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(char.IsControl) || value.Contains('/') || value.Contains('\\'))
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
    }

    public void Dispose() => _http.Dispose();
}
