using Bifrost.ClientService;
using System.Text;

static void Assert(bool value, string message) { if (!value) throw new Exception(message); }
static bool Disconnect(int failures, double seconds, bool fast = false, bool force = false, bool lost = false) =>
    DataPlaneHealthPolicy.ShouldDisconnect(failures, TimeSpan.FromSeconds(seconds), force, lost, fast, fast ? 2 : 3);
Assert(!DataPlaneHealthPolicy.IsFastFailure("BF-TRANSPORT-PROBE-TLS-TIMEOUT"), "TLS jitter is not a local reachability failure");
Assert(!Disconnect(2, 4.7) && !Disconnect(4, 14.9), "23:13 TLS timeout incident must retain the owned tunnel");
Assert(Disconnect(5, 16), "Persistent failure must remain bounded");
Assert(!Disconnect(1, 30) && Disconnect(2, 2, fast: true), "Independent failure requires repeated evidence");
Assert(Disconnect(1, 0, lost: true) && Disconnect(1, 0, force: true), "Lost ownership and startup remain strict");
var calls = new List<int>();
var fallback = DataPlaneHealthPolicy.ProbeWithFallback(0, (index, budget, token) =>
{
    calls.Add(index);
    Assert(budget >= TimeSpan.FromMilliseconds(5078) && budget <= TimeSpan.FromSeconds(6),
        "A-100 successful 4-5 second responses fit a bounded per-endpoint budget");
    return index == 0 ? (false, "BF-TRANSPORT-PROBE-TLS-TIMEOUT") : (true, "BF-OK");
}, CancellationToken.None);
Assert(fallback.Healthy && fallback.Preferred == 1 && calls.SequenceEqual(new[] {0,1}),
    "One failed external site must not disconnect a route proven by the other endpoint");
calls.Clear();
var sticky = DataPlaneHealthPolicy.ProbeWithFallback(fallback.Preferred, (index, _, _) =>
{ calls.Add(index); return (true, "BF-OK"); }, CancellationToken.None);
Assert(sticky.Healthy && calls.SequenceEqual(new[] {1}), "Healthy fallback is sticky and sends only one request");
var dead = DataPlaneHealthPolicy.ProbeWithFallback(0, (index, _, _) =>
    (false, index == 0 ? "BF-TRANSPORT-PROBE-TLS-TIMEOUT" : "BF-TRANSPORT-PROBE-HTTP"), CancellationToken.None);
Assert(!dead.Healthy && dead.Code.Contains("+BF-TRANSPORT-PROBE-HTTP"), "All-target failure stays failed with both causes");
calls.Clear();
var lost = DataPlaneHealthPolicy.ProbeWithFallback(0, (index, _, _) =>
{ calls.Add(index); return (false, "BF-TUN-ROUTE"); }, CancellationToken.None);
Assert(!lost.Healthy && calls.Count == 1, "Route ownership loss never receives a fallback grace");
using (var stop = new CancellationTokenSource())
{
    try
    {
        DataPlaneHealthPolicy.ProbeWithFallback(0, (index, _, _) =>
        { Assert(index == 0, "Cancellation prevents fallback traffic"); stop.Cancel(); return (false, "BF-TRANSPORT-PROBE-HTTP"); }, stop.Token);
        throw new Exception("Cancelled probe started its fallback");
    }
    catch (OperationCanceledException) { }
}
foreach (var fragment in new[] { 1, 2, 7, 13, 128 })
{
    using var stream = new FragmentedStream("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", fragment);
    Assert(await DataPlaneHealthPolicy.Read204ResponseAsync(stream, CancellationToken.None), $"Valid fragmented header rejected: {fragment}");
}
foreach (var invalid in new[] { "HTTP/1.1 204", "HTTP/1.1 2040 Wrong\r\n\r\n", "HTTP/1.1 503 Unavailable\r\n\r\n", "HTTP/1.1 204 No Content\r\nX: " + new string('x', 9000) })
{
    using var stream = new FragmentedStream(invalid, 3);
    Assert(!await DataPlaneHealthPolicy.Read204ResponseAsync(stream, CancellationToken.None), "Truncated, malformed or oversized header accepted");
}
using (var cancelled = new CancellationTokenSource())
{
    cancelled.Cancel();
    using var stream = new FragmentedStream("HTTP/1.1 204 No Content\r\n\r\n", 1);
    try { await DataPlaneHealthPolicy.Read204ResponseAsync(stream, cancelled.Token); throw new Exception("Cancelled read continued"); }
    catch (OperationCanceledException) { }
}
Console.WriteLine("PASS DATAPLANE-HEALTH incident replay, bounded failure, route loss, fragmented HTTP and cancellation");

sealed class FragmentedStream(string text, int fragment) : MemoryStream(Encoding.ASCII.GetBytes(text))
{
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return base.ReadAsync(buffer[..Math.Min(fragment, buffer.Length)], cancellationToken);
    }
}
