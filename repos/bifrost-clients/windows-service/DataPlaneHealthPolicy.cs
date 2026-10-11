using System.Text;

namespace Bifrost.ClientService;

internal static class DataPlaneHealthPolicy
{
    internal static readonly TimeSpan TransientFailureWindow = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan EndpointTimeout = TimeSpan.FromSeconds(6);

    // A healthy but slower endpoint, or one unreachable public site, must not
    // be mistaken for a dead tunnel. Keep a successful endpoint sticky and
    // consult the independent endpoint only when the preferred one fails.
    internal static (bool Healthy, string Code, int Preferred) ProbeWithFallback(int preferred,
        Func<int, TimeSpan, CancellationToken, (bool Healthy, string Code)> probe,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        preferred = preferred == 1 ? 1 : 0;
        var first = probe(preferred, EndpointTimeout, cancellationToken);
        if (first.Healthy || first.Code == "BF-TUN-ROUTE")
            return (first.Healthy, first.Code, preferred);
        cancellationToken.ThrowIfCancellationRequested();
        var second = probe(1 - preferred, EndpointTimeout, cancellationToken);
        return second.Healthy ? (true, "BF-OK", 1 - preferred)
            : (false, first.Code + "+" + second.Code, preferred);
    }

    // A timeout of a remote TLS endpoint is not independent evidence that the
    // tunnel is broken. Keep a bounded observation window while its owner and
    // selected node are still healthy. Ownership loss never receives a grace.
    internal static bool ShouldDisconnect(int failures, TimeSpan elapsed, bool force,
        bool routeOwnershipLost, bool fastFailure, int threshold) =>
        force || routeOwnershipLost ||
        (failures >= threshold && (fastFailure || elapsed >= TransientFailureWindow));

    internal static bool IsFastFailure(string code) =>
        code.StartsWith("BF-TRANSPORT-PROBE-TCP", StringComparison.Ordinal) ||
        code.StartsWith("BF-TRANSPORT-PROBE-PROXY", StringComparison.Ordinal);

    internal static async Task<bool> Read204ResponseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[8192];
        var count = 0;
        while (count < header.Length)
        {
            var read = await stream.ReadAsync(header.AsMemory(count), cancellationToken).ConfigureAwait(false);
            if (read == 0) return false;
            var previous = count;
            count += read;
            for (var end = Math.Max(3, previous); end < count; end++)
            {
                if (header[end - 3] != '\r' || header[end - 2] != '\n' ||
                    header[end - 1] != '\r' || header[end] != '\n') continue;
                var lineEnd = Array.IndexOf(header, (byte)'\r', 0, end + 1);
                if (lineEnd < 12) return false;
                var status = Encoding.ASCII.GetString(header, 0, lineEnd);
                return (status.StartsWith("HTTP/1.1 204", StringComparison.Ordinal) ||
                        status.StartsWith("HTTP/1.0 204", StringComparison.Ordinal)) &&
                       (status.Length == 12 || status[12] == ' ');
            }
        }
        return false;
    }
}
