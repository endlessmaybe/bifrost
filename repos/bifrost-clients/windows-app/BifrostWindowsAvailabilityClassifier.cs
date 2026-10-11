using System.Net.Http;
using System.IO;
using System.Net;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading;

namespace Bifrost;

internal class BifrostWindowsReachableStatusException : IOException
{
    public BifrostWindowsReachableStatusException(int status, Exception? inner = null) : base($"BF-CONTROL-{status}", inner) => Status = status;
    public int Status { get; }
}

internal sealed class BifrostWindowsRetryableStatusException : BifrostWindowsReachableStatusException
{
    public BifrostWindowsRetryableStatusException(int status, Exception? inner = null) : base(status, inner) { }
}

/// <summary>
/// Offline LKG is deliberately a very small allow-list.  Reachable control
/// responses and all protocol/crypto/state failures remain blocking errors.
/// </summary>
internal static class BifrostWindowsAvailabilityClassifier
{
    public static bool CanUseOffline(Exception error, CancellationToken callerCancellationToken = default)
    {
        var transport = false;
        var retryableStatus = false;
        var denied = false;
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is OperationCanceledException && callerCancellationToken.IsCancellationRequested)
                return false;
            if (current is AuthenticationException or CryptographicException or SecurityException or InvalidDataException or ProtocolViolationException)
                return false;
            if (current is BifrostWindowsRetryableStatusException) retryableStatus = true;
            if (current is BifrostWindowsReachableStatusException && current is not BifrostWindowsRetryableStatusException) denied = true;
            if (current is HttpRequestException requestError)
            {
                if (requestError.StatusCode is HttpStatusCode status)
                    denied = true;
                else
                    transport = true;
            }
            else if (current is TaskCanceledException or TimeoutException)
            {
                // RefreshAsync passes its caller token.  A canceled caller is
                // never an offline success; an un-canceled TaskCanceledException
                // here is the HttpClient request deadline.
                if (callerCancellationToken.IsCancellationRequested) return false;
                transport = true;
            }
            if (current is InvalidOperationException or InvalidDataException)
            {
                var code = current.Message.Split(new[] { ':', ' ' }, 2, StringSplitOptions.RemoveEmptyEntries)[0];
                if (code.StartsWith("BF-CONTROL-4", StringComparison.Ordinal) ||
                    code is "BF-CONTROL-REDIRECT" or "BF-CONTROL-JSON" or "BF-CONTROL-CONTENT-TYPE" or "BF-CONTROL-RESPONSE-LIMIT" ||
                    code.StartsWith("BF-CONFIG-", StringComparison.Ordinal) ||
                    code.StartsWith("BF-AUTH-", StringComparison.Ordinal) ||
                    code.StartsWith("BF-CRYPTO-", StringComparison.Ordinal) ||
                    code.StartsWith("BF-KEYS-", StringComparison.Ordinal))
                    return false;
            }
        }
        return (transport || retryableStatus) && !denied;
    }
}
