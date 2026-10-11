using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bifrost.ClientService;

namespace Bifrost;

/// <summary>UI to local-service boundary. The UI carries typed intent and opaque ids only.</summary>
public sealed class ClientServiceContract
{
    public const string PipeName = "BifrostClientService";

    public Task<ServiceStatus> ConnectAsync(string mode = ProtocolCodes.ModeSmart, string core = ProtocolCodes.CoreAuto, string source = "auto", string country = "default", string? configId = null, string appPolicy = "allow", CancellationToken cancellationToken = default, ApplicationPolicySnapshot? applicationPolicySnapshot = null, string connectionType = "direct-vmess")
    {
        var normalizedMode = NormalizeMode(mode);
        var normalizedCore = NormalizeCore(core);
        var normalizedSource = NormalizeSource(source);
        var normalizedCountry = NormalizeCountry(country);
        var selection = ConnectionRouteSelection.Parse(connectionType, normalizedMode);
        if (selection.ConnectionType == global::Bifrost.ConnectionType.DirectVmess && normalizedCountry != "default" ||
            selection.ConnectionType == global::Bifrost.ConnectionType.SmartGate && normalizedCountry == "default")
            throw new ServiceException("BF-CONNECTION-TYPE", "country scope does not match the connection type");
        if (!PipeClientProtocol.IsOpaqueId(configId, "cfg_"))
            throw new ServiceException("BF-CONFIG-PACKAGE", "a service-issued config id is required");
        var snapshot = applicationPolicySnapshot is null
            ? ApplicationPolicySnapshot.Create(normalizedMode, normalizedMode == ProtocolCodes.ModePerApp ? NormalizePolicy(appPolicy) : "none", Array.Empty<string>(), Array.Empty<string>(), "00000000000000000000000000000000")
            : ApplicationPolicySnapshot.Parse(applicationPolicySnapshot.CanonicalJson);
        if (applicationPolicySnapshot is not null && snapshot != applicationPolicySnapshot) throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy snapshot changed");
        if (snapshot.RouteMode != normalizedMode) throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy route changed");
        return SendAsync(new { action = "connect", mode = normalizedMode, connection_type = connectionType, core = normalizedCore, source = normalizedSource, country = normalizedCountry, app_policy = snapshot.PolicyMode, app_policy_snapshot = snapshot.CanonicalJson, app_policy_digest = snapshot.Digest, app_policy_generation = snapshot.Generation, config_id = configId }, cancellationToken, snapshot, PipeClientProtocol.ConnectOperationTimeout);
    }

    public Task<ServiceStatus> StageConfigAsync(SignedClientPackageRequest package, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        var snapshot = ApplicationPolicySnapshot.Parse(package.ApplicationPolicySnapshot.CanonicalJson);
        if (snapshot != package.ApplicationPolicySnapshot)
            throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy snapshot changed");
        if (package.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(package.ConfigContentDigest) ||
            string.IsNullOrWhiteSpace(package.SignedConfigJson) || string.IsNullOrWhiteSpace(package.SignedEnvelopeJson) ||
            string.IsNullOrWhiteSpace(package.ConfigKeyStateJson) || string.IsNullOrWhiteSpace(package.SelectedCandidateLabel))
            throw new ServiceException("BF-CONFIG-SIGNED-PACKAGE-REQUIRED", "a verified Control package is required");
        return SendAsync(new
        {
            action = "stage_config",
            mode = package.Mode,
            connection_type = package.ConnectionType,
            core = package.Core,
            source = package.Source,
            country = package.Country,
            app_policy_snapshot = snapshot.CanonicalJson,
            app_policy_digest = snapshot.Digest,
            app_policy_generation = snapshot.Generation,
            config_version = package.ConfigVersion,
            config_content_digest = package.ConfigContentDigest,
            signed_config_json = package.SignedConfigJson,
            signed_envelope_json = package.SignedEnvelopeJson,
            config_key_state_json = package.ConfigKeyStateJson,
            selected_candidate = package.SelectedCandidateLabel,
            front_source = package.FrontSource,
            front_candidate = package.FrontCandidateLabel,
            bootstrap_proxy_type = package.BootstrapProxyType,
            bootstrap_proxy_port = package.BootstrapProxyPort
        }, cancellationToken);
    }

    public Task<ServiceStatus> DisconnectAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new { action = "disconnect" }, cancellationToken);

    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new { action = "status" }, cancellationToken, allowNonOkStatus: true);

    public Task<ServiceStatus> ApplyPendingUpdateAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new { action = "apply_update" }, cancellationToken);

    public Task MeasureLatencyBatchAsync(
        SignedClientPackageRequest package,
        IReadOnlyList<string> candidateLabels,
        Action<LatencyBatchFrame> progress,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(candidateLabels);
        ArgumentNullException.ThrowIfNull(progress);
        if (package.Mode != ProtocolCodes.ModeGlobal || package.ConnectionType != "direct-vmess" || package.Country != "default" ||
            package.Core is not (ProtocolCodes.CoreAuto or ProtocolCodes.CoreMihomo) ||
            package.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(package.ConfigContentDigest) ||
            string.IsNullOrWhiteSpace(package.SignedConfigJson) || string.IsNullOrWhiteSpace(package.SignedEnvelopeJson) ||
            string.IsNullOrWhiteSpace(package.ConfigKeyStateJson) || candidateLabels.Count is < 1 or > 600)
            throw new ServiceException("BF-LATENCY-CONFIG", "invalid latency batch package");
        var normalizedSource = NormalizeSource(package.Source);
        var snapshot = ApplicationPolicySnapshot.Parse(package.ApplicationPolicySnapshot.CanonicalJson);
        if (snapshot != package.ApplicationPolicySnapshot || snapshot.RouteMode != ProtocolCodes.ModeGlobal ||
            snapshot.PolicyMode != "none" || snapshot.Identities.Count != 0)
            throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy snapshot changed");
        var labels = candidateLabels.Select(label => NormalizeToken(label, "BF-CONFIG-CANDIDATE"))
            .Distinct(StringComparer.Ordinal).ToArray();
        if (labels.Length != candidateLabels.Count)
            throw new ServiceException("BF-LATENCY-CONFIG", "duplicate latency candidate");
        return SendLatencyBatchAsync(new
        {
            action = "latency_batch",
            mode = ProtocolCodes.ModeGlobal,
            connection_type = "direct-vmess",
            core = package.Core,
            source = normalizedSource,
            country = "default",
            app_policy_snapshot = snapshot.CanonicalJson,
            app_policy_digest = snapshot.Digest,
            app_policy_generation = snapshot.Generation,
            config_version = package.ConfigVersion,
            config_content_digest = package.ConfigContentDigest,
            signed_config_json = package.SignedConfigJson,
            signed_envelope_json = package.SignedEnvelopeJson,
            config_key_state_json = package.ConfigKeyStateJson,
            candidates = labels,
        }, progress, cancellationToken);
    }

    private static string NormalizeMode(string value) => value switch
    {
        ProtocolCodes.ModeSmart or ProtocolCodes.ModeGlobal or ProtocolCodes.ModePerApp => value,
        _ => throw new ServiceException("BF-CONFIG-MODE", "unsupported route mode")
    };

    private static string NormalizeCore(string value) => value switch
    {
        ProtocolCodes.CoreAuto or ProtocolCodes.CoreMihomo => value,
        _ => throw new ServiceException("BF-CONFIG-CORE", "unsupported core")
    };

    private static string NormalizeSource(string value)
    {
        if (string.Equals(value, "auto", StringComparison.OrdinalIgnoreCase))
            throw new ServiceException("BF-CONFIG-SOURCE", "an explicit source is required");
        return NormalizeToken(value, "BF-CONFIG-SOURCE");
    }

    private static string NormalizeCountry(string value) =>
        string.Equals(value, "default", StringComparison.Ordinal) ? value : NormalizeToken(value, "BF-CONFIG-COUNTRY");

    private static string NormalizeToken(string value, string code)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 96 ||
            value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.')))
            throw new ServiceException(code, "invalid typed identifier");
        return value;
    }

    internal static string NormalizePolicy(string value) => value.Trim().ToLowerInvariant() switch
    {
        "none" or "allow" or "exclude" => value.Trim().ToLowerInvariant(),
        _ => throw new ServiceException("BF-APP-POLICY", "unsupported application policy")
    };

    private static async Task<ServiceStatus> SendAsync(object command, CancellationToken cancellationToken, ApplicationPolicySnapshot? expectedPolicy = null, TimeSpan? operationTimeout = null, bool allowNonOkStatus = false)
    {
        try
        {
            using var binding = PipeClientProtocol.LoadBinding();
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(operationTimeout ?? PipeClientProtocol.OperationTimeout);
            await pipe.ConnectAsync(5000, deadline.Token).ConfigureAwait(false);
            using var challenge = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
            var parsed = PipeClientProtocol.ParseChallenge(challenge.RootElement, binding);
            await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "auth", version = 1, sid = binding.Sid, nonce = parsed.Nonce, counter = 1, mac = PipeClientProtocol.Mac(binding.Secret, $"auth|{parsed.Nonce}|{binding.Sid}|1") }, deadline.Token).ConfigureAwait(false);

            var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(command, JsonOptions);
            try
            {
                if (bodyBytes.Length is <= 0 or > PipeClientProtocol.MaxCommandBytes) throw new ServiceException("BF-IPC-FRAME", "command is too large");
                var body = StrictUtf8.GetString(bodyBytes);
                var digest = Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
                var operationId = Guid.NewGuid().ToString("D");
                await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "request", version = 1, nonce = parsed.Nonce, counter = 2, operation_id = operationId, body, body_sha256 = digest, mac = PipeClientProtocol.Mac(binding.Secret, $"request|{parsed.Nonce}|{operationId}|2|{digest}") }, deadline.Token).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(bodyBytes); }

            using var response = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
            var status = PipeClientProtocol.ParseStatus(response.RootElement);
            if (!status.Ok && !allowNonOkStatus) throw new ServiceException(status.Code ?? "BF-SERVICE-ERROR", "service rejected the request");
            if (expectedPolicy is not null && !status.Connected)
                throw new ServiceException("BF-SERVICE-NOT-CONNECTED", "connect response did not establish a verified connection");
            if (expectedPolicy is not null && status.Connected)
            {
                var summary = status.Enforcement ?? throw new ServiceException("BF-APP-POLICY-READBACK", "service returned no enforcement summary");
                if (summary.Route != expectedPolicy.RouteMode || summary.Policy != expectedPolicy.PolicyMode ||
                    summary.IdentityCount != expectedPolicy.Identities.Count || summary.Digest != expectedPolicy.Digest ||
                    summary.Generation != expectedPolicy.Generation || !summary.ReadbackVerified)
                    throw new ServiceException("BF-APP-POLICY-READBACK", "service enforcement summary does not match the requested policy");
            }
            return status;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw new ServiceException("BF-IPC-TIMEOUT", "service request timed out"); }
        catch (ServiceException) { throw; }
        catch (JsonException) { throw new ServiceException("BF-IPC-JSON", "service returned invalid data"); }
        catch (TimeoutException) { throw new ServiceException("BF-IPC-TIMEOUT", "service request timed out"); }
        catch (IOException) { throw new ServiceException("BF-IPC-IO", "service connection failed"); }
        catch { throw new ServiceException("BF-IPC-ERROR", "service request failed"); }
    }

    private static async Task<LatencyTestResult> SendLatencyAsync(object command, CancellationToken cancellationToken)
    {
        try
        {
            using var binding = PipeClientProtocol.LoadBinding();
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(PipeClientProtocol.LatencyOperationTimeout);
            await pipe.ConnectAsync(5000, deadline.Token).ConfigureAwait(false);
            using var challenge = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
            var parsed = PipeClientProtocol.ParseChallenge(challenge.RootElement, binding);
            await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "auth", version = 1, sid = binding.Sid, nonce = parsed.Nonce, counter = 1, mac = PipeClientProtocol.Mac(binding.Secret, $"auth|{parsed.Nonce}|{binding.Sid}|1") }, deadline.Token).ConfigureAwait(false);
            var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(command, JsonOptions);
            try
            {
                if (bodyBytes.Length is <= 0 or > PipeClientProtocol.MaxCommandBytes)
                    throw new ServiceException("BF-IPC-FRAME", "command is too large");
                var body = StrictUtf8.GetString(bodyBytes);
                var digest = Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
                var operationId = Guid.NewGuid().ToString("D");
                await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "request", version = 1, nonce = parsed.Nonce, counter = 2, operation_id = operationId, body, body_sha256 = digest, mac = PipeClientProtocol.Mac(binding.Secret, $"request|{parsed.Nonce}|{operationId}|2|{digest}") }, deadline.Token).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(bodyBytes); }
            using var response = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
            var result = PipeClientProtocol.ParseLatencyResult(response.RootElement);
            if (!result.Ok) throw new ServiceException(result.Code ?? "BF-SERVICE-ERROR", "service rejected the latency test");
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw new ServiceException("BF-IPC-TIMEOUT", "service latency test timed out"); }
        catch (ServiceException) { throw; }
        catch (JsonException) { throw new ServiceException("BF-IPC-JSON", "service returned invalid latency data"); }
        catch (TimeoutException) { throw new ServiceException("BF-IPC-TIMEOUT", "service latency test timed out"); }
        catch (IOException) { throw new ServiceException("BF-IPC-IO", "service connection failed"); }
        catch { throw new ServiceException("BF-IPC-ERROR", "service latency test failed"); }
    }

    private static async Task SendLatencyBatchAsync(object command, Action<LatencyBatchFrame> progress, CancellationToken cancellationToken)
    {
        try
        {
            using var binding = PipeClientProtocol.LoadBinding();
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(PipeClientProtocol.LatencyBatchOperationTimeout);
            await pipe.ConnectAsync(5000, deadline.Token).ConfigureAwait(false);
            using var challenge = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
            var parsed = PipeClientProtocol.ParseChallenge(challenge.RootElement, binding);
            await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "auth", version = 1, sid = binding.Sid, nonce = parsed.Nonce, counter = 1, mac = PipeClientProtocol.Mac(binding.Secret, $"auth|{parsed.Nonce}|{binding.Sid}|1") }, deadline.Token).ConfigureAwait(false);
            var operationId = Guid.NewGuid().ToString("D");
            var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(command, JsonOptions);
            try
            {
                if (bodyBytes.Length is <= 0 or > PipeClientProtocol.MaxCommandBytes)
                    throw new ServiceException("BF-IPC-FRAME", "command is too large");
                var body = StrictUtf8.GetString(bodyBytes);
                var digest = Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
                await PipeClientProtocol.WriteJsonAsync(pipe, new { kind = "request", version = 1, nonce = parsed.Nonce, counter = 2, operation_id = operationId, body, body_sha256 = digest, mac = PipeClientProtocol.Mac(binding.Secret, $"request|{parsed.Nonce}|{operationId}|2|{digest}") }, deadline.Token).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(bodyBytes); }

            try
            {
                while (true)
                {
                    using var response = await PipeClientProtocol.ReadJsonAsync(pipe, deadline.Token).ConfigureAwait(false);
                    if (response.RootElement.ValueKind == JsonValueKind.Object && response.RootElement.TryGetProperty("connected", out _))
                    {
                        var status = PipeClientProtocol.ParseStatus(response.RootElement);
                        if (!status.Ok) throw new ServiceException(status.Code ?? "BF-SERVICE-ERROR", "service rejected the latency batch before streaming began");
                        throw new ServiceException("BF-IPC-JSON", "service returned an unexpected non-streaming latency response");
                    }
                    var frame = PipeClientProtocol.ParseLatencyBatchFrame(response.RootElement);
                    if (frame.Kind == "progress")
                    {
                        progress(frame);
                        continue;
                    }
                    if (!frame.Ok) throw new ServiceException(frame.Code ?? "BF-SERVICE-ERROR", "service rejected the latency batch");
                    return;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Cancellation is an authenticated operation on the same
                // full-duplex pipe. This lets LocalSystem terminate the
                // outstanding temporary cores immediately instead of merely
                // hiding the progress UI while the batch keeps running.
                using var cancelDeadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(750));
                try
                {
                    await PipeClientProtocol.WriteJsonAsync(pipe, new
                    {
                        kind = "cancel",
                        version = 1,
                        nonce = parsed.Nonce,
                        counter = 3,
                        operation_id = operationId,
                        mac = PipeClientProtocol.Mac(binding.Secret, $"cancel|{parsed.Nonce}|{operationId}|3")
                    }, cancelDeadline.Token).ConfigureAwait(false);
                }
                catch { /* closing the pipe is the secondary cancellation signal */ }
                throw;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw new ServiceException("BF-IPC-TIMEOUT", "service latency batch timed out"); }
        catch (ServiceException) { throw; }
        catch (JsonException) { throw new ServiceException("BF-IPC-JSON", "service returned invalid latency batch data"); }
        catch (TimeoutException) { throw new ServiceException("BF-IPC-TIMEOUT", "service latency batch timed out"); }
        catch (IOException) { throw new ServiceException("BF-IPC-IO", "service connection failed"); }
        catch { throw new ServiceException("BF-IPC-ERROR", "service latency batch failed"); }
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 8, AllowTrailingCommas = false, ReadCommentHandling = JsonCommentHandling.Disallow };

}

internal static class PipeClientProtocol
{
    public const int MaxFrameBytes = 1536 * 1024;
    public const int MaxCommandBytes = 1024 * 1024;
    public static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(10);
    // Startup throughput qualification may legitimately consume up to five
    // minutes when the complete 29/32-candidate cohort needs fresh health and
    // payload samples.  Keep the UI-side deadline slightly beyond the service
    // deadline so the service remains the authority that aborts a hung
    // connection instead of the desktop cancelling a healthy qualification.
    public static readonly TimeSpan ConnectOperationTimeout = TimeSpan.FromSeconds(335);
    public static readonly TimeSpan LatencyOperationTimeout = TimeSpan.FromSeconds(18);
    public static readonly TimeSpan LatencyBatchOperationTimeout = TimeSpan.FromSeconds(335);
    private const int SecretBytes = 32;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal sealed class Binding : IDisposable
    {
        private int _disposed;
        public Binding(byte[] secret, string sid) { Secret = secret; Sid = sid; }
        public byte[] Secret { get; }
        public string Sid { get; }
        public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) CryptographicOperations.ZeroMemory(Secret); }
    }

    internal sealed record Challenge(string Nonce, string Sid, string Pid);

    public static bool IsOpaqueId(string? value, string? requiredPrefix = null)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length is < 8 or > 96) return false;
        if (requiredPrefix is not null && !value.StartsWith(requiredPrefix, StringComparison.Ordinal)) return false;
        return value.All(c => c is >= 'a' and <= 'z' || c is >= 'A' and <= 'Z' || c is >= '0' and <= '9' || c is '_' or '-');
    }

    public static Binding LoadBinding()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "ipc");
        RejectReparse(root, true);
        var secretPath = Path.Combine(root, "ipc-binding.bin");
        var sidPath = Path.Combine(root, "interactive.sid");
        RejectReparse(secretPath, false);
        RejectReparse(sidPath, false);
        var secret = BifrostIpcWire.ReadBoundedFile(secretPath, SecretBytes);
        try
        {
            var sidBytes = BifrostIpcWire.ReadBoundedFile(sidPath, 256);
            if (secret.Length != SecretBytes || sidBytes.Any(b => b > 0x7f || b < 0x20 && b is not (byte)'\r' and not (byte)'\n')) throw new ServiceException("BF-IPC-BINDING", "service is not bound");
            var sid = Encoding.ASCII.GetString(sidBytes).Trim();
            _ = new SecurityIdentifier(sid);
            return new Binding(secret, sid);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new ServiceException("BF-IPC-BINDING", "service is not bound");
        }
    }

    public static string Mac(byte[] secret, string text)
    {
        if (secret.Length != SecretBytes) throw new ServiceException("BF-IPC-BINDING", "service is not bound");
        var textBytes = StrictUtf8.GetBytes(text);
        try { return Convert.ToHexString(HMACSHA256.HashData(secret, textBytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(textBytes); }
    }

    public static bool FixedMac(byte[] secret, string text, string supplied)
    {
        if (!IsCanonicalHex(supplied, 64)) return false;
        var expected = Encoding.ASCII.GetBytes(Mac(secret, text));
        var actual = Encoding.ASCII.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(expected, actual); }
        finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
    }

    public static Challenge ParseChallenge(JsonElement root, Binding binding)
    {
        if (!HasOnly(root, "kind", "version", "nonce", "sid", "pid", "mac") || !TryString(root, "kind", 16, out var kind) || kind != "challenge" || !TryInt(root, "version", out var version) || version != 1 || !TryString(root, "nonce", 128, out var nonce) || !TryString(root, "sid", 256, out var sid) || !TryString(root, "pid", 12, out var pid) || !pid.All(char.IsDigit) || !TryString(root, "mac", 64, out var mac) || !IsCanonicalHex(mac, 64) || !string.Equals(sid, binding.Sid, StringComparison.Ordinal) || !FixedMac(binding.Secret, $"server|{nonce}|{sid}|{pid}", mac))
            throw new ServiceException("BF-IPC-IDENTITY", "service identity proof failed");
        return new Challenge(nonce, sid, pid);
    }

    public static ServiceStatus ParseStatus(JsonElement root)
    {
        try
        {
            return ServiceStatusProtocol.Parse(root);
        }
        catch (ServiceStatusProtocolException failure)
        {
            throw new ServiceException(failure.Code, failure.Message);
        }
    }

    public static LatencyTestResult ParseLatencyResult(JsonElement root)
    {
        try { return LatencyTestProtocol.Parse(root); }
        catch (ServiceStatusProtocolException failure) { throw new ServiceException(failure.Code, failure.Message); }
    }

    public static LatencyBatchFrame ParseLatencyBatchFrame(JsonElement root)
    {
        try { return LatencyBatchProtocol.Parse(root); }
        catch (ServiceStatusProtocolException failure) { throw new ServiceException(failure.Code, failure.Message); }
    }

    public static async Task<JsonDocument> ReadJsonAsync(Stream stream, CancellationToken cancellationToken)
        => await BifrostIpcWire.ReadJsonAsync(stream, cancellationToken).ConfigureAwait(false);

    public static async Task WriteJsonAsync(Stream stream, object value, CancellationToken cancellationToken)
        => await BifrostIpcWire.WriteJsonAsync(stream, value, cancellationToken).ConfigureAwait(false);

    public static JsonDocument ParseStrict(byte[] bytes)
    {
        ValidateJson(bytes);
        return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
    }

    public static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
        => await BifrostIpcWire.ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);

    public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
        => await BifrostIpcWire.WriteFrameAsync(stream, payload, cancellationToken).ConfigureAwait(false);

    private static void RejectReparse(string path, bool directory)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) throw new ServiceException("BF-IPC-BINDING", "service is not bound");
        var attrs = File.GetAttributes(path);
        if ((attrs & FileAttributes.ReparsePoint) != 0 || directory != ((attrs & FileAttributes.Directory) != 0)) throw new ServiceException("BF-IPC-BINDING", "service is not bound");
    }

    private static bool HasOnly(JsonElement root, params string[] names)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;
        var expected = new HashSet<string>(names, StringComparer.Ordinal);
        return root.EnumerateObject().All(p => expected.Contains(p.Name)) && root.EnumerateObject().Count() == expected.Count;
    }

    private static bool TryString(JsonElement root, string name, int max, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String) return false;
        var candidate = element.GetString();
        if (candidate is null || candidate.Length == 0 || candidate.Length > max || candidate.Any(char.IsControl)) return false;
        value = candidate;
        return true;
    }

    private static bool TryNullableString(JsonElement root, string name, int max, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return false;
        if (element.ValueKind == JsonValueKind.Null) return true;
        return TryString(root, name, max, out value!);
    }

    private static bool TryBool(JsonElement root, string name, out bool value)
    {
        value = false;
        if (!root.TryGetProperty(name, out var element) || (element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))) return false;
        value = element.GetBoolean();
        return true;
    }

    private static bool TryInt(JsonElement root, string name, out int value)
    {
        value = 0;
        return root.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value);
    }

    private static bool IsCanonicalHex(string value, int length) => value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void ValidateJson(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
        var objects = new Stack<HashSet<string>?>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject: objects.Push(new HashSet<string>(StringComparer.Ordinal)); break;
                case JsonTokenType.StartArray: objects.Push(null); break;
                case JsonTokenType.PropertyName:
                    if (objects.Count == 0 || objects.Peek() is null || !objects.Peek()!.Add(reader.GetString() ?? throw new JsonException("invalid property"))) throw new JsonException("duplicate JSON property");
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    if (objects.Count == 0) throw new JsonException("invalid JSON nesting");
                    objects.Pop();
                    break;
            }
        }
        if (objects.Count != 0 || reader.BytesConsumed != bytes.Length) throw new JsonException("invalid JSON");
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 8, AllowTrailingCommas = false, ReadCommentHandling = JsonCommentHandling.Disallow };
}

public sealed record UiOption(string Code, string Name);
public sealed record LifecycleSelectionMatrixResult(int Cases, string Digests, bool CrossSourceRejected);
public sealed record ControlledRuntimeMatrixResult(int Cases, int FailClosedFailures, string Routes);
public sealed record UiConfigOptions(
    IReadOnlyList<UiOption> Sources,
    IReadOnlyList<UiOption> FrontSources,
    IReadOnlyList<UiOption> Countries,
    IReadOnlyDictionary<string, IReadOnlyList<UiOption>>? CandidatesBySource = null)
{
    public static UiConfigOptions Empty { get; } = new(Array.Empty<UiOption>(), Array.Empty<UiOption>(), Array.Empty<UiOption>(), new Dictionary<string, IReadOnlyList<UiOption>>(StringComparer.OrdinalIgnoreCase));
}

public sealed class ServiceException : Exception
{
    public ServiceException(string code, string? message) : base(code)
    {
        Code = code;
        Diagnostic = message;
    }

    public string Code { get; }
    public string? Diagnostic { get; }
}

/// <summary>
/// Signed selection descriptor. It carries no final Mihomo bytes:
/// LocalSystem is the only authority allowed to compile the runnable config.
/// </summary>
public sealed class SignedClientPackageRequest : IControlledPackage
{
    public SignedClientPackageRequest(string mode, string core, string source, string country, string appPolicy, ApplicationPolicySnapshot? applicationPolicySnapshot = null, string connectionType = "direct-vmess",
        long configVersion = 0, string? configContentDigest = null, string? signedConfigJson = null, string? signedEnvelopeJson = null, string? configKeyStateJson = null,
        string? selectedCandidateLabel = null, string? frontSource = null, string? frontCandidateLabel = null,
        string? bootstrapProxyType = null, int? bootstrapProxyPort = null)
    {
        Mode = mode; Core = core; Source = source;
        var selection = ConnectionRouteSelection.Parse(connectionType, mode);
        if (selection.ConnectionType == global::Bifrost.ConnectionType.DirectVmess && country != "default" ||
            selection.ConnectionType == global::Bifrost.ConnectionType.SmartGate && country == "default" ||
            selection.ConnectionType == global::Bifrost.ConnectionType.DirectVmess && (!string.IsNullOrWhiteSpace(frontSource) || !string.IsNullOrWhiteSpace(frontCandidateLabel)))
            throw new ServiceException("BF-CONNECTION-TYPE", "country/front scope does not match the connection type");
        ConnectionType = connectionType;
        ApplicationPolicySnapshot = applicationPolicySnapshot is null
            ? Bifrost.ClientService.ApplicationPolicySnapshot.Create(mode, mode == ProtocolCodes.ModePerApp ? ClientServiceContract.NormalizePolicy(appPolicy) : "none", Array.Empty<string>(), Array.Empty<string>(), "00000000000000000000000000000000")
            : Bifrost.ClientService.ApplicationPolicySnapshot.Parse(applicationPolicySnapshot.CanonicalJson);
        if (ApplicationPolicySnapshot != applicationPolicySnapshot && applicationPolicySnapshot is not null) throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy snapshot changed");
        if (ApplicationPolicySnapshot.RouteMode != mode) throw new ServiceException("BF-APP-POLICY-SNAPSHOT", "policy route changed");
        Country = country; AppPolicy = ApplicationPolicySnapshot.PolicyMode;
        ConfigVersion = configVersion;
        ConfigContentDigest = configContentDigest;
        SignedConfigJson = signedConfigJson;
        SignedEnvelopeJson = signedEnvelopeJson;
        ConfigKeyStateJson = configKeyStateJson;
        SelectedCandidateLabel = selectedCandidateLabel;
        FrontSource = frontSource;
        FrontCandidateLabel = frontCandidateLabel;
        if ((bootstrapProxyType is null) != (bootstrapProxyPort is null)) throw new ServiceException("BF-TRANSPORT-UPSTREAM", "bootstrap proxy shape invalid");
        if (bootstrapProxyType is not null)
        {
            if (bootstrapProxyType is not (CandidateProbeEngine.LoopbackBootstrapProxy.HttpConnect or CandidateProbeEngine.LoopbackBootstrapProxy.Socks5) ||
                bootstrapProxyPort is < 1 or > 65535 || bootstrapProxyPort is >= 19000 and <= 49151)
                throw new ServiceException("BF-TRANSPORT-UPSTREAM", "bootstrap proxy is not permitted");
        }
        BootstrapProxyType = bootstrapProxyType;
        BootstrapProxyPort = bootstrapProxyPort;
    }
    public string Mode { get; }
    public string ConnectionType { get; }
    public string Core { get; }
    public string Source { get; }
    public string Country { get; }
    public string AppPolicy { get; }
    public ApplicationPolicySnapshot ApplicationPolicySnapshot { get; }
    public long ConfigVersion { get; }
    public string? ConfigContentDigest { get; }
    public string? SignedConfigJson { get; }
    public string? SignedEnvelopeJson { get; }
    public string? ConfigKeyStateJson { get; }
    public string? SelectedCandidateLabel { get; }
    public string? FrontSource { get; }
    public string? FrontCandidateLabel { get; }
    public string? BootstrapProxyType { get; }
    public int? BootstrapProxyPort { get; }
}
