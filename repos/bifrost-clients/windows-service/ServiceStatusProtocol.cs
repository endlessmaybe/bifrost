using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;

namespace Bifrost.ClientService;

/// <summary>Exact-shape enforcement evidence returned by the service.</summary>
public sealed record EnforcementSummary(
    [property: JsonPropertyName("route")] string Route,
    [property: JsonPropertyName("policy")] string Policy,
    [property: JsonPropertyName("identity_count")] int IdentityCount,
    [property: JsonPropertyName("digest")] string Digest,
    [property: JsonPropertyName("generation")] string Generation,
    [property: JsonPropertyName("readback_verified")] bool ReadbackVerified);

/// <summary>One exact candidate result read back from Mihomo's controller.</summary>
public sealed record MihomoCandidateReadback(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("alive")] bool Alive,
    [property: JsonPropertyName("delay_ms")] int? DelayMs);

/// <summary>
/// Runtime identity and live URLTest selection.  This is controller readback,
/// not the candidate placeholder that authorized compilation of the signed
/// source package.
/// </summary>
public sealed record MihomoRuntimeReadback(
    [property: JsonPropertyName("group")] string Group,
    [property: JsonPropertyName("active_candidate")] string ActiveCandidate,
    [property: JsonPropertyName("candidates")] IReadOnlyList<MihomoCandidateReadback> Candidates,
    [property: JsonPropertyName("process_id")] int ProcessId,
    [property: JsonPropertyName("tun_interface_index")] int TunInterfaceIndex);

/// <summary>
/// The one status shape shared by the service, WPF client and pure fixture.
/// Nulls are intentional: even failures carry every key so a transport error
/// cannot be confused with a malformed response.
/// </summary>
public sealed record ServiceStatus(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("connected")] bool Connected,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("message")] string? Message,
    [property: JsonPropertyName("core")] string? Core,
    [property: JsonPropertyName("mode")] string? Mode,
    [property: JsonPropertyName("configId")] string? ConfigId,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("enforcement")] EnforcementSummary? Enforcement,
    [property: JsonPropertyName("mihomo")] MihomoRuntimeReadback? Mihomo = null)
{
    public static ServiceStatus ConnectedState(string core, string mode, string? configId, string source, EnforcementSummary summary, MihomoRuntimeReadback? mihomo = null) =>
        new(true, true, "connected", null, null, core, mode, configId, source, summary, mihomo);

    public static ServiceStatus Staged(string configId, string core, string mode, string? source = null) =>
        new(true, false, "staged", null, null, core, mode, configId, source, null, null);

    public static ServiceStatus Disconnected() =>
        new(true, false, "disconnected", null, null, null, null, null, null, null, null);

    public static ServiceStatus Reconnecting() =>
        new(true, false, "reconnecting", null, null, null, null, null, null, null, null);

    public static ServiceStatus UpdateScheduled() =>
        new(true, false, "update_scheduled", null, null, null, null, null, null, null, null);

    public static ServiceStatus Blocked(string code, string? diagnostic = null) =>
        new(false, false, "blocked", code,
            code == "BF-RUNTIME-HEALTH" && IsHealthDiagnostic(diagnostic) ? diagnostic : null,
            null, null, null, null, null, null);

    internal static bool IsHealthDiagnostic(string? value) => value is { Length: > 0 and <= 129 } &&
        value.Split('+') is { Length: >= 1 and <= 2 } parts && parts.All(part =>
            part.Length <= 64 && (part.StartsWith("BF-TRANSPORT-PROBE", StringComparison.Ordinal) || part == "BF-TUN-ROUTE") &&
            part.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-'));
}

/// <summary>
/// Release identity returned over the already authenticated named-pipe
/// protocol.  The installer uses this instead of probing an unrelated HTTP
/// listener.  Every value is derived by the service from its own executable
/// and protected installation layout; none is selected by a client request.
/// </summary>
public sealed record ServiceReleaseHealth(
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("install_id")] string InstallId,
    [property: JsonPropertyName("release_sequence")] long ReleaseSequence,
    [property: JsonPropertyName("release_generation")] string ReleaseGeneration,
    [property: JsonPropertyName("service_pid")] int ServicePid,
    [property: JsonPropertyName("binary_identity")] string BinaryIdentity);

/// <summary>Exact response for a v2rayN-compatible real-delay measurement.</summary>
public sealed record LatencyTestResult(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("latency_ms")] int? LatencyMs)
{
    public static LatencyTestResult Measured(int value) => new(true, "measured", null, value);
    public static LatencyTestResult Unavailable() => new(true, "unavailable", null, null);
    public static LatencyTestResult Blocked(string code) => new(false, "blocked", code, null);
}

/// <summary>
/// Streaming frame for a bounded batch of real-delay measurements.  Progress
/// frames carry one signed candidate result as soon as it finishes; the final
/// frame closes the batch explicitly so the desktop can update rows without
/// waiting for the slowest candidate in the entire source.
/// </summary>
public sealed record LatencyBatchFrame(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("latency_ms")] int? LatencyMs,
    [property: JsonPropertyName("completed")] int Completed,
    [property: JsonPropertyName("total")] int Total)
{
    public static LatencyBatchFrame Progress(string label, LatencyTestResult result, int completed, int total) =>
        new("progress", label, result.Ok, result.State, result.Code, result.LatencyMs, completed, total);

    public static LatencyBatchFrame Complete(int total) =>
        new("complete", null, true, "complete", null, null, total, total);

    public static LatencyBatchFrame Blocked(string code, int completed, int total) =>
        new("complete", null, false, "blocked", code, null, completed, total);
}

public sealed class ServiceStatusProtocolException : FormatException
{
    public ServiceStatusProtocolException(string code, string message) : base(message) => Code = code;
    public string Code { get; }
}

/// <summary>
/// Production status parser and semantic validator.  It has no WPF or pipe
/// dependency so the service-contract fixture executes exactly this code.
/// </summary>
public static class ServiceStatusProtocol
{
    private static readonly HashSet<string> ExactFields = new(StringComparer.Ordinal)
    {
        "ok", "connected", "state", "code", "message", "core", "mode", "configId", "source", "enforcement", "mihomo",
    };

    public static ServiceStatus Parse(JsonElement root)
    {
        var ok = false;
        var connected = false;
        var state = string.Empty;
        string? code = null;
        string? message = null;
        string? core = null;
        string? mode = null;
        string? configId = null;
        string? source = null;
        if (!HasOnly(root, ExactFields) ||
            !TryBool(root, "ok", out ok) ||
            !TryBool(root, "connected", out connected) ||
            !TryString(root, "state", 32, out state) ||
            !TryNullableString(root, "code", 64, out code) ||
            !TryNullableString(root, "message", 129, out message) ||
            message is not null && (state != "blocked" || code != "BF-RUNTIME-HEALTH" || !ServiceStatus.IsHealthDiagnostic(message)) ||
            !TryNullableString(root, "core", 64, out core) ||
            !TryNullableString(root, "mode", 32, out mode) ||
            !TryNullableString(root, "configId", 96, out configId) ||
            !TryNullableString(root, "source", 96, out source))
            Reject("BF-IPC-JSON", "service returned invalid status shape");

        var enforcement = ParseEnforcement(root);
        var mihomo = ParseMihomo(root);
        ValidateRelations(ok, connected, state, code, core, mode, configId, source, enforcement, mihomo);
        return new ServiceStatus(ok, connected, state, code, message, core, mode, configId, source, enforcement, mihomo);
    }

    public static bool Matches(
        ServiceStatus status,
        string routeMode,
        string policyMode,
        int identityCount,
        string digest,
        string generation) =>
        status.Ok && status.Connected && status.State == "connected" &&
        status.Enforcement is { ReadbackVerified: true } summary &&
        summary.Route == routeMode && summary.Policy == policyMode &&
        summary.IdentityCount == identityCount && summary.Digest == digest &&
        summary.Generation == generation;

    private static EnforcementSummary? ParseEnforcement(JsonElement root)
    {
        if (!root.TryGetProperty("enforcement", out var element)) Reject("BF-IPC-JSON", "enforcement field is missing");
        if (element.ValueKind == JsonValueKind.Null) return null;
        var route = string.Empty;
        var policy = string.Empty;
        var identityCount = 0;
        var digest = string.Empty;
        var generation = string.Empty;
        var readbackVerified = false;
        if (!HasOnly(element, "route", "policy", "identity_count", "digest", "generation", "readback_verified") ||
            !TryString(element, "route", 16, out route) || route is not ("smart" or "global" or "per-app") ||
            !TryString(element, "policy", 16, out policy) || policy is not ("none" or "allow" or "exclude") ||
            !TryInt(element, "identity_count", out identityCount) || identityCount is < 0 or > 64 ||
            !TryString(element, "digest", 64, out digest) || !IsCanonicalHex(digest, 64) ||
            !TryString(element, "generation", 32, out generation) || !IsCanonicalHex(generation, 32) ||
            !TryBool(element, "readback_verified", out readbackVerified))
            Reject("BF-IPC-JSON", "service returned invalid enforcement summary");
        if (route == "per-app" && policy is not ("allow" or "exclude") ||
            route != "per-app" && policy != "none" ||
            route == "per-app" && identityCount == 0 ||
            route != "per-app" && identityCount != 0 ||
            !readbackVerified)
            Reject("BF-APP-POLICY-READBACK", "enforcement summary is not verified");
        return new EnforcementSummary(route, policy, identityCount, digest, generation, readbackVerified);
    }

    private static MihomoRuntimeReadback? ParseMihomo(JsonElement root)
    {
        if (!root.TryGetProperty("mihomo", out var element)) Reject("BF-IPC-JSON", "mihomo field is missing");
        if (element.ValueKind == JsonValueKind.Null) return null;
        var group = string.Empty;
        var activeCandidate = string.Empty;
        var processId = 0;
        var tunInterfaceIndex = 0;
        JsonElement candidatesElement = default;
        if (!HasOnly(element, "group", "active_candidate", "candidates", "process_id", "tun_interface_index") ||
            !TryToken(element, "group", 96, out group) || !TryToken(element, "active_candidate", 96, out activeCandidate) ||
            !TryInt(element, "process_id", out processId) || processId <= 0 ||
            !TryInt(element, "tun_interface_index", out tunInterfaceIndex) || tunInterfaceIndex <= 0 ||
            !element.TryGetProperty("candidates", out candidatesElement) || candidatesElement.ValueKind != JsonValueKind.Array ||
            candidatesElement.GetArrayLength() is < 1 or > 600)
            Reject("BF-IPC-JSON", "service returned invalid Mihomo runtime readback");

        var candidates = new List<MihomoCandidateReadback>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidateElement in candidatesElement.EnumerateArray())
        {
            var name = string.Empty;
            var alive = false;
            JsonElement delayElement = default;
            if (!HasOnly(candidateElement, "name", "alive", "delay_ms") ||
                !TryToken(candidateElement, "name", 96, out name) || !names.Add(name) ||
                !TryBool(candidateElement, "alive", out alive) ||
                !candidateElement.TryGetProperty("delay_ms", out delayElement) ||
                delayElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.Number))
                Reject("BF-IPC-JSON", "service returned invalid Mihomo candidate readback");
            int? delay = delayElement.ValueKind == JsonValueKind.Number && delayElement.TryGetInt32(out var value) ? value : null;
            if (alive && (delay is null or < 1 or > 65535) || !alive && delay is not null)
                Reject("BF-IPC-JSON", "service returned contradictory Mihomo candidate health");
            candidates.Add(new MihomoCandidateReadback(name, alive, delay));
        }
        if (!names.Contains(activeCandidate) || !candidates.Any(candidate => candidate.Alive &&
            string.Equals(candidate.Name, activeCandidate, StringComparison.OrdinalIgnoreCase)))
            Reject("BF-IPC-JSON", "Mihomo active candidate is not a healthy signed candidate");
        return new MihomoRuntimeReadback(group, activeCandidate, candidates, processId, tunInterfaceIndex);
    }

    private static void ValidateRelations(
        bool ok,
        bool connected,
        string state,
        string? code,
        string? core,
        string? mode,
        string? configId,
        string? source,
        EnforcementSummary? enforcement,
        MihomoRuntimeReadback? mihomo)
    {
        switch (state)
        {
            case "connected":
                if (!ok || !connected || code is not null ||
                    !IsCore(core) || !IsMode(mode) || !IsOpaqueId(configId, "cfg_") || !ServiceSelectionCodes.IsSource(source) || enforcement is null ||
                    core == "mihomo" && mihomo is null || core != "mihomo" && mihomo is not null)
                    Reject("BF-IPC-JSON", "connected status fields contradict");
                break;
            case "reconnecting":
            case "disconnected":
                if (!ok || connected || code is not null || core is not null || mode is not null || configId is not null || source is not null || enforcement is not null || mihomo is not null)
                    Reject("BF-IPC-JSON", "disconnected status fields contradict");
                break;
            case "staged":
                if (!ok || connected || code is not null || !IsCore(core) || !IsMode(mode) || !IsOpaqueId(configId, "cfg_") || (source is not null && !ServiceSelectionCodes.IsSource(source)) || enforcement is not null || mihomo is not null)
                    Reject("BF-IPC-JSON", "staged status fields contradict");
                break;
            case "update_scheduled":
                if (!ok || connected || code is not null || core is not null || mode is not null || configId is not null || source is not null || enforcement is not null || mihomo is not null)
                    Reject("BF-IPC-JSON", "update status fields contradict");
                break;
            case "blocked":
            case "error":
                if (ok || connected || !IsErrorCode(code) || core is not null || mode is not null || configId is not null || source is not null || enforcement is not null || mihomo is not null)
                    Reject("BF-IPC-JSON", "error status fields contradict");
                break;
            default:
                Reject("BF-IPC-JSON", "unknown service status state");
                break;
        }
    }

    private static bool IsCore(string? value) => value is "auto" or "mihomo";
    private static bool IsMode(string? value) => value is "smart" or "global" or "per-app";
    private static bool IsErrorCode(string? value) =>
        !string.IsNullOrEmpty(value) && value.StartsWith("BF-", StringComparison.Ordinal) &&
        value.Length <= 64 && value.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-');

    private static bool IsOpaqueId(string? value, string? prefix)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length is < 8 or > 96 ||
            prefix is not null && !value.StartsWith(prefix, StringComparison.Ordinal)) return false;
        return
            value.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-');
    }

    private static bool HasOnly(JsonElement root, IEnumerable<string> expected)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;
        var names = root.EnumerateObject().Select(property => property.Name).ToArray();
        return names.Length == expected.Count() && names.Distinct(StringComparer.Ordinal).Count() == names.Length && names.All(expected.Contains);
    }

    private static bool HasOnly(JsonElement root, params string[] expected) => HasOnly(root, (IEnumerable<string>)expected);

    private static bool TryString(JsonElement root, string name, int max, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String) return false;
        var candidate = element.GetString();
        if (candidate is null || candidate.Length == 0 || candidate.Length > max || candidate.Any(char.IsControl)) return false;
        value = candidate;
        return true;
    }

    private static bool TryToken(JsonElement root, string name, int max, out string value)
    {
        if (!TryString(root, name, max, out value)) return false;
        return value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    private static bool TryNullableString(JsonElement root, string name, int max, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return false;
        if (element.ValueKind == JsonValueKind.Null) return true;
        if (!TryString(root, name, max, out var nonNull)) return false;
        value = nonNull;
        return true;
    }

    private static bool TryBool(JsonElement root, string name, out bool value)
    {
        value = false;
        if (!root.TryGetProperty(name, out var element) || element.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        value = element.GetBoolean();
        return true;
    }

    private static bool TryInt(JsonElement root, string name, out int value)
    {
        value = 0;
        return root.TryGetProperty(name, out var element) &&
               element.ValueKind == JsonValueKind.Number &&
               element.TryGetInt32(out value);
    }

    private static bool IsCanonicalHex(string value, int length) =>
        value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    [DoesNotReturn]
    private static void Reject(string code, string message) => throw new ServiceStatusProtocolException(code, message);
}

public static class LatencyTestProtocol
{
    private static readonly HashSet<string> ExactFields = new(StringComparer.Ordinal)
        { "ok", "state", "code", "latency_ms" };

    public static LatencyTestResult Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) Reject();
        var names = root.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Length != ExactFields.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length || names.Any(name => !ExactFields.Contains(name))) Reject();
        if (!root.TryGetProperty("ok", out var okElement)) Reject();
        if (!root.TryGetProperty("state", out var stateElement)) Reject();
        if (!root.TryGetProperty("code", out var codeElement)) Reject();
        if (!root.TryGetProperty("latency_ms", out var latencyElement)) Reject();
        if (okElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            stateElement.ValueKind != JsonValueKind.String ||
            codeElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.String) ||
            latencyElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.Number)) Reject();
        var ok = okElement.GetBoolean();
        var state = stateElement.GetString() ?? string.Empty;
        var code = codeElement.ValueKind == JsonValueKind.String ? codeElement.GetString() : null;
        int? latency = latencyElement.ValueKind == JsonValueKind.Number && latencyElement.TryGetInt32(out var value) ? value : null;
        if (state == "measured")
        {
            if (!ok || code is not null || latency is null or < 1 or > 10_000) Reject();
        }
        else if (state == "unavailable")
        {
            if (!ok || code is not null || latency is not null) Reject();
        }
        else if (state == "blocked")
        {
            if (ok || latency is not null || string.IsNullOrWhiteSpace(code) || !code.StartsWith("BF-", StringComparison.Ordinal) || code.Length > 64 ||
                code.Any(character => character is not (>= 'A' and <= 'Z' or >= '0' and <= '9' or '-'))) Reject();
        }
        else Reject();
        return new LatencyTestResult(ok, state, code, latency);
    }

    [DoesNotReturn]
    private static void Reject() => throw new ServiceStatusProtocolException("BF-IPC-JSON", "service returned invalid latency result");
}

public static class LatencyBatchProtocol
{
    private static readonly HashSet<string> ExactFields = new(StringComparer.Ordinal)
        { "kind", "label", "ok", "state", "code", "latency_ms", "completed", "total" };

    public static LatencyBatchFrame Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) Reject();
        var names = root.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Length != ExactFields.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length || names.Any(name => !ExactFields.Contains(name))) Reject();
        JsonElement kindElement = default, labelElement = default, okElement = default, stateElement = default,
            codeElement = default, latencyElement = default, completedElement = default, totalElement = default;
        var completed = 0;
        var total = 0;
        if (!root.TryGetProperty("kind", out kindElement) || kindElement.ValueKind != JsonValueKind.String ||
            !root.TryGetProperty("label", out labelElement) || labelElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.String) ||
            !root.TryGetProperty("ok", out okElement) || okElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            !root.TryGetProperty("state", out stateElement) || stateElement.ValueKind != JsonValueKind.String ||
            !root.TryGetProperty("code", out codeElement) || codeElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.String) ||
            !root.TryGetProperty("latency_ms", out latencyElement) || latencyElement.ValueKind is not (JsonValueKind.Null or JsonValueKind.Number) ||
            !root.TryGetProperty("completed", out completedElement) || completedElement.ValueKind != JsonValueKind.Number || !completedElement.TryGetInt32(out completed) ||
            !root.TryGetProperty("total", out totalElement) || totalElement.ValueKind != JsonValueKind.Number || !totalElement.TryGetInt32(out total)) Reject();

        var kind = kindElement.GetString() ?? string.Empty;
        var label = labelElement.ValueKind == JsonValueKind.String ? labelElement.GetString() : null;
        var ok = okElement.GetBoolean();
        var state = stateElement.GetString() ?? string.Empty;
        var code = codeElement.ValueKind == JsonValueKind.String ? codeElement.GetString() : null;
        int? latency = latencyElement.ValueKind == JsonValueKind.Number && latencyElement.TryGetInt32(out var value) ? value : null;
        if (total is < 1 or > 600 || completed < 0 || completed > total) Reject();

        if (kind == "progress")
        {
            if (string.IsNullOrWhiteSpace(label) || label.Length > 96 || label.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.')) || completed is < 1 ||
                state is not ("measured" or "unavailable" or "blocked")) Reject();
            if (state == "measured" && (!ok || code is not null || latency is null or < 1 or > 10_000)) Reject();
            if (state == "unavailable" && (!ok || code is not null || latency is not null)) Reject();
            if (state == "blocked" && (ok || latency is not null || !IsErrorCode(code))) Reject();
        }
        else if (kind == "complete")
        {
            if (label is not null || latency is not null) Reject();
            if (state == "complete")
            {
                if (!ok || code is not null || completed != total) Reject();
            }
            else if (state == "blocked")
            {
                if (ok || !IsErrorCode(code)) Reject();
            }
            else Reject();
        }
        else Reject();

        return new LatencyBatchFrame(kind, label, ok, state, code, latency, completed, total);
    }

    private static bool IsErrorCode(string? code) =>
        !string.IsNullOrWhiteSpace(code) && code.StartsWith("BF-", StringComparison.Ordinal) && code.Length <= 64 &&
        code.All(character => character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-');

    [DoesNotReturn]
    private static void Reject() => throw new ServiceStatusProtocolException("BF-IPC-JSON", "service returned invalid latency batch frame");
}

internal static class ServiceSelectionCodes
{
    internal static bool IsSource(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length is >= 1 and <= 32 &&
        value.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-');

    internal static bool IsCountry(string? value) =>
        string.Equals(value, "default", StringComparison.Ordinal) ||
        !string.IsNullOrWhiteSpace(value) && value.Length is >= 2 and <= 8 &&
        value.All(c => c is >= 'A' and <= 'Z');
}
