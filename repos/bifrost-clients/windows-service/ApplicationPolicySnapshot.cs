using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

/// <summary>
/// The immutable Windows application policy that crosses the WPF, package,
/// IPC, staging and service boundaries.  The digest covers the canonical
/// route/policy/generation/identity tuple; no boundary is allowed to rebuild
/// a policy from an untrusted list after this object is created.
/// </summary>
public sealed class ApplicationPolicySnapshot : IEquatable<ApplicationPolicySnapshot>
{
    public const int Version = 1;
    public const string Platform = "windows";
    public const int MaxIdentities = 64;
    public const int MaxIdentityBytes = 255;
    public const int MaxTotalIdentityBytes = 8 * 1024;
    public const int MaxJsonBytes = 16 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new() { WriteIndented = false };

    private ApplicationPolicySnapshot(
        string routeMode,
        string policyMode,
        IReadOnlyList<string> includeIdentities,
        IReadOnlyList<string> excludeIdentities,
        string generation,
        string digest,
        string canonicalJson)
    {
        RouteMode = routeMode;
        PolicyMode = policyMode;
        IncludeIdentities = includeIdentities;
        ExcludeIdentities = excludeIdentities;
        Generation = generation;
        Digest = digest;
        CanonicalJson = canonicalJson;
    }

    public string RouteMode { get; }
    public string PolicyMode { get; }
    public IReadOnlyList<string> IncludeIdentities { get; }
    public IReadOnlyList<string> ExcludeIdentities { get; }
    public IReadOnlyList<string> Identities => PolicyMode switch
    {
        "allow" => IncludeIdentities,
        "exclude" => ExcludeIdentities,
        _ => Array.Empty<string>()
    };
    public string Generation { get; }
    public string Digest { get; }
    public string CanonicalJson { get; }

    public static ApplicationPolicySnapshot Create(
        string routeMode,
        string policyMode,
        IEnumerable<string>? includeIdentities,
        IEnumerable<string>? excludeIdentities,
        string generation)
    {
        routeMode = (routeMode ?? string.Empty).ToLowerInvariant();
        policyMode = (policyMode ?? string.Empty).ToLowerInvariant();
        if (routeMode is not ("smart" or "global" or "per-app")) Reject("BF-APP-POLICY");
        if (!IsGeneration(generation)) Reject("BF-APP-GENERATION");

        var include = NormalizeIdentities(includeIdentities ?? Array.Empty<string>());
        var exclude = NormalizeIdentities(excludeIdentities ?? Array.Empty<string>());
        if (include.Count > 0 && exclude.Count > 0) Reject("BF-APP-POLICY-CONFLICT");
        switch (routeMode)
        {
            case "per-app" when policyMode == "allow":
                if (include.Count == 0 || exclude.Count != 0) Reject("BF-APP-ALLOW-EMPTY");
                break;
            case "per-app" when policyMode == "exclude":
                if (exclude.Count == 0 || include.Count != 0) Reject("BF-APP-EXCLUDE-EMPTY");
                break;
            case "per-app":
                Reject("BF-APP-POLICY");
                break;
            default:
                if (policyMode != "none" || include.Count != 0 || exclude.Count != 0) Reject("BF-APP-POLICY");
                break;
        }

        var identities = policyMode == "allow" ? include : policyMode == "exclude" ? exclude : Array.Empty<string>();
        var digest = ComputeDigest(routeMode, policyMode, generation, identities);
        var canonicalObject = new JsonObject
        {
            ["version"] = Version,
            ["platform"] = Platform,
            ["route_mode"] = routeMode,
            ["policy_mode"] = policyMode,
            ["generation"] = generation,
            ["identities"] = new JsonArray(identities.Select(identity => (JsonNode?)JsonValue.Create(identity)).ToArray()),
            ["digest"] = digest
        };
        var canonical = canonicalObject.ToJsonString(CanonicalJsonOptions);
        return new ApplicationPolicySnapshot(
            routeMode,
            policyMode,
            new ReadOnlyCollection<string>(include.ToList()),
            new ReadOnlyCollection<string>(exclude.ToList()),
            generation,
            digest,
            canonical);
    }

    public static ApplicationPolicySnapshot Parse(string? canonicalJson)
    {
        if (canonicalJson is null) Reject("BF-APP-JSON");
        byte[] bytes;
        try { bytes = StrictUtf8.GetBytes(canonicalJson!); }
        catch (EncoderFallbackException) { Reject("BF-APP-JSON"); return null!; }
        try
        {
            if (bytes.Length is 0 or > MaxJsonBytes) Reject("BF-APP-JSON");
            using var document = ParseStrict(bytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) Reject("BF-APP-JSON");
            var fields = root.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
            var expected = new HashSet<string>(new[] { "version", "platform", "route_mode", "policy_mode", "generation", "identities", "digest" }, StringComparer.Ordinal);
            if (!fields.SetEquals(expected) || fields.Count != root.EnumerateObject().Count()) Reject("BF-APP-JSON");
            if (!root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || version.GetInt32() != Version) Reject("BF-APP-JSON");
            var platform = GetString(root, "platform");
            if (platform != Platform) Reject("BF-APP-JSON");
            var routeMode = GetString(root, "route_mode");
            var policyMode = GetString(root, "policy_mode");
            var generation = GetString(root, "generation");
            var suppliedDigest = GetString(root, "digest");
            if (!IsDigest(suppliedDigest)) Reject("BF-APP-DIGEST");
            if (!root.TryGetProperty("identities", out var identityElement) || identityElement.ValueKind != JsonValueKind.Array) Reject("BF-APP-JSON");
            var identities = identityElement.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString()! : throw new ApplicationPolicyFailure("BF-APP-JSON")).ToArray();
            var rebuilt = Create(routeMode, policyMode, policyMode == "allow" ? identities : Array.Empty<string>(), policyMode == "exclude" ? identities : Array.Empty<string>(), generation);
            var expectedDigest = Encoding.ASCII.GetBytes(rebuilt.Digest);
            var actualDigest = Encoding.ASCII.GetBytes(suppliedDigest);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expectedDigest, actualDigest)) Reject("BF-APP-DIGEST");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedDigest);
                CryptographicOperations.ZeroMemory(actualDigest);
            }
            if (!string.Equals(canonicalJson, rebuilt.CanonicalJson, StringComparison.Ordinal)) Reject("BF-APP-JSON");
            return rebuilt;
        }
        catch (JsonException) { Reject("BF-APP-JSON"); return null!; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static IReadOnlyList<string> NormalizeIdentities(IEnumerable<string>? values) =>
        new ReadOnlyCollection<string>(NormalizeIdentitiesInternal(values ?? Array.Empty<string>()));

    private static List<string> NormalizeIdentitiesInternal(IEnumerable<string> values)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var totalBytes = 0;
        foreach (var raw in values)
        {
            if (raw is null) Reject("BF-APP-ID");
            var value = raw!;
            if (value.Length == 0 || value != value.Trim() || value.Any(char.IsControl) || value.Any(char.IsWhiteSpace) ||
                value.Contains('\\') || value.Contains('/') || value.Contains(':') || value.Contains("..", StringComparison.Ordinal)) Reject("BF-APP-ID");
            if (!IsValidIdentity(value)) Reject("BF-APP-ID");
            var canonical = value.ToUpperInvariant();
            byte[] bytes;
            try { bytes = StrictUtf8.GetBytes(canonical); }
            catch (EncoderFallbackException) { Reject("BF-APP-ID"); return null!; }
            try
            {
                if (bytes.Length > MaxIdentityBytes) Reject("BF-APP-ID");
                if (seen.Add(canonical))
                {
                    totalBytes = checked(totalBytes + bytes.Length);
                    if (result.Count >= MaxIdentities || totalBytes > MaxTotalIdentityBytes) Reject("BF-APP-LIMIT");
                    result.Add(canonical);
                }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return result;
    }

    private static bool IsValidIdentity(string value)
    {
        if (value.Length == 0 || !char.IsLetterOrDigit(value[0])) return false;
        return value.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-');
    }

    private static string ComputeDigest(string routeMode, string policyMode, string generation, IReadOnlyList<string> identities)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendLengthPrefixed(hash, "BIFROST-APPLICATION-POLICY\0");
        AppendLengthPrefixed(hash, Version.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AppendLengthPrefixed(hash, Platform);
        AppendLengthPrefixed(hash, routeMode);
        AppendLengthPrefixed(hash, policyMode);
        AppendLengthPrefixed(hash, generation);
        Span<byte> count = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(count, identities.Count);
        hash.AppendData(count);
        foreach (var identity in identities) AppendLengthPrefixed(hash, identity);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        try
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static JsonDocument ParseStrict(byte[] bytes)
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
                    if (objects.Count == 0 || objects.Peek() is null || !objects.Peek()!.Add(reader.GetString() ?? string.Empty)) throw new JsonException("duplicate property");
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    if (objects.Count == 0) throw new JsonException("invalid nesting");
                    objects.Pop();
                    break;
            }
        }
        if (objects.Count != 0 || reader.BytesConsumed != bytes.Length) throw new JsonException("invalid JSON");
        return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(value.GetString())
            ? value.GetString()! : throw new ApplicationPolicyFailure("BF-APP-JSON");

    private static bool IsGeneration(string value) => value?.Length == 32 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsDigest(string value) => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static void Reject(string code) => throw new ApplicationPolicyFailure(code);

    public bool Equals(ApplicationPolicySnapshot? other) => other is not null &&
        RouteMode == other.RouteMode && PolicyMode == other.PolicyMode && Generation == other.Generation && Digest == other.Digest && CanonicalJson == other.CanonicalJson &&
        IncludeIdentities.SequenceEqual(other.IncludeIdentities, StringComparer.Ordinal) && ExcludeIdentities.SequenceEqual(other.ExcludeIdentities, StringComparer.Ordinal);
    public override bool Equals(object? obj) => Equals(obj as ApplicationPolicySnapshot);
    public override int GetHashCode() => HashCode.Combine(RouteMode, PolicyMode, Generation, Digest, CanonicalJson);
    public static bool operator ==(ApplicationPolicySnapshot? left, ApplicationPolicySnapshot? right) => ReferenceEquals(left, right) || (left is not null && left.Equals(right));
    public static bool operator !=(ApplicationPolicySnapshot? left, ApplicationPolicySnapshot? right) => !(left == right);
}

/// <summary>Stable, shared validation failure for the policy-only source file.
/// The service maps it to its internal IPC error type; the WPF client can use
/// the same validator without linking the service entry point.</summary>
public sealed class ApplicationPolicyFailure : Exception
{
    public ApplicationPolicyFailure(string code) : base(code) => Code = code;
    public string Code { get; }
}
