using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bifrost.Release;

namespace Bifrost;

internal sealed record ConfigSigningTrustedKey(string KeyId, string PublicKeyPem, string Fingerprint, long ActivationFloor, long? RetirementFloor);

internal sealed class VerifiedConfigKeyState
{
    internal VerifiedConfigKeyState(long generation, string activeKeyId, string digest, string canonicalState, IReadOnlyList<ConfigSigningTrustedKey> keys)
    {
        Generation = generation;
        ActiveKeyId = activeKeyId;
        Digest = digest;
        CanonicalState = canonicalState;
        Keys = keys;
    }

    internal long Generation { get; }
    internal string ActiveKeyId { get; }
    internal string Digest { get; }
    internal string CanonicalState { get; }
    internal IReadOnlyList<ConfigSigningTrustedKey> Keys { get; }

    internal ConfigSigningTrustedKey Select(string signingKeyId, long configVersion)
    {
        if (!ConfigKeyTrust.KeyIdPattern.IsMatch(signingKeyId) || configVersion <= 0) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        var selected = Keys.FirstOrDefault(item => string.Equals(item.KeyId, signingKeyId, StringComparison.Ordinal))
            ?? throw new InvalidDataException("BF-CONFIG-KEY-UNKNOWN");
        if (configVersion < selected.ActivationFloor) throw new InvalidDataException("BF-CONFIG-KEY-NOT-ACTIVE");
        if (selected.RetirementFloor is long retirement && configVersion >= retirement) throw new InvalidDataException("BF-CONFIG-KEY-RETIRED");
        return selected;
    }
}

internal static class ConfigKeyTrust
{
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    internal static readonly Regex KeyIdPattern = new("^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex SignaturePattern = new("^[A-Za-z0-9_-]{86}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] Ed25519SpkiPrefix = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

    internal static VerifiedConfigKeyState? VerifyResponseState(JsonObject? state, long currentConfigVersion, long previousGeneration, string? previousDigest)
    {
        if (state is null)
        {
            if (ReleaseContract.TrustRootProvisioned) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            return null;
        }
        if (!ReleaseContract.TrustRootProvisioned || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootPem) || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootFingerprint))
            throw new InvalidDataException("BF-CONFIG-TRUST-ROOT");
        return Verify(state, ReleaseContract.TrustRootKeyId, ReleaseContract.TrustRootPem, ReleaseContract.TrustRootFingerprint, previousGeneration, previousDigest, currentConfigVersion);
    }

    internal static VerifiedConfigKeyState Verify(
        JsonObject state,
        string rootKeyId,
        string rootPem,
        string rootFingerprint,
        long previousGeneration = 0,
        string? previousDigest = null,
        long currentConfigVersion = 0)
    {
        Exact(state, ["version", "purpose", "root_key_id", "root_fingerprint", "generation", "active_key_id", "trusted_keys", "previous_state_digest", "signature"]);
        if (state["version"]?.GetValue<int>() != 1 || state["purpose"]?.GetValue<string>() != "config-signing-key-state") throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        if (!KeyIdPattern.IsMatch(rootKeyId) || state["root_key_id"]?.GetValue<string>() != rootKeyId) throw new InvalidDataException("BF-CONFIG-TRUST-ROOT");
        var actualRootFingerprint = PublicKeyFingerprint(rootPem);
        if (!Hex64.IsMatch(rootFingerprint) || !string.Equals(actualRootFingerprint, rootFingerprint, StringComparison.Ordinal) || state["root_fingerprint"]?.GetValue<string>() != rootFingerprint)
            throw new InvalidDataException("BF-CONFIG-TRUST-ROOT");

        var generation = state["generation"]?.GetValue<long>() ?? 0;
        var activeKeyId = state["active_key_id"]?.GetValue<string>() ?? string.Empty;
        if (generation <= 0 || !KeyIdPattern.IsMatch(activeKeyId)) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        string? previousStateDigest = state["previous_state_digest"] is null ? null : state["previous_state_digest"]!.GetValue<string>();
        if (previousStateDigest is not null && !Hex64.IsMatch(previousStateDigest)) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        if (generation == 1 && previousStateDigest is not null) throw new InvalidDataException("BF-CONFIG-KEY-ROLLBACK");
        if (generation > 1 && previousStateDigest is null) throw new InvalidDataException("BF-CONFIG-KEY-ROLLBACK");

        var signatureText = state["signature"]?.GetValue<string>() ?? string.Empty;
        if (!SignaturePattern.IsMatch(signatureText)) throw new InvalidDataException("BF-CONFIG-KEY-SIGNATURE");
        var unsigned = state.DeepClone().AsObject();
        unsigned.Remove("signature");
        byte[]? signed = null, signature = null, rootRaw = null;
        try
        {
            signed = Encoding.UTF8.GetBytes(Canonical(unsigned));
            signature = DecodeBase64UrlCanonical(signatureText, "BF-CONFIG-KEY-SIGNATURE");
            rootRaw = RawPublicKey(rootPem);
            if (signature.Length != 64 || !Ed25519.Verify(signature, signed, rootRaw)) throw new InvalidDataException("BF-CONFIG-KEY-SIGNATURE");
        }
        finally
        {
            if (signed is not null) CryptographicOperations.ZeroMemory(signed);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (rootRaw is not null) CryptographicOperations.ZeroMemory(rootRaw);
        }

        if (state["trusted_keys"] is not JsonArray trusted || trusted.Count is < 1 or > 4) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        var keys = new List<ConfigSigningTrustedKey>(trusted.Count);
        string? priorId = null;
        foreach (var node in trusted)
        {
            if (node is not JsonObject item) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            Exact(item, ["key_id", "public_key_pem", "fingerprint", "activation_floor", "retirement_floor"]);
            var id = item["key_id"]?.GetValue<string>() ?? string.Empty;
            var pem = item["public_key_pem"]?.GetValue<string>() ?? string.Empty;
            var fingerprint = item["fingerprint"]?.GetValue<string>() ?? string.Empty;
            var activation = item["activation_floor"]?.GetValue<long>() ?? 0;
            long? retirement = item["retirement_floor"] is null ? null : item["retirement_floor"]!.GetValue<long>();
            if (!KeyIdPattern.IsMatch(id) || pem.Length is <= 0 or > 2048 || !Hex64.IsMatch(fingerprint) || activation <= 0) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            if (priorId is not null && string.CompareOrdinal(priorId, id) >= 0) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            if (retirement is long floor && floor <= activation) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            if (!string.Equals(PublicKeyFingerprint(pem), fingerprint, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-KEY-MISMATCH");
            keys.Add(new ConfigSigningTrustedKey(id, pem, fingerprint, activation, retirement));
            priorId = id;
        }
        if (keys.Select(item => item.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count || !keys.Any(item => item.KeyId == activeKeyId)) throw new InvalidDataException("BF-CONFIG-KEY-STATE");

        var canonicalState = Canonical(state);
        var digest = Sha256(canonicalState);
        if (previousGeneration < 0 || (previousDigest is not null && !Hex64.IsMatch(previousDigest))) throw new InvalidDataException("BF-CONFIG-KEY-ROLLBACK");
        if (previousGeneration > 0)
        {
            if (generation < previousGeneration) throw new InvalidDataException("BF-CONFIG-KEY-ROLLBACK");
            if (generation == previousGeneration)
            {
                if (previousDigest is null || !string.Equals(digest, previousDigest, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-KEY-EQUIVOCATION");
            }
            else if (generation == previousGeneration + 1 && (previousDigest is null || !string.Equals(previousStateDigest, previousDigest, StringComparison.Ordinal)))
                throw new InvalidDataException("BF-CONFIG-KEY-ROLLBACK");
            // A client can legitimately be offline across multiple
            // root-signed key-state generations.  For a jump larger than one
            // generation there is no locally available intermediate digest
            // to compare.  The immutable compiled root signature above is the
            // authority for the strictly newer state; lower generations and
            // same-generation equivocation remain rejected.
        }

        var verified = new VerifiedConfigKeyState(generation, activeKeyId, digest, canonicalState, keys.AsReadOnly());
        if (currentConfigVersion > 0) _ = verified.Select(activeKeyId, currentConfigVersion);
        return verified;
    }

    internal static byte[] RawPublicKey(string pem)
    {
        var der = DecodeSpki(pem);
        try { return der.AsSpan(der.Length - 32, 32).ToArray(); }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    internal static string PublicKeyFingerprint(string pem)
    {
        var der = DecodeSpki(pem);
        try { return Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    internal static string Canonical(JsonNode? node)
    {
        if (node is null) return "null";
        if (node is JsonObject obj)
            return "{" + string.Join(",", obj.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => JsonSerializer.Serialize(pair.Key, CanonicalJsonOptions) + ":" + Canonical(pair.Value))) + "}";
        if (node is JsonArray array)
            return "[" + string.Join(",", array.Select(Canonical)) + "]";
        if (node is JsonValue value)
        {
            if (value.TryGetValue<string>(out var text)) return JsonSerializer.Serialize(text, CanonicalJsonOptions);
            if (value.TryGetValue<bool>(out var boolean)) return boolean ? "true" : "false";
            if (value.TryGetValue<long>(out var integer)) return integer.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (value.TryGetValue<int>(out var int32)) return int32.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        throw new InvalidDataException("BF-CONFIG-KEY-STATE");
    }

    private static void Exact(JsonObject value, IReadOnlyCollection<string> names)
    {
        if (value.Count != names.Count || value.Any(pair => !names.Contains(pair.Key, StringComparer.Ordinal))) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
    }

    private static byte[] DecodeSpki(string pem)
    {
        try
        {
            var text = pem.Replace("-----BEGIN PUBLIC KEY-----", string.Empty, StringComparison.Ordinal)
                .Replace("-----END PUBLIC KEY-----", string.Empty, StringComparison.Ordinal);
            var der = Convert.FromBase64String(new string(text.Where(ch => !char.IsWhiteSpace(ch)).ToArray()));
            if (der.Length != Ed25519SpkiPrefix.Length + 32 || !der.AsSpan(0, Ed25519SpkiPrefix.Length).SequenceEqual(Ed25519SpkiPrefix))
            {
                CryptographicOperations.ZeroMemory(der);
                throw new InvalidDataException("BF-CONFIG-KEY-STATE");
            }
            return der;
        }
        catch (InvalidDataException) { throw; }
        catch { throw new InvalidDataException("BF-CONFIG-KEY-STATE"); }
    }

    private static byte[] DecodeBase64UrlCanonical(string value, string error)
    {
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            var decoded = Convert.FromBase64String(padded);
            var canonical = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (!string.Equals(canonical, value, StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new InvalidDataException(error);
            }
            return decoded;
        }
        catch (InvalidDataException) { throw; }
        catch { throw new InvalidDataException(error); }
    }

    private static string Sha256(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
