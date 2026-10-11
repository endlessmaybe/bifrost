using System;
using System.IO;

namespace Bifrost.Release;

internal static class ReleaseStateAuthority
{
    internal sealed record State(
        [property: System.Text.Json.Serialization.JsonPropertyName("last_sequence")] long Sequence,
        [property: System.Text.Json.Serialization.JsonPropertyName("last_manifest_digest")] string ManifestDigest,
        [property: System.Text.Json.Serialization.JsonPropertyName("envelope_digest")] string EnvelopeDigest,
        [property: System.Text.Json.Serialization.JsonPropertyName("authority_digest")] string AuthorityDigest,
        [property: System.Text.Json.Serialization.JsonPropertyName("authority_generation")] long AuthorityGeneration,
        [property: System.Text.Json.Serialization.JsonPropertyName("root_key_id")] string RootKeyId,
        [property: System.Text.Json.Serialization.JsonPropertyName("root_fingerprint")] string RootFingerprint,
        [property: System.Text.Json.Serialization.JsonPropertyName("delegation_generation")] long DelegationGeneration,
        [property: System.Text.Json.Serialization.JsonPropertyName("key_id")] string SigningKeyId,
        [property: System.Text.Json.Serialization.JsonPropertyName("signing_key_fingerprint")] string SigningKeyFingerprint,
        [property: System.Text.Json.Serialization.JsonPropertyName("channel")] string Channel,
        [property: System.Text.Json.Serialization.JsonPropertyName("floor")] long Floor,
        [property: System.Text.Json.Serialization.JsonPropertyName("state_generation")] long Generation,
        [property: System.Text.Json.Serialization.JsonPropertyName("slot")] string Slot,
        [property: System.Text.Json.Serialization.JsonPropertyName("state_checksum")] string Checksum,
        [property: System.Text.Json.Serialization.JsonPropertyName("updated_at")] string UpdatedAt);

    internal static string ComputeChecksum(State state)
    {
        var canonical = $"{{\"authority_digest\":{System.Text.Json.JsonSerializer.Serialize(state.AuthorityDigest)},\"authority_generation\":{state.AuthorityGeneration},\"channel\":{System.Text.Json.JsonSerializer.Serialize(state.Channel)},\"delegation_generation\":{state.DelegationGeneration},\"envelope_digest\":{System.Text.Json.JsonSerializer.Serialize(state.EnvelopeDigest)},\"floor\":{state.Floor},\"key_id\":{System.Text.Json.JsonSerializer.Serialize(state.SigningKeyId)},\"last_manifest_digest\":{System.Text.Json.JsonSerializer.Serialize(state.ManifestDigest)},\"last_sequence\":{state.Sequence},\"root_fingerprint\":{System.Text.Json.JsonSerializer.Serialize(state.RootFingerprint)},\"root_key_id\":{System.Text.Json.JsonSerializer.Serialize(state.RootKeyId)},\"signing_key_fingerprint\":{System.Text.Json.JsonSerializer.Serialize(state.SigningKeyFingerprint)},\"slot\":{System.Text.Json.JsonSerializer.Serialize(state.Slot)},\"state_generation\":{state.Generation},\"updated_at\":{System.Text.Json.JsonSerializer.Serialize(state.UpdatedAt)}}}";
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    internal static void Validate(State state)
    {
        if (state.Sequence < 0 || !IsDigest(state.ManifestDigest) || !IsDigest(state.EnvelopeDigest) || !IsDigest(state.AuthorityDigest) || state.AuthorityGeneration < 1 || !IsDigest(state.RootFingerprint) || state.DelegationGeneration < 1 || !IsDigest(state.SigningKeyFingerprint) || state.Floor < 1 || state.Generation < 1 || state.Slot is not ("a" or "b") || !DateTimeOffset.TryParse(state.UpdatedAt, out _) || !string.Equals(ComputeChecksum(state), state.Checksum, StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
    }

    internal static string Classify(long? currentSequence, string? currentManifestDigest, long sequence, string manifestDigest, long floor)
    {
        if (sequence < 1 || floor < 1 || !IsDigest(manifestDigest)) throw new InvalidDataException("BF-RELEASE-STATE");
        if (!currentSequence.HasValue) return "first-install";
        if (!IsDigest(currentManifestDigest)) throw new InvalidDataException("BF-RELEASE-STATE");
        if (sequence < currentSequence.Value || sequence < floor) return "rollback";
        if (sequence == currentSequence.Value) return string.Equals(manifestDigest, currentManifestDigest, StringComparison.Ordinal) ? "idempotent" : "equivocation";
        return "advance";
    }

    internal static string ClassifyAuthority(State? current, long generation, string digest, string signerFingerprint)
    {
        if (generation < 1 || !IsDigest(digest) || !IsDigest(signerFingerprint)) throw new InvalidDataException("BF-RELEASE-AUTHORITY");
        if (current is null) return "first-authority";
        Validate(current);
        if (generation < current.AuthorityGeneration) return "rollback";
        if (generation == current.AuthorityGeneration)
        {
            if (!string.Equals(digest, current.AuthorityDigest, StringComparison.Ordinal)) return "equivocation";
            if (!string.Equals(signerFingerprint, current.SigningKeyFingerprint, StringComparison.Ordinal)) return "equivocation";
            return "idempotent";
        }
        return "advance";
    }

    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(ch => Uri.IsHexDigit(ch)) && value == value.ToLowerInvariant();
}
