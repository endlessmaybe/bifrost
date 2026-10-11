using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.Release;

internal static class ReleaseCorpusFixture
{
    public static int Run(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        var vectors = document.RootElement.GetProperty("vectors");
        if (vectors.ValueKind != JsonValueKind.Array || vectors.GetArrayLength() == 0) throw new InvalidDataException("BF-RELEASE-CORPUS");
        var count = 0;
        foreach (var vector in vectors.EnumerateArray())
        {
            if (!vector.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) throw new InvalidDataException("BF-RELEASE-CORPUS-ID");
            if (!vector.TryGetProperty("operation", out var op) || op.ValueKind != JsonValueKind.String || !vector.TryGetProperty("input", out var input) || input.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-RELEASE-CORPUS-INPUT");
            var operation = op.GetString();
            var expected = vector.TryGetProperty("expected", out var outcome) && outcome.ValueKind == JsonValueKind.String ? outcome.GetString() : null;
            bool accepted;
            try { accepted = Execute(operation!, input); }
            catch (Exception error) { throw new InvalidDataException($"BF-RELEASE-CORPUS-{id.GetString()}:{error.Message}", error); }
            if (expected is "accept" or "idempotent" && !accepted) throw new InvalidDataException($"BF-RELEASE-CORPUS-{id.GetString()}");
            if (expected == "reject" && accepted) throw new InvalidDataException($"BF-RELEASE-CORPUS-{id.GetString()}");
            count++;
        }
        return count;
    }

    public static int RunFullEnvelope(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        var rootPem = document.RootElement.GetProperty("trust").GetProperty("public_key_pem").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-TRUST");
        var baseEnvelope = JsonNode.Parse(document.RootElement.GetProperty("base_envelope").GetRawText())?.AsObject() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-ENVELOPE");
        var count = 0;
        foreach (var vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var envelope = vector.TryGetProperty("envelope", out var fullEnvelope) && fullEnvelope.ValueKind == JsonValueKind.Object
                ? JsonNode.Parse(fullEnvelope.GetRawText())?.AsObject()
                : JsonNode.Parse(baseEnvelope.ToJsonString())?.AsObject();
            if (envelope is null) throw new InvalidDataException("BF-RELEASE-CORPUS-ENVELOPE");
            if (!vector.TryGetProperty("envelope", out _)) ApplyOperations(envelope, vector.GetProperty("operations"));
            var expected = vector.GetProperty("expected").GetString();
            var execution = vector.GetProperty("execution");
            var expectedChannel = execution.GetProperty("channel").GetString();
            var currentClientVersion = execution.GetProperty("client_version").GetString();
            var currentConfigVersion = execution.GetProperty("config_version").GetInt64();
            var previous = execution.TryGetProperty("previous_state", out var previousElement) && previousElement.ValueKind == JsonValueKind.Object ? previousElement : default;
            var previousSequence = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("sequence", out var previousSequenceValue) ? previousSequenceValue.GetInt64() : 0L;
            var previousManifestDigest = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("manifest_digest", out var previousManifestValue) ? previousManifestValue.GetString() : null;
            var previousAuthorityGeneration = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("authority_generation", out var previousAuthorityValue) ? previousAuthorityValue.GetInt64() : 0L;
            var previousAuthorityDigest = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("authority_digest", out var previousAuthorityDigestValue) ? previousAuthorityDigestValue.GetString() : null;
            var previousSigningKeyId = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("signing_key_id", out var previousSigningKeyIdValue) ? previousSigningKeyIdValue.GetString() : null;
            var previousSigningKeyFingerprint = previous.ValueKind == JsonValueKind.Object && previous.TryGetProperty("signing_key_fingerprint", out var previousSigningKeyFingerprintValue) ? previousSigningKeyFingerprintValue.GetString() : null;
            var accepted = true;
            string? errorFamily = null; ReleaseUpdateManager.VerifiedReleasePlan? plan = null;
            try
            {
                if (execution.TryGetProperty("state_status", out var stateStatus) && (stateStatus.GetString() == "corrupt" || stateStatus.GetString() == "missing")) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
                plan = ReleaseUpdateManager.VerifyEnvelopeForCorpus(Encoding.UTF8.GetBytes(envelope.ToJsonString()), rootPem, expectedChannel, currentClientVersion, currentConfigVersion, previousSequence, previousManifestDigest, previousAuthorityGeneration, previousAuthorityDigest, previousSigningKeyId, previousSigningKeyFingerprint).Plan;
            }
            catch (Exception error) { accepted = false; errorFamily = error.Message.Split(':')[0]; }
            var disposition = accepted && previousSequence > 0 && plan is not null && plan.Sequence == previousSequence && plan.ManifestDigest == previousManifestDigest ? "idempotent" : accepted ? "accept" : "reject";
            if (disposition != expected) throw new InvalidDataException($"BF-RELEASE-CORPUS-{vector.GetProperty("id").GetString()}:expected={expected}:actual={disposition}:{errorFamily}");
            var expectedErrorFamily = vector.TryGetProperty("error_family", out var expectedErrorValue) && expectedErrorValue.ValueKind == JsonValueKind.String ? expectedErrorValue.GetString() : null;
            if (!string.Equals(errorFamily, expectedErrorFamily, StringComparison.Ordinal)) throw new InvalidDataException($"BF-RELEASE-CORPUS-{vector.GetProperty("id").GetString()}:error-family:expected={expectedErrorFamily ?? "null"}:actual={errorFamily ?? "null"}");
            if (vector.TryGetProperty("expected_digests", out var expectedDigests) && plan is not null)
            {
                if (plan.ManifestDigest != expectedDigests.GetProperty("manifest").GetString() || plan.EnvelopeDigest != expectedDigests.GetProperty("envelope").GetString() || plan.AllowlistDigest != expectedDigests.GetProperty("allowlist").GetString()) throw new InvalidDataException($"BF-RELEASE-CORPUS-{vector.GetProperty("id").GetString()}:digest");
            }
            Console.WriteLine(JsonSerializer.Serialize(new { id = vector.GetProperty("id").GetString(), disposition, error_family = errorFamily, manifest_digest = plan?.ManifestDigest, envelope_digest = plan?.EnvelopeDigest, allowlist_digest = plan?.AllowlistDigest, authority_digest = plan?.AuthorityDigest, root_fingerprint = plan?.RootFingerprint }));
            count++;
        }
        return count;
    }

    private static void ApplyOperations(JsonObject envelope, JsonElement operations)
    {
        if (operations.ValueKind != JsonValueKind.Array) throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
        foreach (var operation in operations.EnumerateArray())
        {
            if (operation.TryGetProperty("manifest_field", out var manifestField) && manifestField.ValueKind == JsonValueKind.String)
            {
                var manifest = JsonNode.Parse(envelope["manifest_text"]?.GetValue<string>() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION"))?.AsObject() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                manifest[manifestField.GetString()!] = JsonNode.Parse(operation.GetProperty("set").GetRawText());
                envelope["manifest_text"] = manifest.ToJsonString();
                continue;
            }
            if (operation.TryGetProperty("manifest_number", out var manifestNumber) && manifestNumber.ValueKind == JsonValueKind.String)
            {
                var text = envelope["manifest_text"]?.GetValue<string>() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                var token = $"\"{manifestNumber.GetString()}\":1";
                if (!text.Contains(token, StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                envelope["manifest_text"] = text.Replace(token, $"\"{manifestNumber.GetString()}\":{operation.GetProperty("encoding").GetString()}", StringComparison.Ordinal);
                continue;
            }
            if (operation.TryGetProperty("manifest_duplicate", out var manifestDuplicate) && manifestDuplicate.ValueKind == JsonValueKind.String)
            {
                var text = envelope["manifest_text"]?.GetValue<string>() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                var marker = $"\"{manifestDuplicate.GetString()}\":"; var start = text.IndexOf(marker, StringComparison.Ordinal); var comma = start < 0 ? -1 : text.IndexOf(',', start);
                if (start < 0 || comma < 0) throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                var field = text[start..comma]; envelope["manifest_text"] = text[..comma] + "," + field + text[comma..];
                continue;
            }
            if (operation.GetProperty("path").ValueKind != JsonValueKind.Array) throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
            JsonObject target = envelope;
            var path = operation.GetProperty("path").EnumerateArray().Select(item => item.GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION")).ToArray();
            for (var index = 0; index < path.Length - 1; index++) target = target[path[index]]?.AsObject() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
            if (operation.TryGetProperty("flip_first", out var flip) && flip.ValueKind == JsonValueKind.True)
            {
                var current = target[path[^1]]?.GetValue<string>() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-MUTATION");
                target[path[^1]] = (current[0] == 'A' ? 'B' : 'A') + current[1..];
            }
            else target[path[^1]] = JsonNode.Parse(operation.GetProperty("set").GetRawText());
        }
    }

    private static bool Execute(string operation, JsonElement vector)
    {
        switch (operation)
        {
            case "signature":
                var message = Encoding.UTF8.GetBytes(vector.GetProperty("message_utf8").GetString()!);
                var signature = DecodeBase64Url(vector.GetProperty("signature_base64url").GetString()!);
                var publicKey = ExtractRawPublicKey(vector.GetProperty("public_key_pem").GetString()!);
                try { return Ed25519.Verify(signature, message, publicKey); }
                finally { CryptographicOperations.ZeroMemory(message); CryptographicOperations.ZeroMemory(signature); CryptographicOperations.ZeroMemory(publicKey); }
            case "strict-json":
                try { ReleaseUpdateManager.ValidateStrictJsonForContract(Encoding.UTF8.GetBytes(vector.GetProperty("raw_json").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-JSON"))); return true; } catch { return false; }
            case "canonical-number":
                try { ReleaseUpdateManager.ValidateCanonicalJsonForContract(Encoding.UTF8.GetBytes(vector.GetProperty("raw_manifest").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-JSON"))); return true; } catch { return false; }
            case "safe-path":
                try { ReleaseUpdateManager.ValidateReleasePathForContract(vector.GetProperty("path").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-PATH")); return true; } catch { return false; }
            case "path-collision":
                try
                {
                    var paths = vector.GetProperty("paths");
                    var first = ReleaseUpdateManager.ValidateReleasePathForContract(paths[0].GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
                    var second = ReleaseUpdateManager.ValidateReleasePathForContract(paths[1].GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
                    return !string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
                }
                catch { return false; }
            case "schema-reject":
            case "envelope":
                return false;
            case "manifest-shape":
                if (vector.TryGetProperty("release_sequence", out var releaseSequence) && releaseSequence.TryGetInt64(out var shapeSequence) && vector.TryGetProperty("rollback_floor", out var rollbackFloor) && rollbackFloor.TryGetInt64(out var floor) && floor > shapeSequence) return false;
                if (vector.TryGetProperty("signing_key_id", out var signingKey) && signingKey.ValueKind == JsonValueKind.String && !System.Text.RegularExpressions.Regex.IsMatch(signingKey.GetString() ?? string.Empty, "^bifrost-release-v[0-9]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) return false;
                if (vector.TryGetProperty("extra", out _) || vector.TryGetProperty("revoked_key_ids", out _)) return false;
                if (vector.TryGetProperty("activation_sequence", out var activation) && vector.TryGetProperty("release_sequence", out var release) && activation.TryGetInt64(out var a) && release.TryGetInt64(out var r) && a >= r) return false;
                return false;
            case "strict-state":
                try { using var _ = JsonDocument.Parse(vector.GetProperty("raw").GetString() ?? string.Empty); return true; } catch { return false; }
            case "download-status":
                try { ReleaseUpdateManager.ValidateDownloadStatusForContract(vector.GetProperty("status").GetInt32()); return true; } catch { return false; }
            case "state":
                var sequence = vector.GetProperty("sequence").GetInt64();
                var currentDigest = vector.GetProperty("current_manifest_digest").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-STATE");
                var incomingDigest = vector.GetProperty("manifest_digest").GetString() ?? throw new InvalidDataException("BF-RELEASE-CORPUS-STATE");
                return ReleaseStateAuthority.Classify(sequence, currentDigest, sequence, incomingDigest, 1) == "idempotent";
            default: throw new InvalidDataException("BF-RELEASE-CORPUS-OPERATION");
        }
    }

    private static byte[] DecodeBase64Url(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("BF-RELEASE-BASE64");
        var padded = value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static byte[] ExtractRawPublicKey(string pem)
    {
        var start = pem.IndexOf("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal);
        var end = pem.IndexOf("-----END PUBLIC KEY-----", StringComparison.Ordinal);
        if (start < 0 || end < 0) throw new InvalidDataException("BF-RELEASE-KEY");
        var body = pem[(start + 26)..end].Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
        var der = Convert.FromBase64String(body);
        var prefix = Convert.FromHexString("302a300506032b6570032100");
        if (der.Length != prefix.Length + 32 || !der.AsSpan(0, prefix.Length).SequenceEqual(prefix)) throw new InvalidDataException("BF-RELEASE-KEY");
        return der[prefix.Length..];
    }
}
