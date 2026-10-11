using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost;
using Bifrost.Release;

namespace Bifrost.ClientService;

/// <summary>
/// LocalSystem-side importer for Control-signed client configuration.
/// The desktop UI may choose only signed source/candidate/profile identifiers;
/// it never supplies the final Mihomo runtime package accepted by the service.
/// </summary>
internal static class SignedClientPackageImporter
{
    internal const int MaxSignedConfigBytes = 512 * 1024;
    internal const int MaxSignedEnvelopeBytes = 768 * 1024;
    private const int MaxKeyStateBytes = 64 * 1024;
    private const int MaxSignedJsonDepth = 32;
    private const string StateName = ".signed-import-state.json";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static ClientPackageStageResult Import(string root, ServiceCommand command) =>
        ImportCore(root, command);

    private static ClientPackageStageResult ImportCore(string root, ServiceCommand command)
    {
        if (!ReleaseContract.TrustRootProvisioned || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootPem) ||
            string.IsNullOrWhiteSpace(ReleaseContract.TrustRootFingerprint))
            throw new ServiceFailure("BF-CONFIG-TRUST-ROOT");
        if (command.ConfigVersion <= 0 || !IsDigest(command.ConfigContentDigest) ||
            string.IsNullOrWhiteSpace(command.SignedConfigJson) || string.IsNullOrWhiteSpace(command.SignedEnvelopeJson) ||
            string.IsNullOrWhiteSpace(command.ConfigKeyStateJson) || string.IsNullOrWhiteSpace(command.SelectedCandidate))
            throw new ServiceFailure("BF-CONFIG-SIGNED-PACKAGE-REQUIRED");

        // Establish the protected ProgramData ACL before reading rollback
        // authority. The importer must not trust a state file from a directory
        // that has only been path-checked but not ownership/ACL-checked yet.
        ClientPackageStager.EnsureDirectory(root);
        var previous = ReadState(root);
        if (previous is not null)
        {
            if (command.ConfigVersion < previous.ConfigVersion) throw new ServiceFailure("BF-CONFIG-ANTI-ROLLBACK");
            if (command.ConfigVersion == previous.ConfigVersion && !string.Equals(command.ConfigContentDigest, previous.ContentDigest, StringComparison.Ordinal))
                throw new ServiceFailure("BF-CONFIG-EQUIVOCATION");
        }

        var keyState = ParseObject(command.ConfigKeyStateJson!, MaxKeyStateBytes, "BF-CONFIG-KEY-STATE");
        VerifiedConfigKeyState verifiedState;
        try
        {
            verifiedState = ConfigKeyTrust.Verify(
                keyState,
                ReleaseContract.TrustRootKeyId,
                ReleaseContract.TrustRootPem,
                ReleaseContract.TrustRootFingerprint,
                previous?.KeyStateGeneration ?? 0,
                previous?.KeyStateDigest,
                command.ConfigVersion);
        }
        catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }
        catch { throw new ServiceFailure("BF-CONFIG-KEY-STATE"); }

        var envelope = ParseObject(command.SignedEnvelopeJson!, MaxSignedEnvelopeBytes, "BF-CONFIG-PACKAGE");
        VerifyEnvelope(envelope, command.ConfigVersion, command.ConfigContentDigest!, verifiedState);

        var config = ParseObject(command.SignedConfigJson!, MaxSignedConfigBytes, "BF-CONFIG-SCHEMA");
        var canonicalConfig = ConfigKeyTrust.Canonical(config);
        if (!string.Equals(canonicalConfig, command.SignedConfigJson, StringComparison.Ordinal) ||
            !string.Equals(Sha256(canonicalConfig), command.ConfigContentDigest, StringComparison.Ordinal))
            throw new ServiceFailure("BF-CONFIG-DIGEST");
        if (config["schema_version"]?.GetValue<string>() != "1.0" ||
            config["config_version"]?.GetValue<long>() != command.ConfigVersion ||
            config["anti_rollback"]?.GetValue<long>() != command.ConfigVersion)
            throw new ServiceFailure("BF-CONFIG-SCHEMA");

        ClientPackageInput input;
        try { input = CompileSignedConfig(config, command); }
        catch (JsonException) { throw new ServiceFailure("BF-CONFIG-COMPILE-JSON"); }
        try
        {
            ClientPackageStageResult staged;
            try { staged = ClientPackageStager.Stage(root, input); }
            catch (JsonException) { throw new ServiceFailure("BF-CONFIG-STAGE-JSON"); }
            try { WriteState(root, new ImportState(command.ConfigVersion, command.ConfigContentDigest!, verifiedState.Generation, verifiedState.Digest)); }
            catch
            {
                try { ClientPackageStager.RemoveStaged(root, staged.ConfigId); } catch { }
                throw;
            }
            return staged;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input.MainConfigUtf8);
            CryptographicOperations.ZeroMemory(input.ProviderConfigUtf8);
        }
    }

    /// <summary>
    /// Import several manual candidates from one immutable Control-signed
    /// configuration.  The trust root, key-state transition, signed envelope
    /// and canonical config bytes are verified once, then only the
    /// candidate-dependent compiled runtime graph is produced per label.
    ///
    /// This is intentionally narrower than repeatedly calling Import: all
    /// candidates share the exact same signed config/version/policy and the
    /// durable anti-rollback state is committed once after every staged
    /// package succeeds.  A partial failure removes every package created by
    /// this batch before returning.
    /// </summary>
    internal static IReadOnlyList<(string Label, ClientPackageStageResult Package)> ImportBatch(
        string root,
        ServiceCommand command,
        IReadOnlyList<string> candidateLabels)
    {
        if (candidateLabels is null || candidateLabels.Count is < 1 or > 600 ||
            candidateLabels.Any(label => string.IsNullOrWhiteSpace(label) || label.Length > 96 ||
                label.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.'))) ||
            candidateLabels.Distinct(StringComparer.Ordinal).Count() != candidateLabels.Count)
            throw new ServiceFailure("BF-LATENCY-CONFIG");
        if (!ReleaseContract.TrustRootProvisioned || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootPem) ||
            string.IsNullOrWhiteSpace(ReleaseContract.TrustRootFingerprint))
            throw new ServiceFailure("BF-CONFIG-TRUST-ROOT");
        if (command.ConfigVersion <= 0 || !IsDigest(command.ConfigContentDigest) ||
            string.IsNullOrWhiteSpace(command.SignedConfigJson) || string.IsNullOrWhiteSpace(command.SignedEnvelopeJson) ||
            string.IsNullOrWhiteSpace(command.ConfigKeyStateJson))
            throw new ServiceFailure("BF-CONFIG-SIGNED-PACKAGE-REQUIRED");

        ClientPackageStager.EnsureDirectory(root);
        var previous = ReadState(root);
        if (previous is not null)
        {
            if (command.ConfigVersion < previous.ConfigVersion) throw new ServiceFailure("BF-CONFIG-ANTI-ROLLBACK");
            if (command.ConfigVersion == previous.ConfigVersion && !string.Equals(command.ConfigContentDigest, previous.ContentDigest, StringComparison.Ordinal))
                throw new ServiceFailure("BF-CONFIG-EQUIVOCATION");
        }

        var keyState = ParseObject(command.ConfigKeyStateJson!, MaxKeyStateBytes, "BF-CONFIG-KEY-STATE");
        VerifiedConfigKeyState verifiedState;
        try
        {
            verifiedState = ConfigKeyTrust.Verify(
                keyState,
                ReleaseContract.TrustRootKeyId,
                ReleaseContract.TrustRootPem,
                ReleaseContract.TrustRootFingerprint,
                previous?.KeyStateGeneration ?? 0,
                previous?.KeyStateDigest,
                command.ConfigVersion);
        }
        catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }
        catch { throw new ServiceFailure("BF-CONFIG-KEY-STATE"); }

        var envelope = ParseObject(command.SignedEnvelopeJson!, MaxSignedEnvelopeBytes, "BF-CONFIG-PACKAGE");
        VerifyEnvelope(envelope, command.ConfigVersion, command.ConfigContentDigest!, verifiedState);
        var config = ParseObject(command.SignedConfigJson!, MaxSignedConfigBytes, "BF-CONFIG-SCHEMA");
        var canonicalConfig = ConfigKeyTrust.Canonical(config);
        if (!string.Equals(canonicalConfig, command.SignedConfigJson, StringComparison.Ordinal) ||
            !string.Equals(Sha256(canonicalConfig), command.ConfigContentDigest, StringComparison.Ordinal))
            throw new ServiceFailure("BF-CONFIG-DIGEST");
        if (config["schema_version"]?.GetValue<string>() != "1.0" ||
            config["config_version"]?.GetValue<long>() != command.ConfigVersion ||
            config["anti_rollback"]?.GetValue<long>() != command.ConfigVersion)
            throw new ServiceFailure("BF-CONFIG-SCHEMA");

        var staged = new List<(string Label, ClientPackageStageResult Package)>(candidateLabels.Count);
        try
        {
            foreach (var label in candidateLabels)
            {
                ClientPackageInput input;
                try { input = CompileSignedConfig(config, command with { SelectedCandidate = label, Candidates = null }); }
                catch (JsonException) { throw new ServiceFailure("BF-CONFIG-COMPILE-JSON"); }
                try
                {
                    ClientPackageStageResult package;
                    // Batch latency packages are verified again on Resolve
                    // before use and are deleted at the end of this one
                    // operation. They are not recovery authority, so avoid
                    // forcing every candidate file through durable disk I/O.
                    try { package = ClientPackageStager.Stage(root, input, durable: false); }
                    catch (JsonException) { throw new ServiceFailure("BF-CONFIG-STAGE-JSON"); }
                    staged.Add((label, package));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(input.MainConfigUtf8);
                    CryptographicOperations.ZeroMemory(input.ProviderConfigUtf8);
                }
            }
            try { WriteState(root, new ImportState(command.ConfigVersion, command.ConfigContentDigest!, verifiedState.Generation, verifiedState.Digest)); }
            catch
            {
                foreach (var item in staged)
                    try { ClientPackageStager.RemoveStaged(root, item.Package.ConfigId); } catch { }
                throw;
            }
            return staged;
        }
        catch
        {
            foreach (var item in staged)
                try { ClientPackageStager.RemoveStaged(root, item.Package.ConfigId); } catch { }
            throw;
        }
    }

    private static void VerifyEnvelope(JsonObject envelope, long expectedVersion, string expectedContentDigest, VerifiedConfigKeyState trustState)
    {
        var required = new HashSet<string>(StringComparer.Ordinal)
        {
            "alg", "key_id", "config_version", "anti_rollback", "content_digest",
            "ephemeral_public_key", "salt", "iv", "ciphertext", "tag", "signature"
        };
        if (envelope.Count != required.Count || envelope.Any(pair => !required.Contains(pair.Key)) ||
            envelope["alg"]?.GetValue<string>() != "X25519-HKDF-SHA256-AES-256-GCM" ||
            envelope["config_version"]?.GetValue<long>() != expectedVersion ||
            envelope["anti_rollback"]?.GetValue<long>() != expectedVersion ||
            !string.Equals(envelope["content_digest"]?.GetValue<string>(), expectedContentDigest, StringComparison.Ordinal))
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var keyId = envelope["key_id"]?.GetValue<string>() ?? string.Empty;
        ConfigSigningTrustedKey leaf;
        try { leaf = trustState.Select(keyId, expectedVersion); }
        catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }

        var signatureText = envelope["signature"]?.GetValue<string>() ?? string.Empty;
        byte[]? signature = null, payload = null, publicKey = null, ephemeral = null, salt = null, iv = null, tag = null, ciphertext = null;
        try
        {
            signature = DecodeBase64Url(signatureText, 64, "BF-CONFIG-SIGNATURE");
            ephemeral = DecodeBase64Url(envelope["ephemeral_public_key"]?.GetValue<string>() ?? string.Empty, 44, "BF-CONFIG-CRYPTO");
            if (!ephemeral.AsSpan(0, 12).SequenceEqual(new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 }))
                throw new ServiceFailure("BF-CONFIG-CRYPTO");
            salt = DecodeBase64Url(envelope["salt"]?.GetValue<string>() ?? string.Empty, 16, "BF-CONFIG-CRYPTO");
            iv = DecodeBase64Url(envelope["iv"]?.GetValue<string>() ?? string.Empty, 12, "BF-CONFIG-CRYPTO");
            tag = DecodeBase64Url(envelope["tag"]?.GetValue<string>() ?? string.Empty, 16, "BF-CONFIG-CRYPTO");
            ciphertext = DecodeBase64UrlBounded(envelope["ciphertext"]?.GetValue<string>() ?? string.Empty, MaxSignedConfigBytes, "BF-CONFIG-CRYPTO");
            var unsigned = envelope.DeepClone().AsObject(); unsigned.Remove("signature");
            payload = StrictUtf8.GetBytes(ConfigKeyTrust.Canonical(unsigned));
            publicKey = ConfigKeyTrust.RawPublicKey(leaf.PublicKeyPem);
            if (!Ed25519.Verify(signature, payload, publicKey)) throw new ServiceFailure("BF-CONFIG-SIGNATURE");
        }
        finally
        {
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (payload is not null) CryptographicOperations.ZeroMemory(payload);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (ephemeral is not null) CryptographicOperations.ZeroMemory(ephemeral);
            if (salt is not null) CryptographicOperations.ZeroMemory(salt);
            if (iv is not null) CryptographicOperations.ZeroMemory(iv);
            if (tag is not null) CryptographicOperations.ZeroMemory(tag);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static ClientPackageInput CompileSignedConfig(
        JsonObject config,
        ServiceCommand command)
    {
        var mode = command.Mode ?? throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var sourceCode = command.Source ?? throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var country = command.Country ?? throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var policy = ApplicationPolicySnapshot.Parse(command.AppPolicySnapshot ?? throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT"));
        if (!string.Equals(policy.Digest, command.AppPolicyDigest, StringComparison.Ordinal) ||
            !string.Equals(policy.Generation, command.AppPolicyGeneration, StringComparison.Ordinal) || policy.RouteMode != mode)
            throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");

        var source = Source(config, sourceCode);
        _ = Candidate(source, command.SelectedCandidate!);
        _ = source["transport"] as JsonObject ?? throw new ServiceFailure("BF-CONFIG-TRANSPORT");
        var connectionType = command.ConnectionType ?? throw new ServiceFailure("BF-CONNECTION-TYPE");
        if (connectionType == "direct-vmess")
        {
            if (!string.Equals(country, "default", StringComparison.Ordinal) ||
                !string.IsNullOrWhiteSpace(command.FrontSource) || !string.IsNullOrWhiteSpace(command.FrontCandidate))
                throw new ServiceFailure("BF-CONNECTION-TYPE");
            _ = Profile(source, "default");
        }
        else if (connectionType == "smartgate")
        {
            if (string.Equals(country, "default", StringComparison.OrdinalIgnoreCase))
                throw new ServiceFailure("BF-CONNECTION-TYPE");
            _ = Profile(source, "default");
            var countryObject = (config["countries"] as JsonArray)?.OfType<JsonObject>()
                .FirstOrDefault(item => string.Equals(item["code"]?.GetValue<string>(), country, StringComparison.OrdinalIgnoreCase))
                ?? throw new ServiceFailure("BF-CONFIG-COUNTRY");
            if (countryObject["status"]?.GetValue<string>() != "enabled") throw new ServiceFailure("BF-CONFIG-COUNTRY");
            _ = countryObject["socks"] as JsonObject ?? throw new ServiceFailure("BF-SMARTGATE-SOCKS");
            var mapped = countryObject["front_source_code"]?.GetValue<string>()?.Trim();
            var allowed = (countryObject["front_source_options"] as JsonArray)?.OfType<JsonValue>().Select(v => v.GetValue<string>()).ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new();
            var requestedFront = command.FrontSource?.Trim();
            var explicitRequest = !string.IsNullOrWhiteSpace(requestedFront) && !string.Equals(requestedFront, "auto", StringComparison.OrdinalIgnoreCase);
            var resolvedFront = explicitRequest ? requestedFront! : string.IsNullOrWhiteSpace(mapped) ? sourceCode : mapped!;
            if (explicitRequest && (!string.IsNullOrWhiteSpace(mapped) || allowed.Count > 0))
            {
                var explicitlyAuthorized = allowed.Count > 0 && allowed.Contains(resolvedFront) ||
                    allowed.Count == 0 && string.Equals(mapped, resolvedFront, StringComparison.OrdinalIgnoreCase);
                if (!explicitlyAuthorized) throw new ServiceFailure("BF-SMARTGATE-FRONT-NOT-MAPPED");
            }
            if (!string.Equals(resolvedFront, sourceCode, StringComparison.OrdinalIgnoreCase))
            {
                var authorized = allowed.Count > 0 && allowed.Contains(resolvedFront) ||
                    allowed.Count == 0 && string.Equals(mapped, resolvedFront, StringComparison.OrdinalIgnoreCase);
                if (!authorized || explicitRequest && string.IsNullOrWhiteSpace(mapped) && allowed.Count == 0)
                    throw new ServiceFailure("BF-SMARTGATE-FRONT-NOT-MAPPED");
                var front = Source(config, resolvedFront);
                _ = Candidate(front, command.FrontCandidate ?? throw new ServiceFailure("BF-SMARTGATE-FRONT-CANDIDATE"));
                _ = front["transport"] as JsonObject ?? throw new ServiceFailure("BF-SMARTGATE-FRONT-TRANSPORT");
            }
            else if (!string.IsNullOrWhiteSpace(command.FrontCandidate)) throw new ServiceFailure("BF-SMARTGATE-FRONT-CANDIDATE");
        }
        else throw new ServiceFailure("BF-CONNECTION-TYPE");

        var corePolicy = config["core_policy"] as JsonObject ?? throw new ServiceFailure("BF-CONFIG-CORE");
        var requestedCore = command.Core ?? "auto";
        var defaultCore = corePolicy["default"]?.GetValue<string>() ?? "mihomo";
        var allowedCores = (corePolicy["allowed"] as JsonArray)?.OfType<JsonValue>().Select(v => v.GetValue<string>()).ToHashSet(StringComparer.Ordinal) ?? new();
        if (requestedCore is not ("auto" or "mihomo") || defaultCore != "mihomo" ||
            allowedCores.Count != 1 || !allowedCores.Contains("mihomo")) throw new ServiceFailure("BF-CONFIG-CORE");
        const string effectiveCore = "mihomo";

        _ = ValidateDnsPolicy(config);
        // Every Mihomo VMess socket is bound to the verified physical
        // underlay, which remains safe before and after the Bifrost /1 route
        // cutover. No user-session proxy or legacy core participates.
        // Every production graph is compiled against the physical underlay,
        // including when another transparent tunnel is present. Bifrost starts its TUN
        // route-neutral and commits host routes only after a canary succeeds;
        // once those /1 routes are present, an unbound VMess socket could
        // otherwise be captured by Bifrost itself and form a recursive loop.
        // Failing to identify a real physical egress is therefore a reason to
        // refuse staging, never a reason to fall back to an unsafe auto-route
        // startup.
        if (!OwnedTunNetworkBoundary.TryGetPhysicalUnderlay(out var physicalUnderlay) ||
            string.IsNullOrWhiteSpace(physicalUnderlay))
            throw new ServiceFailure("BF-CONFIG-ROUTE");
        var clashApiPort = AllocateMihomoPortPairBase();
        string controllerSecret;
        var controllerSecretBytes = RandomNumberGenerator.GetBytes(48);
        try { controllerSecret = Convert.ToBase64String(controllerSecretBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
        finally { CryptographicOperations.ZeroMemory(controllerSecretBytes); }
        var mihomo = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            config,
            sourceCode,
            connectionType,
            mode,
            mode == "global" ? command.SelectedCandidate : null,
            country,
            policy,
            physicalUnderlay,
            clashApiPort,
            controllerSecret,
            "bifrost1",
            "providers/source-" + sourceCode.ToLowerInvariant() + ".json",
            null,
            command.FrontSource,
            command.FrontCandidate,
            EnableIpv6: System.Net.Sockets.Socket.OSSupportsIPv6));
        return new ClientPackageInput(mode, effectiveCore, sourceCode, country, policy.PolicyMode,
            mihomo.MainConfig, mihomo.Provider, policy);
    }

    private static int AllocateMihomoPortPairBase()
    {
        for (var attempt = 0; attempt < 64; attempt++)
        {
            var port = RandomNumberGenerator.GetInt32(20000, MihomoWindowsContract.ControllerPortMax);
            if (PortBindingProbe.CanBindTcpExclusive(port) && PortBindingProbe.CanBindTcpExclusive(port + 1)) return port;
        }
        throw new ServiceFailure("BF-CORE-PORT-IN-USE");
    }

    private static JsonObject Source(JsonObject config, string code) =>
        (config["sources"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(item =>
            string.Equals(item["code"]?.GetValue<string>(), code, StringComparison.OrdinalIgnoreCase) && item["configured"]?.GetValue<bool>() == true)
        ?? throw new ServiceFailure("BF-CONFIG-SOURCE");

    private static JsonObject Candidate(JsonObject source, string label) =>
        (source["candidates"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(item => string.Equals(item["label"]?.GetValue<string>(), label, StringComparison.Ordinal))
        ?? throw new ServiceFailure("BF-CONFIG-CANDIDATE-NOT-IN-SOURCE");

    private static JsonObject Profile(JsonObject source, string country)
    {
        var profiles = source["profiles"] as JsonObject ?? throw new ServiceFailure("BF-PROFILE-MISSING");
        var profile = string.Equals(country, "default", StringComparison.OrdinalIgnoreCase)
            ? profiles["direct"] as JsonObject ?? throw new ServiceFailure("BF-PROFILE-MISSING")
            : (profiles["countries"] as JsonObject)?[country] as JsonObject ?? throw new ServiceFailure("BF-PROFILE-MISSING");
        var uuid = profile["uuid"]?.GetValue<string>();
        if (profile.Any(property => property.Key is not ("profile_id" or "uuid")) ||
            string.IsNullOrWhiteSpace(uuid) || !Guid.TryParseExact(uuid, "D", out _))
            throw new ServiceFailure("BF-PROFILE-SHAPE");
        return profile;
    }

    private static JsonObject ValidateDnsPolicy(JsonObject config)
    {
        var dns = ((config["routing"] as JsonObject)?["dns_policy"] as JsonObject) ?? throw new ServiceFailure("BF-DNS-POLICY-MISSING");
        var allowed = new HashSet<string>(StringComparer.Ordinal)
            { "version", "remote", "direct", "smart_gate_remote", "plaintext_fallback", "ipv4", "ipv6", "failure" };
        if (dns.Count != allowed.Count || dns.Any(property => !allowed.Contains(property.Key)) ||
            dns["version"]?.GetValue<string>() != "dns-policy-v1" || dns["smart_gate_remote"]?.GetValue<bool>() != true ||
            dns["plaintext_fallback"]?.GetValue<bool>() != false || dns["failure"]?.GetValue<string>() != "block" ||
            dns["ipv4"]?.GetValue<string>() is not ("proxy" or "block") || dns["ipv6"]?.GetValue<string>() is not ("proxy" or "block"))
            throw new ServiceFailure("BF-DNS-POLICY");
        return dns;
    }

    private static string Dns(JsonObject dns, string name)
    {
        var value = dns[name]?.GetValue<string>() ?? throw new ServiceFailure("BF-DNS-POLICY-MISSING");
        var hostIsIp = false;
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsedForHost))
            hostIsIp = System.Net.IPAddress.TryParse(parsedForHost.Host.TrimEnd('.'), out _);
#if BIFROST_RELEASE_TRUST_ROOT_TEST_ONLY
        const bool allowLiteralIpDns = true;
#else
        const bool allowLiteralIpDns = false;
#endif
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            (uri.Port != -1 && uri.Port != 443) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
            (hostIsIp && !allowLiteralIpDns) || uri.Host.TrimEnd('.').Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.TrimEnd('.').EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) || uri.Host.TrimEnd('.').Equals("test", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.TrimEnd('.').EndsWith(".test", StringComparison.OrdinalIgnoreCase))
            throw new ServiceFailure("BF-DNS-POLICY");
        return value;
    }

    private static JsonObject ParseObject(string text, int maxBytes, string code)
    {
        byte[]? bytes = null;
        try
        {
            bytes = StrictUtf8.GetBytes(text);
            if (bytes.Length <= 0 || bytes.Length > maxBytes) throw new ServiceFailure(code);
            // Signed Control configuration is not an IPC envelope.  It has a
            // separately bounded schema and can legitimately be deeper than
            // BifrostIpcWire's deliberately shallow MaxDepth=8 request frame.
            // Keep duplicate-key rejection and a hard depth ceiling here,
            // without weakening the IPC parser itself.
            using var strict = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = MaxSignedJsonDepth,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false
            });
            ValidateNoDuplicateKeys(strict.RootElement, 0);
            if (strict.RootElement.ValueKind != JsonValueKind.Object) throw new ServiceFailure(code);
            return JsonNode.Parse(bytes, nodeOptions: null, documentOptions: new JsonDocumentOptions
            {
                MaxDepth = MaxSignedJsonDepth,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false
            })?.AsObject() ?? throw new ServiceFailure(code);
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure(code); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateNoDuplicateKeys(JsonElement element, int depth)
    {
        if (depth > MaxSignedJsonDepth) throw new ServiceFailure("BF-CONFIG-JSON");
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new ServiceFailure("BF-CONFIG-JSON");
                ValidateNoDuplicateKeys(property.Value, depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) ValidateNoDuplicateKeys(item, depth + 1);
        }
    }

    private static byte[] DecodeBase64Url(string value, int expectedBytes, string code)
    {
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/'); padded += new string('=', (4 - padded.Length % 4) % 4);
            var bytes = Convert.FromBase64String(padded);
            var canonical = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (bytes.Length != expectedBytes || canonical != value) { CryptographicOperations.ZeroMemory(bytes); throw new ServiceFailure(code); }
            return bytes;
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure(code); }
    }

    private static byte[] DecodeBase64UrlBounded(string value, int maxBytes, string code)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > ((maxBytes + 2) / 3) * 4 + 4) throw new ServiceFailure(code);
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/'); padded += new string('=', (4 - padded.Length % 4) % 4);
            var bytes = Convert.FromBase64String(padded);
            var canonical = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (bytes.Length <= 0 || bytes.Length > maxBytes || canonical != value) { CryptographicOperations.ZeroMemory(bytes); throw new ServiceFailure(code); }
            return bytes;
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure(code); }
    }

    private static ImportState? ReadState(string root)
    {
        var path = Path.Combine(root, StateName);
        if (Directory.Exists(path)) throw new ServiceFailure("BF-CONFIG-LKG");
        if (!File.Exists(path)) return null;
        byte[] bytes;
        try { bytes = BifrostIpcWire.ReadBoundedFile(path, 4096); }
        catch { throw new ServiceFailure("BF-CONFIG-LKG"); }
        try
        {
            using var doc = BifrostIpcWire.ParseStrict(bytes);
            var rootElement = doc.RootElement;
            if (rootElement.ValueKind != JsonValueKind.Object ||
                !rootElement.EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal).SetEquals(
                    new[] { "ConfigVersion", "ContentDigest", "KeyStateGeneration", "KeyStateDigest" }))
                throw new ServiceFailure("BF-CONFIG-LKG");
            if (!rootElement.TryGetProperty("ConfigVersion", out var configVersionElement) || !configVersionElement.TryGetInt64(out var configVersion) ||
                !rootElement.TryGetProperty("ContentDigest", out var contentDigestElement) || contentDigestElement.ValueKind != JsonValueKind.String ||
                !rootElement.TryGetProperty("KeyStateGeneration", out var generationElement) || !generationElement.TryGetInt64(out var keyStateGeneration) ||
                !rootElement.TryGetProperty("KeyStateDigest", out var keyStateDigestElement) || keyStateDigestElement.ValueKind != JsonValueKind.String)
                throw new ServiceFailure("BF-CONFIG-LKG");
            var state = new ImportState(configVersion, contentDigestElement.GetString() ?? string.Empty, keyStateGeneration, keyStateDigestElement.GetString() ?? string.Empty);
            if (state.ConfigVersion <= 0 || !IsDigest(state.ContentDigest) || state.KeyStateGeneration <= 0 || !IsDigest(state.KeyStateDigest)) throw new ServiceFailure("BF-CONFIG-LKG");
            return state;
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-CONFIG-LKG"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void WriteState(string root, ImportState state)
    {
        var target = Path.Combine(root, StateName); var temp = Path.Combine(root, ".signed-state-" + Guid.NewGuid().ToString("N") + ".tmp");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(bytes); stream.Flush(true); }
            File.Move(temp, target, overwrite: true);
            var readback = ReadState(root);
            if (readback != state) throw new ServiceFailure("BF-CONFIG-LKG");
        }
        catch { try { File.Delete(temp); } catch { } throw new ServiceFailure("BF-CONFIG-LKG"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static bool IsDigest(string? value) => value?.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Sha256(string text) { var bytes = StrictUtf8.GetBytes(text); try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    private sealed record ImportState(long ConfigVersion, string ContentDigest, long KeyStateGeneration, string KeyStateDigest);
}
