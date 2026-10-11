using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Bifrost.ClientService;

/// <summary>
/// The only post-verification runtime package accepted on Windows. The
/// LocalSystem importer compiles both files from one Control-signed document;
/// neither JSON file is accepted from the desktop process.
/// </summary>
public sealed record ClientPackageInput(
    string Mode,
    string Core,
    string Source,
    string Country,
    string AppPolicy,
    byte[] MainConfigUtf8,
    byte[] ProviderConfigUtf8,
    ApplicationPolicySnapshot ApplicationPolicy);

public sealed record ClientPackageStageResult(
    string ConfigId,
    string Mode,
    string Core,
    string Source,
    string Country,
    string AppPolicy,
    string MainSha256,
    string ProviderSha256,
    string ApplicationPolicyDigest,
    string ApplicationPolicyGeneration);

public sealed record ClientPackageResolved(
    string ConfigId,
    string Mode,
    string Core,
    string Source,
    string Country,
    string AppPolicy,
    string MainConfigPath,
    string ProviderConfigPath,
    string MainSha256,
    string ProviderSha256,
    string ApplicationPolicyDigest,
    string ApplicationPolicyGeneration,
    ApplicationPolicySnapshot ApplicationPolicySnapshot);

public static class ClientPackageValidator
{
    public const int MaxConfigBytes = 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static ApplicationPolicySnapshot ParseApplicationPolicy(string mode, string appPolicy)
    {
        if (string.IsNullOrWhiteSpace(appPolicy)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        if (appPolicy.TrimStart().StartsWith("{", StringComparison.Ordinal))
        {
            var parsed = ApplicationPolicySnapshot.Parse(appPolicy);
            if (parsed.RouteMode != mode) throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
            return parsed;
        }
        if (mode == "per-app") throw new ServiceFailure("BF-APP-POLICY-MISSING");
        if (appPolicy is not ("allow" or "exclude" or "none")) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        return ApplicationPolicySnapshot.Create(mode, "none", Array.Empty<string>(), Array.Empty<string>(),
            "00000000000000000000000000000000");
    }

    internal static JsonDocument ParseMetadata(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is <= 0 or > MaxConfigBytes) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        try { _ = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException) { throw new ServiceFailure("BF-CONFIG-PACKAGE"); }
        RejectDuplicateProperties(bytes);
        try
        {
            var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new ServiceFailure("BF-CONFIG-PACKAGE");
            }
            return document;
        }
        catch (ServiceFailure) { throw; }
        catch (JsonException) { throw new ServiceFailure("BF-CONFIG-PACKAGE"); }
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes)
    {
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            var objectProperties = new Stack<HashSet<string>>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.StartObject)
                    objectProperties.Push(new HashSet<string>(StringComparer.Ordinal));
                else if (reader.TokenType == JsonTokenType.EndObject)
                    objectProperties.Pop();
                else if (reader.TokenType == JsonTokenType.PropertyName &&
                    (objectProperties.Count == 0 || !objectProperties.Peek().Add(reader.GetString() ?? string.Empty)))
                    throw new ServiceFailure("BF-CONFIG-PACKAGE");
            }
        }
        catch (ServiceFailure) { throw; }
        catch (JsonException) { throw new ServiceFailure("BF-CONFIG-PACKAGE"); }
    }
}

public static class ClientPackageStager
{
    private static readonly string[] ExactPackageFiles = ["mihomo.json", "package.json", "provider.json"];

    public static ClientPackageStageResult Stage(string root, ClientPackageInput input, bool durable = true)
    {
        if (input.Core != "mihomo" || input.Mode is not ("smart" or "global" or "per-app") ||
            !IsToken(input.Source) || input.Source.Equals("auto", StringComparison.OrdinalIgnoreCase) ||
            !IsToken(input.Country) || input.Country.Equals("auto", StringComparison.OrdinalIgnoreCase) ||
            input.MainConfigUtf8.Length is <= 0 or > ClientPackageValidator.MaxConfigBytes ||
            input.ProviderConfigUtf8.Length is <= 0 or > ClientPackageValidator.MaxConfigBytes)
            throw new ServiceFailure("BF-CONFIG-PACKAGE");

        var verifiedPolicy = ApplicationPolicySnapshot.Parse(input.ApplicationPolicy.CanonicalJson);
        if (verifiedPolicy != input.ApplicationPolicy || verifiedPolicy.RouteMode != input.Mode ||
            verifiedPolicy.PolicyMode != input.AppPolicy)
            throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
        try { MihomoConfigValidator.ValidateStaged(input.MainConfigUtf8, input.ProviderConfigUtf8, input.Source, input.Mode, verifiedPolicy); }
        catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }

        EnsureDirectory(root);
        var id = "cfg_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var temp = Path.Combine(root, ".stage_" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, id);
        try
        {
            Directory.CreateDirectory(temp);
            var mainDigest = Digest(input.MainConfigUtf8);
            var providerDigest = Digest(input.ProviderConfigUtf8);
            WriteFile(Path.Combine(temp, "mihomo.json"), input.MainConfigUtf8, durable);
            WriteFile(Path.Combine(temp, "provider.json"), input.ProviderConfigUtf8, durable);
            var metadata = JsonSerializer.SerializeToUtf8Bytes(new
            {
                config_id = id,
                source = input.Source,
                country = input.Country,
                mode = input.Mode,
                core = "mihomo",
                app_policy = input.AppPolicy,
                app_policy_snapshot = verifiedPolicy.CanonicalJson,
                app_policy_digest = verifiedPolicy.Digest,
                app_policy_generation = verifiedPolicy.Generation,
                main_sha256 = mainDigest,
                provider_sha256 = providerDigest,
            });
            try { WriteFile(Path.Combine(temp, "package.json"), metadata, durable); }
            finally { CryptographicOperations.ZeroMemory(metadata); }
            if (Directory.Exists(target) || File.Exists(target)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
            Directory.Move(temp, target);
            return new ClientPackageStageResult(id, input.Mode, "mihomo", input.Source, input.Country,
                input.AppPolicy, mainDigest, providerDigest, verifiedPolicy.Digest, verifiedPolicy.Generation);
        }
        catch
        {
            TryDeleteOwned(temp);
            throw;
        }
    }

    public static ClientPackageResolved Resolve(string root, string id, string mode, string core,
        string source, string country, string appPolicy) =>
        Resolve(root, id, mode, core, source, country, ClientPackageValidator.ParseApplicationPolicy(mode, appPolicy));

    public static ClientPackageResolved Resolve(string root, string id, string mode, string core,
        string source, string country, ApplicationPolicySnapshot applicationPolicy)
    {
        if (core != "mihomo") throw new ServiceFailure("BF-CONFIG-CORE");
        var verifiedPolicy = ApplicationPolicySnapshot.Parse(applicationPolicy.CanonicalJson);
        if (verifiedPolicy != applicationPolicy || verifiedPolicy.RouteMode != mode)
            throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
        if (!IsId(id)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        EnsureDirectory(root);
        var target = Path.GetFullPath(Path.Combine(root, id));
        if (!IsContained(root, target)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        RejectReparse(target, true);
        var names = Directory.EnumerateFileSystemEntries(target).Select(Path.GetFileName)
            .Where(name => name is not null).Select(name => name!).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        if (!names.SequenceEqual(ExactPackageFiles, StringComparer.Ordinal)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        foreach (var name in names) RejectReparse(Path.Combine(target, name), false);

        var metadataBytes = ReadLimited(Path.Combine(target, "package.json"));
        try
        {
            using var metadataDocument = ClientPackageValidator.ParseMetadata(metadataBytes);
            var metadata = metadataDocument.RootElement;
            var required = new HashSet<string>(StringComparer.Ordinal)
            {
                "config_id", "source", "country", "mode", "core", "app_policy", "app_policy_snapshot",
                "app_policy_digest", "app_policy_generation", "main_sha256", "provider_sha256",
            };
            if (!metadata.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal).SetEquals(required) ||
                !StringEquals(metadata, "config_id", id) || !StringEquals(metadata, "source", source) ||
                !StringEquals(metadata, "country", country) || !StringEquals(metadata, "mode", mode) ||
                !StringEquals(metadata, "core", "mihomo") || !StringEquals(metadata, "app_policy", verifiedPolicy.PolicyMode) ||
                !StringEquals(metadata, "app_policy_snapshot", verifiedPolicy.CanonicalJson) ||
                !StringEquals(metadata, "app_policy_digest", verifiedPolicy.Digest) ||
                !StringEquals(metadata, "app_policy_generation", verifiedPolicy.Generation))
                throw new ServiceFailure("BF-CONFIG-PACKAGE");

            var mainPath = Path.Combine(target, "mihomo.json");
            var providerPath = Path.Combine(target, "provider.json");
            var main = ReadLimited(mainPath);
            var provider = ReadLimited(providerPath);
            try
            {
                var mainDigest = Digest(main);
                var providerDigest = Digest(provider);
                if (!StringEquals(metadata, "main_sha256", mainDigest) ||
                    !StringEquals(metadata, "provider_sha256", providerDigest))
                    throw new ServiceFailure("BF-CONFIG-PACKAGE");
                try { MihomoConfigValidator.ValidateStaged(main, provider, source, mode, verifiedPolicy); }
                catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }
                return new ClientPackageResolved(id, mode, "mihomo", source, country, verifiedPolicy.PolicyMode,
                    mainPath, providerPath, mainDigest, providerDigest, verifiedPolicy.Digest,
                    verifiedPolicy.Generation, verifiedPolicy);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(main);
                CryptographicOperations.ZeroMemory(provider);
            }
        }
        finally { CryptographicOperations.ZeroMemory(metadataBytes); }
    }

    internal static JsonDocument ParseMetadata(byte[] bytes) => ClientPackageValidator.ParseMetadata(bytes);

    internal static void EnsureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        RejectReparse(path, true);
        if (!OperatingSystem.IsWindows() ||
            !string.Equals(Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(ServicePaths.ConfigRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase)) return;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    internal static void RemoveStaged(string root, string id)
    {
        if (!IsId(id)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        EnsureDirectory(root);
        var target = Path.GetFullPath(Path.Combine(root, id));
        if (!IsContained(root, target)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        if (Directory.Exists(target)) DeleteOwnedDirectory(target, requireCompletePackage: false);
    }

    internal static void PruneStaged(string root, IEnumerable<string?> keepIds, int maxPackages = 16)
    {
        if (maxPackages is < 2 or > 64) throw new ServiceFailure("BF-SECURITY-CLEANUP");
        EnsureDirectory(root);
        var keep = keepIds.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!).ToHashSet(StringComparer.Ordinal);
        if (keep.Any(id => !IsId(id))) throw new ServiceFailure("BF-SECURITY-CLEANUP");
        var packages = new List<(string Id, string Path, DateTime Stamp)>();
        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            var name = Path.GetFileName(directory);
            if (name.StartsWith(".stage_", StringComparison.Ordinal))
            {
                if (name.Length == 39 && name[7..].All(IsHex)) DeleteOwnedDirectory(directory, requireCompletePackage: false);
                continue;
            }
            if (!IsId(name)) continue;
            RejectReparse(directory, true);
            packages.Add((name, directory, Directory.GetLastWriteTimeUtc(directory)));
        }
        foreach (var package in packages.Where(item => !keep.Contains(item.Id)).OrderBy(item => item.Stamp).ThenBy(item => item.Id, StringComparer.Ordinal).ToArray())
        {
            if (packages.Count <= maxPackages) break;
            DeleteOwnedDirectory(package.Path, requireCompletePackage: true);
            packages.Remove(package);
        }
        if (packages.Count > maxPackages) throw new ServiceFailure("BF-SECURITY-CLEANUP");
    }

    private static void DeleteOwnedDirectory(string path, bool requireCompletePackage)
    {
        RejectReparse(path, true);
        var entries = Directory.EnumerateFileSystemEntries(path).ToArray();
        var names = entries.Select(Path.GetFileName).ToArray();
        if (names.Any(name => !ExactPackageFiles.Contains(name, StringComparer.Ordinal)) ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length ||
            requireCompletePackage && !names.OrderBy(name => name, StringComparer.Ordinal).SequenceEqual(ExactPackageFiles, StringComparer.Ordinal))
            throw new ServiceFailure("BF-SECURITY-CLEANUP");
        foreach (var entry in entries)
        {
            if (Directory.Exists(entry)) throw new ServiceFailure("BF-SECURITY-CLEANUP");
            RejectReparse(entry, false);
        }
        foreach (var entry in entries) File.Delete(entry);
        Directory.Delete(path, false);
    }

    private static void WriteFile(string path, byte[] bytes, bool durable)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
            durable ? FileOptions.WriteThrough : FileOptions.SequentialScan);
        stream.Write(bytes);
        if (durable) stream.Flush(true); else stream.Flush();
    }

    private static byte[] ReadLimited(string path)
    {
        try { return BifrostIpcWire.ReadBoundedFile(path, ClientPackageValidator.MaxConfigBytes); }
        catch (Exception failure) when (failure is InvalidDataException or IOException)
        { throw new ServiceFailure("BF-CONFIG-PACKAGE"); }
    }

    private static void RejectReparse(string path, bool directory)
    {
        if (!Directory.Exists(path) && !File.Exists(path)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || directory != ((attributes & FileAttributes.Directory) != 0))
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
    }

    private static bool IsContained(string root, string path)
    {
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(path).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsToken(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 96 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');
    private static bool IsId(string id) => id.StartsWith("cfg_", StringComparison.Ordinal) && id.Length == 36 && id.Skip(4).All(IsHex);
    private static bool IsHex(char character) => character is >= '0' and <= '9' or >= 'a' and <= 'f';
    private static bool StringEquals(JsonElement root, string name, string expected) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() == expected;
    private static string Digest(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static void TryDeleteOwned(string path)
    {
        try { if (Directory.Exists(path)) DeleteOwnedDirectory(path, requireCompletePackage: false); }
        catch { }
    }
}
