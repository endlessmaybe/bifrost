using System.IO;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

[assembly: InternalsVisibleTo("Bifrost.UiStateFixture")]

namespace Bifrost;

/// <summary>
/// DPAPI-backed, single-file storage for non-secret UI choices.  The UI must
/// never fall back to a plaintext file: a malformed or undecipherable record
/// is rejected and the caller uses safe defaults.
/// </summary>
internal sealed class UiStateStore
{
    internal const int MaxProtectedBytes = 64 * 1024;
    internal const int MaxPlaintextBytes = 32 * 1024;
    private const string Corrupt = "BF-UI-STATE-CORRUPT";
    private const string WriteError = "BF-UI-STATE-WRITE";
    private const string ClearError = "BF-UI-STATE-CLEAR";
    private const string MigrationError = "BF-UI-STATE-MIGRATION";
    private const string LegacyJsonName = "ui-state.json";
    private const string LegacyThemeName = "theme.txt";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("BIFROST-UI-V1\0");
    private static readonly HashSet<string> AllowedKeys = new(StringComparer.Ordinal)
    {
        "mode", "connection_type", "route_mode", "core", "source", "country", "front_source",
        "candidate_mode", "candidate_label", "app_policy", "app_policy_enabled",
        "include_apps", "exclude_apps", "theme", "design_direction",
    };
    // Protected records written by Bifrost 2.0 before the visual-direction
    // selector existed remain valid.  This is a one-field additive migration,
    // not a permissive schema fallback: the legacy shape must still match the
    // old exact key set and receives only the safe recommended default.
    private static readonly HashSet<string> LegacyAllowedKeys = new(AllowedKeys.Where(key => key != "design_direction"), StringComparer.Ordinal);
    private readonly string _root;
    private readonly string _path;
    private readonly Func<byte[], byte[]> _protect;
    private readonly Func<byte[], byte[]> _unprotect;
    private readonly Func<string, bool> _deleteFile;

    internal UiStateStore(
        string? rootOverride = null,
        Func<byte[], byte[]>? protect = null,
        Func<byte[], byte[]>? unprotect = null,
        Func<string, bool>? deleteFile = null)
    {
        _root = rootOverride ?? ResolveDefaultRoot();
        _path = Path.Combine(_root, "ui-state.bin");
        _protect = protect ?? (bytes => ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser));
        _unprotect = unprotect ?? (bytes => ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser));
        _deleteFile = deleteFile ?? DeleteFileChecked;
    }

    private static string ResolveDefaultRoot()
    {
        if (BifrostBuildConstants.LocalEvaluationFixture)
        {
            var overrideRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_STATE_ROOT");
            if (!string.IsNullOrWhiteSpace(overrideRoot))
            {
                var full = Path.GetFullPath(overrideRoot);
                var temp = Path.GetFullPath(Path.GetTempPath());
                if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-TEST-SCOPE");
                return Path.Combine(full, "ui");
            }
            throw new InvalidDataException("BF-TEST-SCOPE");
        }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost");
    }

    internal JsonObject Load()
    {
        try
        {
            if (!TryGetAttributes(_root, directory: true, out _)) return new JsonObject();
            var encrypted = TryGetAttributes(_path, directory: false, out _)
                ? ReadEncrypted()
                : null;
            var legacy = ReadLegacyState();
            if (legacy is null) return encrypted ?? new JsonObject();

            // If no protected record exists, migrate the validated legacy
            // choices first, read them back through the production decoder,
            // and only then scrub both plaintext files.  If a protected record
            // already exists it remains authoritative; legacy is still parsed
            // and scrubbed so stale plaintext is never silently ignored.
            if (encrypted is null)
            {
                Save(legacy);
                encrypted = ReadEncrypted();
            }
            DeleteLegacyFiles();
            return encrypted;
        }
        catch (InvalidOperationException error) when (error.Message is Corrupt or MigrationError)
        {
            throw;
        }
        catch
        {
            throw new InvalidOperationException(Corrupt);
        }
    }

    internal void Save(JsonObject state)
    {
        Validate(state);
        byte[]? jsonBytes = null;
        byte[]? plain = null;
        byte[]? protectedBytes = null;
        string? temp = null;
        try
        {
            Directory.CreateDirectory(_root);
            RejectReparse(_root, directory: true);
            if (File.Exists(_path)) RejectReparse(_path, directory: false);

            jsonBytes = StrictUtf8.GetBytes(state.ToJsonString());
            if (jsonBytes.Length + Magic.Length > MaxPlaintextBytes) throw new InvalidOperationException(WriteError);
            plain = new byte[Magic.Length + jsonBytes.Length];
            Magic.CopyTo(plain, 0);
            jsonBytes.CopyTo(plain, Magic.Length);
            protectedBytes = _protect(plain);
            if (protectedBytes.Length == 0 || protectedBytes.Length > MaxProtectedBytes) throw new InvalidOperationException(WriteError);

            temp = Path.Combine(_root, $".ui-state.tmp-{Guid.NewGuid():N}");
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan))
            {
                stream.Write(protectedBytes, 0, protectedBytes.Length);
                stream.Flush(true);
            }
            RejectReparse(temp, directory: false);
            if (File.Exists(_path)) File.Replace(temp, _path, null, true);
            else File.Move(temp, _path);
            temp = null;
        }
        catch (InvalidOperationException error) when (error.Message == WriteError)
        {
            throw;
        }
        catch
        {
            throw new InvalidOperationException(WriteError);
        }
        finally
        {
            if (temp is not null) TryDeleteTemp(temp);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (jsonBytes is not null) CryptographicOperations.ZeroMemory(jsonBytes);
        }
    }

    internal void Clear()
    {
        try
        {
            if (!TryGetAttributes(_root, directory: true, out _)) return;
            DeleteIfPresent(_path, ClearError);
            DeleteIfPresent(Path.Combine(_root, LegacyJsonName), ClearError);
            DeleteIfPresent(Path.Combine(_root, LegacyThemeName), ClearError);
            foreach (var temp in Directory.EnumerateFiles(_root, ".ui-state.tmp-*", SearchOption.TopDirectoryOnly))
            {
                RejectReparse(temp, directory: false);
                if (!_deleteFile(temp) || TryGetAttributes(temp, directory: false, out _))
                    throw new InvalidOperationException(ClearError);
            }
        }
        catch (InvalidOperationException error) when (error.Message == ClearError)
        {
            throw;
        }
        catch
        {
            throw new InvalidOperationException(ClearError);
        }
    }

    private JsonObject ReadEncrypted()
    {
        var protectedBytes = ReadBounded(_path, MaxProtectedBytes, Corrupt);
        byte[]? plain = null;
        byte[]? jsonBytes = null;
        try
        {
            plain = _unprotect(protectedBytes);
            if (plain.Length <= Magic.Length || plain.Length > MaxPlaintextBytes || !plain.AsSpan(0, Magic.Length).SequenceEqual(Magic))
                throw new InvalidOperationException(Corrupt);
            jsonBytes = plain.AsSpan(Magic.Length).ToArray();
            return ParseStrict(StrictUtf8.GetString(jsonBytes), requireAllKeys: true, errorCode: Corrupt);
        }
        finally
        {
            if (jsonBytes is not null) CryptographicOperations.ZeroMemory(jsonBytes);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private JsonObject? ReadLegacyState()
    {
        var jsonPath = Path.Combine(_root, LegacyJsonName);
        var themePath = Path.Combine(_root, LegacyThemeName);
        var found = false;
        var result = DefaultState();
        if (TryGetAttributes(jsonPath, directory: false, out _))
        {
            var bytes = ReadBounded(jsonPath, MaxPlaintextBytes, MigrationError);
            try
            {
                var parsed = ParseStrict(StrictUtf8.GetString(bytes), requireAllKeys: false, errorCode: MigrationError);
                foreach (var property in parsed)
                {
                    if (property.Key == "app_policy_enabled") result[property.Key] = property.Value?.GetValue<bool>() ?? throw new InvalidOperationException(MigrationError);
                    else result[property.Key] = property.Value?.GetValue<string>() ?? throw new InvalidOperationException(MigrationError);
                }
                found = true;
            }
            catch (InvalidOperationException error) when (error.Message == MigrationError)
            {
                throw;
            }
            catch
            {
                throw new InvalidOperationException(MigrationError);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        if (TryGetAttributes(themePath, directory: false, out _))
        {
            var bytes = ReadBounded(themePath, 256, MigrationError);
            try
            {
                var theme = StrictUtf8.GetString(bytes);
                if (theme is not ("system" or "dark" or "light")) throw new InvalidOperationException(MigrationError);
                result["theme"] = theme;
                found = true;
            }
            catch (InvalidOperationException error) when (error.Message == MigrationError)
            {
                throw;
            }
            catch
            {
                throw new InvalidOperationException(MigrationError);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return found ? result : null;
    }

    private void DeleteLegacyFiles()
    {
        DeleteIfPresent(Path.Combine(_root, LegacyJsonName), MigrationError);
        DeleteIfPresent(Path.Combine(_root, LegacyThemeName), MigrationError);
    }

    private void DeleteIfPresent(string path, string errorCode)
    {
        if (!TryGetAttributes(path, directory: false, out _)) return;
        RejectReparse(path, directory: false);
        if (!_deleteFile(path) || TryGetAttributes(path, directory: false, out _))
            throw new InvalidOperationException(errorCode);
    }

    private static JsonObject DefaultState() => new()
    {
        ["mode"] = "smart", ["connection_type"] = "direct-vmess", ["route_mode"] = "smart",
        ["core"] = "auto", ["source"] = "", ["country"] = "default", ["front_source"] = "auto",
        ["candidate_mode"] = "auto", ["candidate_label"] = "", ["app_policy"] = "allow",
        ["app_policy_enabled"] = false, ["include_apps"] = "", ["exclude_apps"] = "", ["theme"] = "system",
        ["design_direction"] = "a",
    };

    private static JsonObject ParseStrict(string json, bool requireAllKeys, string errorCode)
    {
        if (json.Length == 0) throw new InvalidOperationException(errorCode);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidOperationException(errorCode);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new JsonObject();
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!AllowedKeys.Contains(property.Name) || !seen.Add(property.Name)) throw new InvalidOperationException(errorCode);
            if (property.Name == "app_policy_enabled")
            {
                if (property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new InvalidOperationException(errorCode);
                result[property.Name] = property.Value.GetBoolean();
                continue;
            }
            if (property.Value.ValueKind != JsonValueKind.String) throw new InvalidOperationException(errorCode);
            var value = property.Value.GetString() ?? throw new InvalidOperationException(errorCode);
            ValidateValue(property.Name, value, errorCode);
            result[property.Name] = value;
        }
        if (requireAllKeys)
        {
            if (seen.SetEquals(LegacyAllowedKeys)) result["design_direction"] = "a";
            else if (!seen.SetEquals(AllowedKeys)) throw new InvalidOperationException(errorCode);
        }
        else if (seen.Count == 0) throw new InvalidOperationException(errorCode);
        return result;
    }

    private static void Validate(JsonObject state)
    {
        if (state is null) throw new InvalidOperationException(WriteError);
        if (!state.Select(pair => pair.Key).ToHashSet(StringComparer.Ordinal).SetEquals(AllowedKeys) || state.Count != AllowedKeys.Count)
            throw new InvalidOperationException(WriteError);
        foreach (var key in AllowedKeys)
        {
            if (key == "app_policy_enabled")
            {
                if (state[key] is not JsonValue boolValue || !boolValue.TryGetValue<bool>(out _)) throw new InvalidOperationException(WriteError);
            }
            else
            {
                if (state[key] is not JsonValue value || !value.TryGetValue<string>(out var text) || text is null)
                    throw new InvalidOperationException(WriteError);
                ValidateValue(key, text, WriteError);
            }
        }
    }

    private static void ValidateValue(string key, string value, string code)
    {
        var max = key is "include_apps" or "exclude_apps" ? 8192 : 256;
        if (value.Length > max || value.Any(character => char.IsControl(character) && character is not '\r' and not '\n'))
            throw new InvalidOperationException(code);
    }

    private static void RejectReparse(string path, bool directory)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || (directory && (attributes & FileAttributes.Directory) == 0) || (!directory && (attributes & FileAttributes.Directory) != 0))
            throw new InvalidOperationException(Corrupt);
    }

    private static bool TryGetAttributes(string path, bool directory, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (directory && (attributes & FileAttributes.Directory) == 0) ||
                (!directory && (attributes & FileAttributes.Directory) != 0))
                throw new InvalidOperationException(Corrupt);
            return true;
        }
        catch (FileNotFoundException) { attributes = 0; return false; }
        catch (DirectoryNotFoundException) { attributes = 0; return false; }
    }

    private static byte[] ReadBounded(string path, int maximum, string errorCode)
    {
        try
        {
            RejectReparse(path, directory: false);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            var length = stream.Length;
            if (length <= 0 || length > maximum) throw new InvalidOperationException(errorCode);
            var bytes = new byte[(int)length];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = stream.Read(bytes, offset, bytes.Length - offset);
                if (read <= 0) { CryptographicOperations.ZeroMemory(bytes); throw new InvalidOperationException(errorCode); }
                offset += read;
            }
            if (stream.ReadByte() != -1) { CryptographicOperations.ZeroMemory(bytes); throw new InvalidOperationException(errorCode); }
            return bytes;
        }
        catch (InvalidOperationException error) when (error.Message == errorCode) { throw; }
        catch { throw new InvalidOperationException(errorCode); }
    }

    private static bool DeleteFileChecked(string path)
    {
        try
        {
            File.Delete(path);
            return !File.Exists(path);
        }
        catch { return false; }
    }

    private static void TryDeleteTemp(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
