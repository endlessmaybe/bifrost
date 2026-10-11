using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Bifrost;

internal sealed class UpdateRestartIntentStore
{
    private readonly string _root;
    private readonly string _path;
    internal UpdateRestartIntentStore(string? root = null)
    {
        _root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost");
        _path = Path.Combine(_root, "update-restart-intent.bin");
    }

    internal void Save(long sequence, bool reconnect)
    {
        if (sequence <= 0) throw new InvalidDataException("BF-UPDATE-RESTART");
        Directory.CreateDirectory(_root);
        RejectReparse(_root);
        if (File.Exists(_path)) RejectReparse(_path);
        var plain = JsonSerializer.SerializeToUtf8Bytes(new Intent(sequence, reconnect, DateTimeOffset.UtcNow));
        var temp = Path.Combine(_root, ".update-restart-" + Guid.NewGuid().ToString("N"));
        try
        {
            var encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(temp, encrypted);
            File.Move(temp, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    internal bool TryConsume(long runningSequence)
    {
        try
        {
            if (!File.Exists(_path)) return false;
            RejectReparse(_root);
            RejectReparse(_path);
            if (new FileInfo(_path).Length is <= 0 or > 4096) return false;
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(_path), null, DataProtectionScope.CurrentUser);
            try
            {
                var intent = JsonSerializer.Deserialize<Intent>(plain);
                if (intent is null) return false;
                // An old still-running UI may not consume the new generation's
                // one-shot record. A stale record expires without connecting.
                if (intent.Sequence != runningSequence) return false;
                File.Delete(_path);
                var age = DateTimeOffset.UtcNow - intent.CreatedAt;
                return intent.Reconnect && age >= TimeSpan.Zero && age < TimeSpan.FromHours(1);
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch { return false; }
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("BF-UPDATE-RESTART");
    }
    private sealed record Intent(long Sequence, bool Reconnect, DateTimeOffset CreatedAt);
}
