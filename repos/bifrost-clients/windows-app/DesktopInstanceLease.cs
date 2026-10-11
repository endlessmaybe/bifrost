using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Bifrost;

/// <summary>One desktop controller per committed installation and logon session.</summary>
internal sealed class DesktopInstanceLease : IDisposable
{
    private readonly Mutex _mutex;
    private readonly bool _owned;
    private DesktopInstanceLease(Mutex mutex, bool owned) { _mutex = mutex; _owned = owned; }
    internal static DesktopInstanceLease Acquire(string installRoot)
    {
        var canonical = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        var mutex = new Mutex(false, @"Local\Bifrost.Desktop." + digest);
        bool owned;
        try { owned = mutex.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        return new DesktopInstanceLease(mutex, owned);
    }
    internal bool IsOwner => _owned;
    internal static void RaiseExisting(string imagePath)
    {
        using var current = Process.GetCurrentProcess();
        foreach (var process in Process.GetProcessesByName("Bifrost")) using (process)
        {
            if (process.Id == current.Id) continue;
            try
            {
                if (process.SessionId != current.SessionId || !string.Equals(process.MainModule?.FileName, imagePath, StringComparison.OrdinalIgnoreCase)) continue;
                var window = process.MainWindowHandle;
                if (window == IntPtr.Zero) continue;
                _ = ShowWindowAsync(window, 9);
                _ = SetForegroundWindow(window);
                return;
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }
    }
    public void Dispose() { if (_owned) _mutex.ReleaseMutex(); _mutex.Dispose(); }
    [DllImport("user32.dll")] private static extern bool ShowWindowAsync(IntPtr hWnd, int command);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
}
