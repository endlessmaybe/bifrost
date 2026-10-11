using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;

namespace Bifrost;

/// <summary>Owns an eagerly rendered copy without invoking another app's OLE data provider.</summary>
internal sealed class WpfSensitiveClipboard : ISensitiveClipboard
{
    private uint _sequence;
    private string? _value;
    public SensitiveClipboardReadResult TryReadText()
    {
        // Ownership needs no read from an arbitrary clipboard provider.
        if (_value is not null && _sequence != 0 && GetClipboardSequenceNumber() == _sequence)
            return new SensitiveClipboardReadResult(true, _value);
        _value = null;
        return new SensitiveClipboardReadResult(true, null);
    }

    public bool WriteText(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 256) return false;
        var owner = Application.Current?.MainWindow;
        if (owner is null) return false;
        var handle = new WindowInteropHelper(owner).EnsureHandle();
        var bytes = Encoding.Unicode.GetBytes(value + '\0');
        var memory = GlobalAlloc(0x0002, (UIntPtr)bytes.Length);
        if (memory == IntPtr.Zero) return false;
        try
        {
            var pointer = GlobalLock(memory);
            if (pointer == IntPtr.Zero) return false;
            try { Marshal.Copy(bytes, 0, pointer, bytes.Length); }
            finally { GlobalUnlock(memory); }
            // A busy clipboard fails immediately and remains retryable.
            if (!OpenClipboard(handle)) return false;
            try
            {
                if (!EmptyClipboard() || SetClipboardData(13, memory) == IntPtr.Zero) return false;
                memory = IntPtr.Zero; // Windows owns the allocation after SetClipboardData.
                _sequence = GetClipboardSequenceNumber();
                _value = value;
                return true;
            }
            finally { CloseClipboard(); }
        }
        finally { Array.Clear(bytes); if (memory != IntPtr.Zero) GlobalFree(memory); }
    }

    public bool ClearIfMatches(string expected)
    {
        if (!string.Equals(_value, expected, StringComparison.Ordinal)) return true;
        if (!OpenClipboard(IntPtr.Zero)) return false;
        try
        {
            if (_sequence == 0 || GetClipboardSequenceNumber() != _sequence)
            { _value = null; return true; }
            if (!EmptyClipboard()) return false;
            _value = null; _sequence = 0;
            return true;
        }
        finally { CloseClipboard(); }
    }

    [DllImport("user32.dll")] private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern bool EmptyClipboard();
    [DllImport("user32.dll")] private static extern IntPtr SetClipboardData(uint format, IntPtr memory);
    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalLock(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
}
