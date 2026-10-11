using System;
using System.Linq;

namespace Bifrost;

/// <summary>Minimal platform seam for clipboard ownership tests.</summary>
public readonly record struct SensitiveClipboardReadResult(bool Succeeded, string? Value);

public interface ISensitiveClipboard
{
    SensitiveClipboardReadResult TryReadText();
    bool WriteText(string value);
    bool ClearIfMatches(string expected);
}

/// <summary>
/// Keeps recovery and pairing values in separate, non-persistent lifecycles.
/// Clipboard cleanup is equality-bound and never clears a user's replacement.
/// </summary>
public sealed class SensitiveCodeController
{
    private readonly SensitiveValueLifecycle _lifecycle;
    private readonly ISensitiveClipboard _clipboard;
    private string? _ownedClipboard;
    internal long ClipboardRevision { get; private set; }

    public SensitiveCodeController(ISensitiveClipboard clipboard, TimeSpan? ttl = null)
    {
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _lifecycle = new SensitiveValueLifecycle(ttl);
    }

    public bool Publish(string value, DateTimeOffset now)
    {
        if (!ClearClipboard())
        {
            _lifecycle.Clear();
            return false;
        }
        return _lifecycle.Publish(value, now);
    }

    public string? Reveal(DateTimeOffset now) => _lifecycle.Reveal(now);

    public bool Copy(DateTimeOffset now)
    {
        if (!ClearClipboard()) return false;
        var value = _lifecycle.Reveal(now);
        if (value is null) return false;
        try
        {
            if (!_clipboard.WriteText(value)) return false;
            _ownedClipboard = value;
            ClipboardRevision++;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool Acknowledge(DateTimeOffset now)
    {
        // Do not discard the one-display value until clipboard cleanup has
        // succeeded.  A read/clear failure must remain retryable and visible
        // to the dialog instead of leaving an owned secret with no lifecycle.
        if (_lifecycle.Reveal(now) is null) return false;
        if (!ClearClipboard()) return false;
        _lifecycle.Clear();
        return true;
    }

    public bool ClearClipboard()
    {
        var expected = _ownedClipboard;
        if (expected is null) return true;
        try
        {
            var read = _clipboard.TryReadText();
            if (!read.Succeeded) return false;
            if (!string.Equals(read.Value, expected, StringComparison.Ordinal))
            {
                _ownedClipboard = null;
                // The user replaced our value. Treat that as a safe no-op and
                // release ownership so the next explicit copy can proceed.
                return true;
            }

            if (!_clipboard.ClearIfMatches(expected)) return false;
            _ownedClipboard = null;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void OnBackground()
    {
        _ = ClearClipboard();
        _lifecycle.OnBackground();
    }

    // An explicit clipboard copy has its own deadline, independent of visibility.
    public void HideValue() => _lifecycle.OnBackground();

    public void Clear()
    {
        OnBackground();
    }
}

/// <summary>Short, explicit reveal window independent from the one-display TTL.</summary>
public sealed class SensitiveRevealState
{
    private readonly TimeSpan _ttl;
    private string? _value;
    private DateTimeOffset _remaskAt = DateTimeOffset.MinValue;

    public SensitiveRevealState(TimeSpan? ttl = null)
    {
        _ttl = ttl ?? TimeSpan.FromSeconds(30);
        if (_ttl <= TimeSpan.Zero || _ttl > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(ttl));
    }

    public bool Reveal(string value, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 256 || value.Any(char.IsControl))
        {
            Clear();
            return false;
        }
        _value = value;
        _remaskAt = now + _ttl;
        return true;
    }

    public string? Read(DateTimeOffset now)
    {
        if (_value is null) return null;
        if (now >= _remaskAt)
        {
            Clear();
            return null;
        }
        return _value;
    }

    public void Mask() => Clear();

    public void Clear()
    {
        _value = null;
        _remaskAt = DateTimeOffset.MinValue;
    }
}

/// <summary>Owns the separate 30-second clipboard cleanup deadline.</summary>
public sealed class SensitiveClipboardLease
{
    private readonly SensitiveCodeController _controller;
    private readonly TimeSpan _ttl;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;
    private long _revision;

    public SensitiveClipboardLease(SensitiveCodeController controller, TimeSpan? ttl = null)
    {
        _controller = controller ?? throw new ArgumentNullException(nameof(controller));
        _ttl = ttl ?? TimeSpan.FromSeconds(30);
        if (_ttl <= TimeSpan.Zero || _ttl > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(ttl));
    }

    public bool IsArmed => _expiresAt != DateTimeOffset.MinValue;

    public void Arm(DateTimeOffset now) { _revision = _controller.ClipboardRevision; _expiresAt = now + _ttl; }

    public bool Expire(DateTimeOffset now)
    {
        if (!IsArmed) return true;
        if (_revision != _controller.ClipboardRevision) { _expiresAt = DateTimeOffset.MinValue; return true; }
        if (now < _expiresAt) return true;
        if (_controller.ClearClipboard())
        {
            _expiresAt = DateTimeOffset.MinValue;
            return true;
        }
        // Keep a bounded retry deadline; an I/O failure must remain visible to
        // the caller and must not silently abandon ownership.
        _expiresAt = now + _ttl;
        return false;
    }

    public bool Clear()
    {
        if (!_controller.ClearClipboard()) return false;
        _expiresAt = DateTimeOffset.MinValue;
        return true;
    }
}
