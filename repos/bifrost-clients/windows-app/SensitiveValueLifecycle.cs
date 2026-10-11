using System;

namespace Bifrost;

/// <summary>Non-persistent owner for a one-display recovery or pairing value.</summary>
public sealed class SensitiveValueLifecycle
{
    private readonly TimeSpan _ttl;
    private string? _value;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public SensitiveValueLifecycle(TimeSpan? ttl = null)
    {
        _ttl = ttl ?? TimeSpan.FromMinutes(10);
        if (_ttl <= TimeSpan.Zero || _ttl > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(ttl));
    }

    public bool Publish(string value, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 256 || HasControl(value))
        {
            Clear();
            return false;
        }
        _value = value;
        _expiresAt = now + _ttl;
        return true;
    }

    public string? Reveal(DateTimeOffset now)
    {
        if (_value is null) return null;
        if (now >= _expiresAt)
        {
            Clear();
            return null;
        }
        return _value;
    }

    public bool Acknowledge(DateTimeOffset now)
    {
        if (Reveal(now) is null) return false;
        Clear();
        return true;
    }

    public void OnBackground() => Clear();

    public void Clear()
    {
        _value = null;
        _expiresAt = DateTimeOffset.MinValue;
    }

    private static bool HasControl(string value)
    {
        foreach (var character in value)
            if (char.IsControl(character)) return true;
        return false;
    }
}
