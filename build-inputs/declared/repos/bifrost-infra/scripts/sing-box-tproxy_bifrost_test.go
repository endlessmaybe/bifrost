package redirect

import (
    "net/netip"
    "testing"
)

func TestBifrostScopedDestination(t *testing.T) {
    for _, row := range []struct{ target, source, expected string }{
        {"[fe80::2]:53", "fe80::1%wlan0", "[fe80::2%wlan0]:53"},
        {"[fe80::2%eth0]:53", "fe80::1%wlan0", "[fe80::2%eth0]:53"},
        {"[2001:db8::2]:53", "fe80::1%wlan0", "[2001:db8::2]:53"},
        {"192.0.2.2:53", "192.0.2.1", "192.0.2.2:53"},
    } {
        actual := bifrostScopedDestination(netip.MustParseAddrPort(row.target), netip.MustParseAddr(row.source))
        if actual.String() != row.expected { t.Fatalf("%s: got %s, want %s", row.target, actual, row.expected) }
    }
}
