using Bifrost.ClientService;

static partial class Fixture
{
    private static void TunDnsLifecycle()
    {
        OwnedTunDnsState? state = new("owned-adapter-guid", Array.Empty<string>());
        var writes = new List<bool>();
        bool Write(int index, bool enable)
        {
            Assert(index == 77, "only the owned TUN index is touched");
            writes.Add(enable);
            state = state! with { Servers = enable ? new[] { MihomoWindowsContract.TunDnsAddress } : Array.Empty<string>() };
            return true;
        }
        using (var dns = new OwnedTunDns(77, _ => state, Write))
        {
            dns.Install();
            Assert(dns.IsBound, "connected requires the real resolver readback");
            Assert(dns.Restore() && !dns.IsBound, "disconnect restores an empty TUN resolver");
            Assert(dns.Restore(), "repeated disconnect is harmless");
        }
        Assert(writes.SequenceEqual(new[] { true, false }), "one DNS commit and one release");

        state = new("owned-adapter-guid", new[] { "192.0.2.53" });
        using (var dns = new OwnedTunDns(77, _ => state, Write))
            ExpectCode(dns.Install, "BF-TUN-DNS-OWNER");
        Assert(writes.Count == 2, "foreign resolver settings are preserved");

        state = new("owned-adapter-guid", new[] { MihomoWindowsContract.TunDnsAddress });
        Assert(OwnedTunDns.Recover(77, _ => state, Write) && state.Servers.Count == 0,
            "service restart recovers an interrupted DNS commit");

        state = new("owned-adapter-guid", Array.Empty<string>());
        using (var dns = new OwnedTunDns(77, _ => state, Write))
        {
            dns.Install();
            var count = writes.Count;
            state = new("another-adapter-guid", new[] { "192.0.2.54" });
            Assert(!dns.IsBound && dns.Restore() && writes.Count == count,
                "recycled interface indices cannot change another adapter");
        }

        state = new("owned-adapter-guid", Array.Empty<string>());
        using (var dns = new OwnedTunDns(77, _ => state, (_, _) => true))
        {
            ExpectCode(dns.Install, "BF-TUN-DNS-READBACK");
            Assert(!dns.IsBound, "command exit zero without DNS readback is a failed connect");
        }
        Console.WriteLine("MIHOMO-TUN-DNS lifecycle, recovery and foreign-owner preservation PASS");
    }
}
