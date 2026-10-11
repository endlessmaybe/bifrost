using System.Net;
using Bifrost.ClientService;

static partial class Fixture
{
    private static int Main()
    {
        SuccessfulCommit();
        CanaryFailureNeverCommits();
        PartialCommitRollsBack();
        DirectFallbackNeverTouchesRoutes();
        TunDnsLifecycle();
        WindowsInterfaceSnapshot[] interfaces;
        using (WindowsInterfaceReadback.Begin())
        {
            interfaces = WindowsInterfaceReadback.Read();
            Assert(ReferenceEquals(interfaces, WindowsInterfaceReadback.Read()), "one health observation shares enumeration");
            using (WindowsInterfaceReadback.Begin())
                Assert(!ReferenceEquals(interfaces, WindowsInterfaceReadback.Read()), "nested observation refreshes independently");
            Assert(ReferenceEquals(interfaces, WindowsInterfaceReadback.Read()), "nested scope restores the outer snapshot");
        }
        Assert(!ReferenceEquals(interfaces, WindowsInterfaceReadback.Read()), "teardown and later observations must not reuse stale interfaces");
        InterfaceReadbackAcceptance();
        Console.WriteLine("MIHOMO-HANDOVER-FIXTURE PASS");
        return 0;
    }

    private static void SuccessfulCommit()
    {
        var operations = new List<string>();
        bool Runner(string operation, string prefix, int index) { operations.Add($"{operation}|{prefix}|{index}"); return true; }
        using var handover = new WindowsRouteHandover(77, false, Runner, _ => true);
        var snapshot = handover.PrepareAndCommit(Identity(), Group("A-02", true), Allowed(), IPAddress.Parse("203.0.113.44"),
            (_, _) => true, CancellationToken.None);
        Assert(snapshot.Ipv4Committed && !snapshot.Ipv6Committed && snapshot.TunInterfaceIndex == 77, "commit snapshot");
        Assert(operations.SequenceEqual(new[]
        {
            "add|203.0.113.44/32|77", "add|0.0.0.0/1|77", "add|128.0.0.0/1|77", "delete|203.0.113.44/32|77"
        }), "literal successful route order");
        handover.RollbackAndVerify();
        Assert(operations.TakeLast(2).SequenceEqual(new[] { "delete|128.0.0.0/1|77", "delete|0.0.0.0/1|77" }), "disconnect reverses routes");
    }

    private static void CanaryFailureNeverCommits()
    {
        var operations = new List<string>();
        bool Runner(string operation, string prefix, int index) { operations.Add($"{operation}|{prefix}|{index}"); return true; }
        using var handover = new WindowsRouteHandover(78, false, Runner, _ => true);
        ExpectCode(() => handover.PrepareAndCommit(Identity(), Group("A-01", true), Allowed(), IPAddress.Parse("203.0.113.45"),
            (_, _) => false, CancellationToken.None), "BF-HANDOVER-CANARY");
        Assert(operations.SequenceEqual(new[] { "add|203.0.113.45/32|78", "delete|203.0.113.45/32|78" }), "canary rollback only");
    }

    private static void PartialCommitRollsBack()
    {
        var operations = new List<string>();
        bool Runner(string operation, string prefix, int index)
        {
            operations.Add($"{operation}|{prefix}|{index}");
            return !(operation == "add" && prefix == "128.0.0.0/1");
        }
        using var handover = new WindowsRouteHandover(79, false, Runner, _ => true);
        ExpectCode(() => handover.PrepareAndCommit(Identity(), Group("A-01", true), Allowed(), IPAddress.Parse("203.0.113.46"),
            (_, _) => true, CancellationToken.None), "BF-HANDOVER-ROUTE-COMMIT");
        Assert(operations.Contains("delete|0.0.0.0/1|79") && operations.Contains("delete|203.0.113.46/32|79"), "partial commit rollback");
    }

    private static void DirectFallbackNeverTouchesRoutes()
    {
        var operations = new List<string>();
        bool Runner(string operation, string prefix, int index) { operations.Add(prefix); return true; }
        using var handover = new WindowsRouteHandover(80, false, Runner, _ => true);
        ExpectCode(() => handover.PrepareAndCommit(Identity(), Group("DIRECT", true), Allowed(), IPAddress.Parse("203.0.113.47"),
            (_, _) => true, CancellationToken.None), "BF-MIHOMO-DIRECT-FALLBACK");
        Assert(operations.Count == 0, "direct fallback is route neutral");
    }

    private static MihomoRuntimeIdentity Identity() => new(1234, @"C:\TEST-ONLY\mihomo.exe", new string('a', 64));
    private static HashSet<string> Allowed() => new(StringComparer.OrdinalIgnoreCase) { "A-01", "A-02" };
    private static MihomoGroupState Group(string now, bool alive) => new("BIFROST-SMART-A", now,
        new[] { new MihomoProxyHealth("A-01", alive, alive ? 201 : null), new MihomoProxyHealth("A-02", true, 210) });

    private static void ExpectCode(Action action, string code)
    {
        try { action(); }
        catch (Exception error) when (error.Message == code) { return; }
        throw new InvalidOperationException("expected " + code);
    }
    private static void Assert(bool value, string label) { if (!value) throw new InvalidOperationException("fixture assertion failed: " + label); }
}
