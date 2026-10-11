using System.Diagnostics;
using System.Reflection;
using Bifrost.ClientService;

internal static class RuntimeTeardownFixture
{
    internal static void Run()
    {
        RetryAfterDelayedTunRemoval();
        RetryAfterDnsFailure();
        RetryAfterRouteFailure(false);
        RetryAfterRouteFailure(true);
        RoutesRemovedByWindowsAreAlreadyClean();
        ReconnectHintRespectsNetworkProviderAndExpiry();
        Console.WriteLine("WINDOWS-TEARDOWN retry after delayed TUN, DNS failure, both route leases and already-absent routes PASS");
    }

    private static void ReconnectHintRespectsNetworkProviderAndExpiry()
    {
        var directory = Path.Combine(Path.GetTempPath(), "bifrost-memory-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "memory.json");
        var memory = new MihomoConnectionMemory(path);
        var key = MihomoConnectionMemory.StableKey("BIFROST-SOURCE-A", "TEST-ONLY-NETWORK-A");
        var allowed = new HashSet<string> { "A-08", "A-107" };
        try
        {
            memory.Remember(key, "A-107", 1000);
            Assert(new MihomoConnectionMemory(path).Recall(key, allowed, 2000) == "A-107", "Restart lost last optimized member");
            Assert(memory.Recall(MihomoConnectionMemory.StableKey("BIFROST-SOURCE-A", "TEST-ONLY-NETWORK-B"), allowed, 2000) is null, "Hint crossed physical networks");
            Assert(memory.Recall(MihomoConnectionMemory.StableKey("BIFROST-SOURCE-B", "TEST-ONLY-NETWORK-A"), allowed, 2000) is null, "Hint crossed source identity");
            Assert(memory.Recall(key, new HashSet<string> { "A-08" }, 2000) is null, "Removed provider member was recalled");
            Assert(memory.Recall(key, allowed, 1000 + MihomoConnectionMemory.LifetimeMs) == "A-107", "Hint expired at the exact retention boundary");
            Assert(memory.Recall(key, allowed, 1001 + MihomoConnectionMemory.LifetimeMs) is null && memory.Recall(key, allowed, 999) is null, "Expired or future hint was recalled");
            File.WriteAllText(path, "invalid");
            Assert(memory.Recall(key, allowed, 2000) is null, "Corrupt hint blocked safe startup");
            File.WriteAllText(path, "[null,{}, {\"Key\":null,\"Candidate\":null,\"At\":1000}]");
            Assert(memory.Recall(key, allowed, 2000) is null, "Malformed entries blocked safe startup");
            memory.Remember(key, "A-08", 2100);
            Assert(memory.Recall(key, allowed, 2200) == "A-08", "Malformed cache could not be repaired");
            memory.Forget(key);
            Assert(memory.Recall(key, allowed, 2300) is null, "Rejected optimized member survived explicit forget");
            var legacy = MihomoConnectionMemory.Key(new byte[] { 1, 2 }, "TEST-ONLY-NETWORK-A");
            memory.Remember(legacy, "A-08", 2400);
            Assert(memory.RecallAny(allowed, 2500) == "A-08", "Legacy opaque key cannot be migrated by allowed candidate");
            Console.WriteLine("WINDOWS-RECONNECT last optimized member survives restart; network, provider, expiry, forget and corruption isolation PASS");
        }
        finally { if (File.Exists(path)) File.Delete(path); if (Directory.Exists(directory)) Directory.Delete(directory); }
    }

    private static Process Child()
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("--teardown-child");
        return Process.Start(start) ?? throw new Exception("Test child did not start");
    }

    private static void Set(CoreRuntime runtime, string field, object? value) =>
        typeof(CoreRuntime).GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(runtime, value);

    private static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }

    private static void RetryAfterDelayedTunRemoval()
    {
        var inactive = false;
        var runtime = new CoreRuntime(ensureOwnedTunInactiveForTest: () => inactive);
        using var child = Child();
        Set(runtime, "_core", child);
        var first = runtime.Disconnect();
        Assert(first.Code == "BF-CONNECTION-TEARDOWN", "Unconfirmed TUN removal must remain blocked");
        inactive = true;
        var second = runtime.Disconnect();
        Assert(second.Ok && !second.Connected && second.Code is null,
            "A disposed process handle stranded teardown after the TUN disappeared");
    }

    private static void RetryAfterDnsFailure()
    {
        var dns = new OwnedTunDnsState("TEST-ONLY-TUN", Array.Empty<string>());
        var fail = false;
        var writes = 0;
        var lease = new OwnedTunDns(77, _ => dns, (_, enable) => {
            if (!enable) { writes++; if (fail) return false; }
            dns = dns with { Servers = enable ? new[] { MihomoWindowsContract.TunDnsAddress } : Array.Empty<string>() };
            return true;
        });
        lease.Install(); fail = true;
        var runtime = new CoreRuntime(ensureOwnedTunInactiveForTest: () => true);
        using var child = Child();
        Set(runtime, "_core", child); Set(runtime, "_mihomoDns", lease);
        Assert(runtime.Disconnect().Code == "BF-CONNECTION-TEARDOWN", "DNS failure was hidden");
        var beforeRetry = writes; fail = false;
        var second = runtime.Disconnect();
        Assert(second.Ok && second.Code is null && dns.Servers.Count == 0 && writes > beforeRetry,
            "DNS ownership was discarded before restoration could be retried");
    }

    private static void RetryAfterRouteFailure(bool handover)
    {
        var routes = new HashSet<string>(); var fail = false;
        bool Runner(string operation, string prefix, int index) {
            Assert(index == 77, "Route cleanup touched another interface");
            if (operation == "add") { routes.Add(prefix); return true; }
            if (fail && prefix == "0.0.0.0/1") return false;
            routes.Remove(prefix); return true;
        }
        var runtime = new CoreRuntime(ensureOwnedTunInactiveForTest: () => true);
        using var child = Child();
        Set(runtime, "_core", child);
        if (handover)
        {
            var lease = new WindowsRouteHandover(77, false, Runner);
            lease.PrepareAndCommit(new(child.Id, "TEST-ONLY", new string('a',64)),
                new("TEST", "A-01", new[] { new MihomoProxyHealth("A-01", true, 500) }),
                new HashSet<string> { "A-01" }, System.Net.IPAddress.Parse("203.0.113.44"), (_, _) => true, CancellationToken.None);
            Set(runtime, "_mihomoHandover", lease);
        }
        else
        {
            var lease = new OwnedTunRouteCommit(77, false, Runner);
            lease.CommitFullTunnel(); Set(runtime, "_coexistRoutes", lease);
        }
        fail = true;
        Assert(runtime.Disconnect().Code == "BF-CONNECTION-TEARDOWN", "Partial route deletion was hidden");
        fail = false;
        var second = runtime.Disconnect();
        Assert(second.Ok && second.Code is null && routes.Count == 0,
            "The stale egress route could not be removed by a later disconnect");
    }

    private static void RoutesRemovedByWindowsAreAlreadyClean()
    {
        foreach (bool? exists in new bool?[] { false, true, null })
        {
            var lease = new OwnedTunRouteCommit(77, false, (operation, _, _) => operation == "add", (_, _) => exists);
            lease.CommitFullTunnel();
            Assert(lease.RemoveAll() == (exists == false), "Cleanup must distinguish an absent route from a failed readback");
        }
        var loopback = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Single(item => item.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback);
        var index = loopback.GetIPProperties().GetIPv4Properties().Index;
        Assert(OwnedTunRouteCommit.ReadRoutePresent("127.0.0.1/32", index) == true, "Native readback did not find the existing loopback route");
        Assert(OwnedTunRouteCommit.ReadRoutePresent("198.51.100.255/32", index) == false, "Native readback did not confirm a missing route");
    }
}
