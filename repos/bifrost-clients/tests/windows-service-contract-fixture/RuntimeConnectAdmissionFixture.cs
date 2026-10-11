using System.Diagnostics;
using System.Reflection;
using Bifrost;
using Bifrost.ClientService;

internal static class RuntimeConnectAdmissionFixture
{
    internal static void Run()
    {
        using var session = new Session();
        var runtime = session.Runtime;
        var recovery = Get<RuntimeConnectionRecovery>(runtime, "_connectionRecovery");
        var reconnects = 0;
        var intent = recovery.Begin(_ => { reconnects++; return session.Online; });
        recovery.CompleteInitial(intent, session.Online);
        Get<RuntimeStatusSnapshot>(runtime, "_statusSnapshot").Publish(session.Online);

        var same = runtime.ConnectWithRecovery(session.Command, default);
        Check(same.Ok && same.Connected, "Identical connection was not idempotent");
        Check(recovery.IsCurrent(intent) && intent.Armed, "Identical request replaced recovery ownership");

        var rejected = runtime.ConnectWithRecovery(session.Command with { ConfigId = "cfg_" + new string('b', 32) }, default);
        Check(rejected.Code == "BF-CONNECTION-RESET-REQUIRED", "Different staged package bypassed explicit teardown");
        Check(runtime.StatusForClient().Connected && runtime.StatusForClient().ConfigId == session.Command.ConfigId,
            "Rejected request overwrote the existing session's status");
        Check(recovery.IsCurrent(intent) && intent.Armed && !session.Child.HasExited,
            "Rejected request canceled the working session or its recovery");
        recovery.Tick(() => ServiceStatus.Blocked("BF-RUNTIME-HEALTH"), default);
        Check(reconnects == 1, "Existing session stopped recovering after a rejected request");

        // Hold the same mutation lock used by startup/recovery. A second
        // request must wait without canceling the owner, and an explicit
        // disconnect must invalidate that queued request before it can begin.
        var sync = Get<object>(runtime, "_sync");
        using var startup = new CancellationTokenSource();
        Set(runtime, "_connectCancellation", startup);
        ServiceStatus? queuedResult = null;
        Exception? queuedError = null;
        var queued = new Thread(() =>
        {
            try { queuedResult = runtime.ConnectWithRecovery(session.Command, default); }
            catch (Exception error) { queuedError = error; }
        });
        lock (sync)
        {
            queued.Start();
            Check(SpinWait.SpinUntil(() => (queued.ThreadState & System.Threading.ThreadState.WaitSleepJoin) != 0,
                TimeSpan.FromSeconds(5)), "Second request never reached admission");
            Check(!startup.IsCancellationRequested && recovery.IsCurrent(intent),
                "Queued request canceled the legitimate startup/recovery before admission");
            var disconnected = runtime.Disconnect();
            Check(disconnected.Ok && !disconnected.Connected && startup.IsCancellationRequested,
                "Disconnect did not cancel the owner promptly");
        }
        Check(queued.Join(TimeSpan.FromSeconds(5)), "Queued request did not finish after disconnect");
        Check(queuedError is null && queuedResult is { Ok: true, Connected: false, State: "disconnected" },
            "A request queued before disconnect attempted a new connection");
        Check(runtime.StatusForClient().State == "disconnected" && !recovery.IsCurrent(intent),
            "Late request resurrected recovery or overwrote the disconnected state");
        Console.WriteLine("WINDOWS-CONNECT-ADMISSION idempotency, rejection ownership, recovery, queued start and disconnect cancellation PASS");
    }

    private static T Get<T>(CoreRuntime runtime, string name) =>
        (T)typeof(CoreRuntime).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(runtime)!;
    private static void Set(CoreRuntime runtime, string name, object? value) =>
        typeof(CoreRuntime).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(runtime, value);
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }

    private sealed class Session : IDisposable
    {
        internal Process Child { get; }
        internal CoreRuntime Runtime { get; }
        internal ServiceCommand Command { get; }
        internal ServiceStatus Online { get; }

        internal Session()
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("--teardown-child");
            Child = Process.Start(start) ?? throw new Exception("Fixture child did not start");
            var boundary = new FakeNetworkBoundary();
            Runtime = new CoreRuntime(boundary, ensureOwnedTunInactiveForTest: () => true);
            var policy = ApplicationPolicySnapshot.Create("smart", "none", Array.Empty<string>(), Array.Empty<string>(), new string('a', 32));
            var configId = "cfg_" + new string('a', 32);
            var boundaryIntent = new NetworkBoundaryIntent("smart", "mihomo", configId, policy.Digest, policy.Generation);
            var boundaryState = Get<NetworkBoundaryStateMachine>(Runtime, "_boundaryState");
            Check(boundaryState.Prepare(boundary, boundaryIntent).Ok && boundaryState.Activate(boundary, Child.Id).Ok,
                "Fixture boundary did not become active");
            var summary = new EnforcementSummary("smart", "none", 0, policy.Digest, policy.Generation, true);
            Runtime.ConnectControlledForTest(new Package(), new Core(Child), new Boundary());
            foreach (var (name, value) in new (string, object)[]
            {
                ("_core", Child), ("_coreName", "mihomo"), ("_effectiveCore", "mihomo"),
                ("_mode", "smart"), ("_source", "A"), ("_country", "default"), ("_configId", configId),
                ("_appPolicy", "none"), ("_appPolicyDigest", policy.Digest), ("_appPolicyGeneration", policy.Generation),
                ("_applicationPolicySnapshot", policy), ("_boundaryIntent", boundaryIntent), ("_enforcementSummary", summary),
                ("_mihomoIdentity", new MihomoRuntimeIdentity(Child.Id, "TEST-ONLY", new string('a', 64))),
                ("_mihomoGroup", new MihomoGroupState("TEST", "A-01", new[] { new MihomoProxyHealth("A-01", true, 500) })),
                ("_mihomoAllowedCandidates", new HashSet<string> { "A-01" }), ("_mihomoTunInterfaceIndex", 77)
            }) Set(Runtime, name, value);
            Command = new ServiceCommand("connect", "smart", "mihomo", "A", "default", configId, "none",
                policy.CanonicalJson, policy.Digest, policy.Generation, "direct-vmess");
            Online = ServiceStatus.ConnectedState("mihomo", "smart", configId, "A", summary);
        }

        public void Dispose()
        {
            Runtime.CancelRecovery();
            if (!Child.HasExited) { Child.Kill(); Child.WaitForExit(5000); }
            Child.Dispose();
        }
    }

    private sealed record Package : IControlledPackage
    { public string ConnectionType => "direct-vmess"; public string Core => "mihomo"; }
    private sealed class Core(Process process) : IControlledCoreAdapter
    {
        public bool Start(IControlledPackage _) => true;
        public bool IsHealthy => !process.HasExited;
        public bool Stop() { if (!process.HasExited) { process.Kill(); process.WaitForExit(5000); } return process.HasExited; }
    }
    private sealed class Boundary : IControlledNetworkBoundary
    {
        public bool EnterFailClosed() => true;
        public bool Activate() => true;
        public bool IsBound => true;
        public bool Release() => true;
    }
}
