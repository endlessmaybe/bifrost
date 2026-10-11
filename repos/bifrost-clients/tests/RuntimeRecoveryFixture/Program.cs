using Bifrost.ClientService;

static void Check(bool value, string message) { if (!value) throw new Exception(message); }
var clock = new Clock();
var recovery = new RuntimeConnectionRecovery(clock);
var online = new ServiceStatus(true, true, "connected", null, null, "mihomo", "smart", "cfg", "A", null);
var fault = ServiceStatus.Blocked("BF-RUNTIME-HEALTH");
var calls = 0;
var next = recovery.Begin(_ => { calls++; return fault; });
recovery.CompleteInitial(next, fault);
recovery.Tick(() => fault, default);
Check(calls == 0, "Failed initial attempts must not later connect automatically");
recovery.CompleteInitial(next, online);
recovery.Tick(() => fault, default);
Check(calls == 1, "A live session recovers after health failure");
for (var i = 0; i < 10; i++) recovery.Tick(() => fault, default);
Check(calls == 1, "Repeated polls respect the recovery backoff");
clock.Advance(2);
recovery.Tick(() => fault, default);
Check(calls == 2, "Expired backoff permits retry");
recovery.Cancel();
clock.Advance(60);
recovery.Tick(() => fault, default);
Check(calls == 2, "Explicit disconnect prevents later recovery");
var staleRevision = recovery.CancellationRevision;
recovery.Cancel();
Check(recovery.TryBegin(staleRevision, _ => online) is null, "A queued connection cannot register after disconnect");
var admitted = recovery.TryBegin(recovery.CancellationRevision, _ => online)!;
Check(recovery.IsCurrent(admitted), "A fresh request after disconnect can be admitted");
recovery.Cancel();
Check(admitted.Cancellation.IsCancellationRequested, "Disconnect cancels a newly admitted request");
next = recovery.Begin(token => { calls++; recovery.Cancel(); token.ThrowIfCancellationRequested(); return online; });
recovery.CompleteInitial(next, online);
recovery.Tick(() => fault, default);
Check(!recovery.IsCurrent(next), "An in-flight recovery is canceled by user intent");
var before = calls;
next = recovery.Begin(_ => { calls++; return online; });
recovery.CompleteInitial(next, online);
recovery.Tick(() => ServiceStatus.Blocked("BF-CONFIG-SIGNATURE"), default);
recovery.Tick(() => fault, default);
Check(calls == before, "Trust failures disarm automatic recovery");
next = recovery.Begin(_ => { calls++; return online; });
recovery.CompleteInitial(next, online);
recovery.Tick(() => fault, default);
recovery.Tick(() => online, default);
Check(calls == before + 1, "Recovered sessions stop retrying");
var flapClock = new Clock();
var flapping = new RuntimeConnectionRecovery(flapClock);
var flapCalls = 0;
var flapIntent = flapping.Begin(_ => { flapCalls++; return online; });
flapping.CompleteInitial(flapIntent, online);
flapping.Tick(() => fault, default);
for(var i=0;i<10;i++) { flapping.Tick(() => online, default); flapping.Tick(() => fault, default); }
Check(flapCalls == 1, "A momentary reconnect success must not reset backoff and spin the tunnel");
flapClock.Advance(2);
flapping.Tick(() => fault, default);
Check(flapCalls == 2, "First flapping connection retry waits two seconds");
flapClock.Advance(2);
flapping.Tick(() => fault, default);
Check(flapCalls == 2, "Repeated short-lived successes escalate the backoff to five seconds");
flapClock.Advance(3);
flapping.Tick(() => fault, default);
Check(flapCalls == 3, "Escalated retry eventually runs");
flapping.Tick(() => online, default);
flapClock.Advance(31);
flapping.Tick(() => online, default);
flapping.Tick(() => fault, default);
Check(flapCalls == 4, "A continuously stable connection restores immediate recovery for a new failure");
var snapshotClock = new Clock();
var snapshot = new RuntimeStatusSnapshot(snapshotClock);
Check(snapshot.Read(false).State == "disconnected", "An uninitialized snapshot never invents a connection");
snapshot.Publish(online);
Check(snapshot.Read(false).Connected, "Fresh completed observations remain readable");
Check(snapshot.Read(true).State == "reconnecting" && !snapshot.Read(true).Connected,
    "Active recovery never presents stale protection");
snapshotClock.Advance(16);
Check(!snapshot.Read(false).Connected && snapshot.Read(false).Code == "BF-IPC-TIMEOUT", "Expired protection cannot remain connected");
using var reconnectJson = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(ServiceStatus.Reconnecting()));
Check(ServiceStatusProtocol.Parse(reconnectJson.RootElement).State == "reconnecting", "Reconnecting status passes the production wire parser");
var blockedRecovery = new RuntimeConnectionRecovery();
using var entered = new ManualResetEventSlim();
using var unblock = new ManualResetEventSlim();
var blockedIntent = blockedRecovery.Begin(_ => { entered.Set(); unblock.Wait(TimeSpan.FromSeconds(10)); return online; });
blockedRecovery.CompleteInitial(blockedIntent, online);
var background = Task.Run(() => blockedRecovery.Tick(() => fault, default));
Check(entered.Wait(TimeSpan.FromSeconds(5)), "Slow recovery entered");
try
{
    var watch = System.Diagnostics.Stopwatch.StartNew();
    for(var i=0;i<1000;i++) Check(snapshot.Read(blockedRecovery.IsReconnecting).State == "reconnecting", "Readers observe recovery without its mutation lock");
    Check(watch.Elapsed < TimeSpan.FromSeconds(1), "Status readers must not wait for the recovery callback");
}
finally { unblock.Set(); background.GetAwaiter().GetResult(); }
Check(!blockedRecovery.IsReconnecting, "Completed recovery clears its in-progress flag");
Console.WriteLine("RUNTIME-RECOVERY PASS");

sealed class Clock : TimeProvider
{
    private long _seconds;
    public override long TimestampFrequency => 1;
    public override long GetTimestamp() => _seconds;
    public void Advance(int seconds) => _seconds += seconds;
}
