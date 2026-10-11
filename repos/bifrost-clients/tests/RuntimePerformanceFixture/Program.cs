using Bifrost.ClientService;

static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var written = new List<string>();
var writer = new BoundedTraceWriter(async lines =>
{
    started.TrySetResult();
    await release.Task;
    written.AddRange(lines);
}, capacity: 4);
Assert(writer.TryWrite("first"), "First message rejected.");
await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
for (var i = 0; i < 4; i++) Assert(writer.TryWrite($"queued-{i}"), "Queue capacity mismatch.");
Assert(!writer.TryWrite("overflow") && writer.DroppedMessages == 1, "Slow disk did not preserve the queue bound.");
release.SetResult();
await writer.CompleteAsync().WaitAsync(TimeSpan.FromSeconds(5));
Assert(written.SequenceEqual(new[] { "first", "queued-0", "queued-1", "queued-2", "queued-3" }), "Accepted messages lost ordering.");
Assert(!writer.TryWrite("after-stop"), "Closed writer accepted a new message.");

var attempts = 0;
var firstFailure = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var recovered = new BoundedTraceWriter(lines =>
{
    if (Interlocked.Increment(ref attempts) == 1) { firstFailure.SetResult(); throw new IOException("TEST-ONLY disk failure"); }
    return Task.CompletedTask;
});
recovered.TryWrite("fail");
await firstFailure.Task.WaitAsync(TimeSpan.FromSeconds(5));
recovered.TryWrite("recover");
await recovered.CompleteAsync().WaitAsync(TimeSpan.FromSeconds(5));
Assert(recovered.FailedBatches == 1 && attempts == 2, "I/O failure terminated the diagnostics consumer.");

var directory = Path.Combine(Path.GetTempPath(), "bifrost-trace-fixture-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    var path = Path.Combine(directory, "service.log");
    await File.WriteAllTextAsync(path, new string('x', 20000));
    var sink = new RotatingTraceFile(path, maximumBytes: 4096);
    await sink.WriteBatchAsync(Enumerable.Range(0, 80).Select(i => $"{i:D3}|" + new string('测', 100)).Append("last-record").ToArray());
    Assert(new FileInfo(path).Length <= 4096 && new FileInfo(path + ".1").Length <= 4096, "Rotation exceeded the byte limit, including legacy logs.");
    Assert((await File.ReadAllTextAsync(path)).EndsWith("last-record" + Environment.NewLine), "Rotation lost the newest diagnostics.");
    Assert(Directory.GetFiles(directory).Length == 2, "Rotation accumulated extra archives.");
    var lifecycle = Path.Combine(directory, "ui");
    var privateError = new InvalidOperationException("TEST-ONLY private URL query and credential must never be logged");
    Bifrost.UiLifecycleTrace.WriteTo(lifecycle, "dispatcher-unhandled", privateError);
    var lifecyclePath = Path.Combine(lifecycle, "ui-lifecycle.ndjson");
    var record = await File.ReadAllTextAsync(lifecyclePath);
    Assert(record.Contains("InvalidOperationException") && !record.Contains(privateError.Message),
        "Lifecycle diagnostics must preserve the failure type without exception messages.");
    for (var i = 0; i < 1800; i++) Bifrost.UiLifecycleTrace.WriteTo(lifecycle, "application-exit", exitCode: 0);
    Assert(new FileInfo(lifecyclePath).Length <= 128 * 1024 && new FileInfo(lifecyclePath + ".1").Length <= 128 * 1024,
        "Idle/exit diagnostics must remain bounded.");
    Bifrost.UiLifecycleTrace.WriteTo(path, "disk-write-failure", privateError);
    Console.WriteLine("PASS UI lifecycle diagnostics redact messages, rotate and tolerate write failures");
}
finally { Directory.Delete(directory, recursive: true); }
Console.WriteLine("PASS bounded nonblocking trace queue, FIFO drain, disk failure recovery and 8 KiB rotation fixture");
