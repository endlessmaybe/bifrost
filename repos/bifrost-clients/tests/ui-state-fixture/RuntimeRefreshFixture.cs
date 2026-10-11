using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Collections.Immutable;
using System.Text.Json;
using Bifrost;
using Bifrost.ClientService;

internal static class RuntimeRefreshFixture
{
    internal static int Run()
    {
        try
        {
            using var model = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), new InMemoryUiShellPersistence(new UiShellState()));
            var changes = new List<string?>();
            model.PropertyChanged += (_, change) => changes.Add(change.PropertyName);
            model.ApplyStatus(ServiceStatus.Disconnected());
            changes.Clear();
            var bytesBefore = GC.GetAllocatedBytesForCurrentThread();
            var timer = Stopwatch.StartNew();
            for (var i = 0; i < 1000; i++) model.ApplyStatus(ServiceStatus.Disconnected());
            timer.Stop();
            var allocated = GC.GetAllocatedBytesForCurrentThread() - bytesBefore;
            var fullRefreshes = changes.Count(name => name is null or "");
            Console.WriteLine(JsonSerializer.Serialize(new { scenario = "1000-idle-status-polls", elapsed_ms = timer.Elapsed.TotalMilliseconds, allocated_bytes = allocated, full_refreshes = fullRefreshes, notifications = changes.Count }));
            if (fullRefreshes != 0 || changes.Contains(nameof(UiShellViewModel.CandidateRoutes)) || changes.Contains(nameof(UiShellViewModel.SourceRouteGroups)))
                throw new Exception("Unchanged service status rebuilt the shell or route lists.");

            var connected = ServiceStatus.ConnectedState("auto", "smart", "cfg_fixture", "A", new EnforcementSummary("smart", "none", 0, new string('f', 64), new string('a', 32), true));
            foreach (var status in new[] { connected, ServiceStatus.Blocked("BF-TEST-ONLY"), ServiceStatus.Disconnected() })
            {
                var before = ScalarValues(model);
                changes.Clear();
                model.ApplyStatus(status);
                var after = ScalarValues(model);
                foreach (var pair in before)
                    if (!Equals(pair.Value, after[pair.Key]) && !changes.Contains(pair.Key))
                        throw new Exception($"Changed binding was not notified: {pair.Key}");
                if (changes.Any(string.IsNullOrEmpty)) throw new Exception("State transition invalidated unrelated bindings.");
                if (!changes.Contains(nameof(UiShellViewModel.Presentation))) throw new Exception("State transition did not update the status indicator.");
            }
            var readback = new MihomoRuntimeReadback("TEST-ONLY", "A-01", new[] { new MihomoCandidateReadback("A-01", true, 30) }, 1, 1);
            model.ApplyStatus(connected with { Mihomo = readback });
            if (!model.IsProtected) throw new Exception("Verified service status did not become protected.");
            changes.Clear();
            model.ApplyStatus(connected with { Mihomo = readback });
            if (changes.Contains(nameof(UiShellViewModel.CandidateRoutes))) throw new Exception("Identical candidate readback rebuilt route rows.");
            model.ApplyStatus(connected with { Mihomo = readback with { Candidates = new[] { new MihomoCandidateReadback("A-01", true, 70) } } });
            if (!changes.Contains(nameof(UiShellViewModel.CandidateRoutes))) throw new Exception("Updated candidate latency was not published.");
            var freshReadback = connected with { Mihomo = readback };
            model.ApplyStatus(freshReadback);
            var automatic = model.LastAutomaticMeasurement;
            var beforeTelemetry = ScalarValues(model);
            changes.Clear();
            model.ApplyRuntimeSnapshot(freshReadback, model.Presentation,
                new UiTunnelTelemetry(true, "1.00 MB/s", "20.00 KB/s", "5.00 MB", "00:10", [1d, 2d], [0.1d, 0.2d]));
            var afterTelemetry = ScalarValues(model);
            foreach (var pair in beforeTelemetry)
                if (!Equals(pair.Value, afterTelemetry[pair.Key]) && !changes.Contains(pair.Key))
                    throw new Exception($"Telemetry changed a binding without notification: {pair.Key}");
            if (!ReferenceEquals(automatic, model.LastAutomaticMeasurement) || changes.Contains(nameof(UiShellViewModel.CandidateRoutes)))
                throw new Exception("Traffic-only update rebuilt unchanged candidate measurements.");
            if (!changes.Contains(nameof(UiShellViewModel.LiveDownloadSamples)) || !changes.Contains(nameof(UiShellViewModel.LiveUploadSamples)))
                throw new Exception("Traffic-only update did not refresh both charts.");
            changes.Clear();
            model.CheckProgramUpdateAsync().GetAwaiter().GetResult();
            if (changes.Any(string.IsNullOrEmpty)) throw new Exception("Program update feedback rebuilt unrelated UI.");
            if (!changes.Contains(nameof(UiShellViewModel.UpdateStatusTitle)) || !changes.Contains(nameof(UiShellViewModel.UpdateProgressIndeterminate)))
                throw new Exception("Program update feedback did not update the progress UI.");
            // Exercise the production failure handler, not a duplicate reducer.
            model.ApplyStatus(connected);
            var beforeLoss = model.Presentation;
            model.ApplyRuntimeReadFailure(beforeLoss, new IOException("TEST-ONLY pipe timeout"));
            if (model.Presentation.State != UiConnectionState.Reconnecting || model.IsProtected || !model.IsEnrolled)
                throw new Exception("Transient IPC failure lost the account or claimed protection.");
            if (model.Presentation.Source != beforeLoss.Source)
                throw new Exception("Transient IPC failure lost the selected source.");
            model.ApplyStatus(connected);
            if (!model.IsProtected) throw new Exception("Status readback did not recover.");
            model.ApplyStatus(ServiceStatus.Disconnected());
            model.ApplyRuntimeReadFailure(beforeLoss, new IOException("TEST-ONLY delayed failure"));
            if (model.Presentation.State != UiConnectionState.Idle)
                throw new Exception("A stale failure overwrote a newer disconnect.");
            Console.WriteLine("PASS status read failure, recovery, account retention and stale callback rejection");
            Console.WriteLine("PASS runtime refresh notifications and connection transitions");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }

    private static Dictionary<string, object?> ScalarValues(UiShellViewModel model) => typeof(UiShellViewModel)
        .GetProperties(BindingFlags.Instance | BindingFlags.Public)
        .Where(property => property.GetIndexParameters().Length == 0 && (property.PropertyType == typeof(string) || property.PropertyType.IsPrimitive || property.PropertyType.IsEnum))
        .ToDictionary(property => property.Name, property => property.GetValue(model));
}
