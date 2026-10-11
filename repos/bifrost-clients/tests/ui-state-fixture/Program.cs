using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost;
using Bifrost.ClientService;
using Bifrost.Release;

internal static class Program
{
    private static readonly Func<byte[], byte[]> IdentityProtect = bytes => bytes.ToArray();
    private static readonly Func<byte[], byte[]> IdentityUnprotect = bytes => bytes.ToArray();

    public static int Main(string[] args)
    {
        if (args is ["--node-notifications"]) return NodeNotificationFixture.Run();
        if (args is ["--desktop-generation"])
        {
            var install = Path.Combine(Path.GetTempPath(), "BifrostTestInstall");
            var current = Path.Combine(install, ".bifrost-generations", "g-new", "Bifrost.exe");
            Assert(DesktopGenerationPolicy.IsPreviousImage(Path.Combine(install, ".bifrost-generations", "g-old", "Bifrost.exe"), current, install), "Old installed UI was not retired");
            foreach (var preserved in new[] { current, Path.Combine(install, "Bifrost.exe"),
                Path.Combine(install, ".bifrost-generations", "g-old", "BifrostClientService.exe"),
                Path.Combine(install, ".bifrost-generations", "g-old", "nested", "Bifrost.exe"),
                Path.Combine(install + "Other", ".bifrost-generations", "g-old", "Bifrost.exe") })
                Assert(!DesktopGenerationPolicy.IsPreviousImage(preserved, current, install), "Current or unrelated process could be retired");
            Console.WriteLine("DESKTOP-GENERATION exact prior UI retired; current UI, launcher, service and other installations preserved PASS");
            return 0;
        }
        if (args is ["--service-recovery-status"]) { PresentationStateBehavior(); Console.WriteLine("SERVICE-RECOVERY-UI PASS"); return 0; }
        if (args is ["--sensitive-lifecycle"]) { SensitiveLifecycleBehavior(); Console.WriteLine("SENSITIVE-LIFECYCLE PASS"); return 0; }
        if (args is ["--authentication-recovery"]) return AuthenticationRecoveryFixture.Run();
        if (args is ["--smartgate-recovery"]) return SmartGateRecovery();
        if (args is ["--connect-conflict"]) return ConnectConflict();
        if (args is ["--update-restart-intent"]) return UpdateRestartIntentFixture.Run();
        if (args is ["--runtime-refresh"]) return RuntimeRefreshFixture.Run();
        if (args is ["--tunnel-telemetry"]) return TunnelTrafficFixture.Run();
        if (args.Length == 1 && string.Equals(args[0], "--enrollment-resume-identity", StringComparison.Ordinal))
        {
            var enrollmentRoot = Path.Combine(Path.GetTempPath(), $"bifrost-enrollment-identity-{Guid.NewGuid():N}");
            try
            {
                Directory.CreateDirectory(enrollmentRoot);
                var handler = new EnrollmentIdentityHandler();
                using var client = BifrostControlClient.CreateEnrollmentIdentityClientForTest(
                    Path.Combine(enrollmentRoot, "state.bin"), "http://127.0.0.1:18183", handler);
                client.RestoreSessionIdentityForTestAsync().GetAwaiter().GetResult();
                Assert(client.PublicIdForTest == "BF-TEST-LOST-RESPONSE", "authenticated session restores missing public id");
                Assert(handler.SessionRequests == 1, "legacy session token is forcibly renewed when public id is missing");
                client.EnsureSessionForTestAsync().GetAwaiter().GetResult();
                Assert(handler.SessionRequests == 1, "fresh session is reused before its renewal window");
                client.ExpireSessionForTest();
                client.EnsureSessionForTestAsync().GetAwaiter().GetResult();
                Assert(handler.SessionRequests == 2, "expired session is renewed before an authenticated operation");
                client.EnsureSessionForTestAsync().GetAwaiter().GetResult();
                Assert(handler.SessionRequests == 2, "replacement session remains reusable");
                Assert(handler.IdentityOptInSeen, "identity session response is explicitly negotiated");
                Console.WriteLine("ENROLLMENT-RESUME-IDENTITY PASS public_id=BF-TEST-LOST-RESPONSE");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"ENROLLMENT-RESUME-IDENTITY FAIL {error}");
                return 1;
            }
            finally { try { Directory.Delete(enrollmentRoot, recursive: true); } catch { } }
        }
        if (args.Length == 1 && string.Equals(args[0], "--enrollment-replacement-rollback", StringComparison.Ordinal))
        {
            var replacementRoot = Path.Combine(Path.GetTempPath(), $"bifrost-enrollment-replacement-{Guid.NewGuid():N}");
            try
            {
                Directory.CreateDirectory(replacementRoot);
                var oldInvite = "TEST-ONLY-OLD-INVITE-CODE-0001";
                var newInvite = "TEST-ONLY-NEW-INVITE-CODE-0002";

                var missingHandler = new EnrollmentReplacementHandler("BF-DEVICE-404");
                using (var client = BifrostControlClient.CreatePendingEnrollmentReplacementClientForTest(
                    Path.Combine(replacementRoot, "missing-state.bin"), "http://127.0.0.1:18184", missingHandler, oldInvite))
                {
                    var oldDevice = client.DeviceIdForTest;
                    var oldFingerprint = client.EnrollmentInviteFingerprintForTest;
                    var oldIdempotency = client.EnrollmentIdempotencyForTest;
                    try
                    {
                        client.EnrollAsync(newInvite).GetAwaiter().GetResult();
                        throw new InvalidOperationException("replacement enrollment unexpectedly succeeded");
                    }
                    catch (InvalidOperationException error)
                    {
                        Assert(error.Message == "BF-ENROLL-001", "rejected replacement code preserves its registered error");
                    }
                    Assert(missingHandler.RedeemRequests == 1, "explicit device absence permits exactly one replacement redeem");
                    Assert(missingHandler.ChallengeDeviceIds.Count == 2 && missingHandler.ChallengeDeviceIds.Distinct(StringComparer.Ordinal).Count() == 2,
                        "replacement path proves old absence then probes a distinct fresh candidate identity");
                    Assert(client.DeviceIdForTest == oldDevice, "rejected replacement keeps the original device identity");
                    Assert(client.EnrollmentInviteFingerprintForTest == oldFingerprint, "rejected replacement keeps the original pending invite fingerprint");
                    Assert(client.EnrollmentIdempotencyForTest == oldIdempotency, "rejected replacement keeps the original pending idempotency key");
                    Assert(!client.EnrollmentCandidateExistsForTest, "rejected replacement removes the candidate sidecar");
                }

                var revokedHandler = new EnrollmentReplacementHandler("BF-AUTH-003");
                using (var client = BifrostControlClient.CreatePendingEnrollmentReplacementClientForTest(
                    Path.Combine(replacementRoot, "revoked-state.bin"), "http://127.0.0.1:18185", revokedHandler, oldInvite))
                {
                    var oldDevice = client.DeviceIdForTest;
                    try
                    {
                        client.EnrollAsync(newInvite).GetAwaiter().GetResult();
                        throw new InvalidOperationException("revoked replacement unexpectedly proceeded");
                    }
                    catch (InvalidOperationException error)
                    {
                        Assert(error.Message == "BF-ENROLL-001", "replacement still requires a valid credential");
                    }
                    Assert(revokedHandler.RedeemRequests == 1, "confirmed old revocation permits one independently authorized replacement attempt");
                    Assert(revokedHandler.ChallengeDeviceIds.Count == 2 && revokedHandler.ChallengeDeviceIds.Distinct().Count() == 2,
                        "revoked identity is not reused for replacement");
                    Assert(client.DeviceIdForTest == oldDevice, "rejected replacement preserves old state");
                    Assert(!client.EnrollmentCandidateExistsForTest, "rejected replacement removes its candidate sidecar");
                }

                Console.WriteLine("ENROLLMENT-REPLACEMENT-ROLLBACK PASS");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"ENROLLMENT-REPLACEMENT-ROLLBACK FAIL {error}");
                return 1;
            }
            finally { try { Directory.Delete(replacementRoot, recursive: true); } catch { } }
        }
        if (args.Length == 4 && string.Equals(args[0], "--enrollment-real-seed", StringComparison.Ordinal))
        {
            try
            {
                var stateFile = Path.GetFullPath(args[1]);
                var origin = args[2].TrimEnd('/');
                var invite = args[3];
                Directory.CreateDirectory(Path.GetDirectoryName(stateFile)!);
                using var transport = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromSeconds(5) };
                using var client = BifrostControlClient.CreatePendingEnrollmentReplacementClientForTest(stateFile, origin, transport, invite);
                var originalDevice = client.DeviceIdForTest;
                var result = client.EnrollAsync(invite).GetAwaiter().GetResult();
                Assert(result.Ok && client.IsEnrolled, "real Control seed enrollment completes");
                Assert(client.DeviceIdForTest == originalDevice, "first enrollment keeps its original generated identity");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentIdempotencyForTest), "successful seed enrollment clears pending idempotency");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentInviteFingerprintForTest), "successful seed enrollment clears pending invite fingerprint");
                Assert(!client.EnrollmentCandidateExistsForTest, "successful seed enrollment has no candidate sidecar");
                Assert(!string.IsNullOrWhiteSpace(client.PublicIdForTest), "seed enrollment returns a public account id");
                Assert(result.ConfigVersion > 0, "real signed configuration is committed during seed enrollment");
                client.MarkPendingEnrollmentForTest(invite);
                Assert(!string.IsNullOrWhiteSpace(client.EnrollmentIdempotencyForTest), "fixture reproduces the old-client pending idempotency on the enrolled identity");
                Assert(!string.IsNullOrWhiteSpace(client.EnrollmentInviteFingerprintForTest), "fixture reproduces the old-client pending invite fingerprint on the enrolled identity");
                Console.WriteLine($"ENROLLMENT-REAL-SEED PASS public_id={client.PublicIdForTest} device_id={client.DeviceIdForTest} config={result.ConfigVersion}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"ENROLLMENT-REAL-SEED FAIL {error}");
                return 1;
            }
        }
        if (args.Length == 5 && string.Equals(args[0], "--enrollment-real-replace", StringComparison.Ordinal))
        {
            try
            {
                var stateFile = Path.GetFullPath(args[1]);
                var origin = args[2].TrimEnd('/');
                var replacementInvite = args[3];
                var unusedInvite = args[4];
                using var transport = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromSeconds(5) };
                using var client = BifrostControlClient.CreatePersistedEnrollmentClientForTest(stateFile, origin, transport);
                var deletedDevice = client.DeviceIdForTest;
                var deletedPublicId = client.PublicIdForTest;
                Assert(!string.IsNullOrWhiteSpace(client.EnrollmentIdempotencyForTest), "deleted-account fixture begins with retained pending idempotency");
                Assert(!string.IsNullOrWhiteSpace(client.EnrollmentInviteFingerprintForTest), "deleted-account fixture begins with retained pending invite fingerprint");

                var replaced = client.EnrollAsync(replacementInvite).GetAwaiter().GetResult();
                Assert(replaced.Ok && client.IsEnrolled, "new invite activates after Control proves the retained device is absent");
                Assert(!string.Equals(client.DeviceIdForTest, deletedDevice, StringComparison.Ordinal), "replacement commits a distinct candidate device identity");
                Assert(!string.Equals(client.PublicIdForTest, deletedPublicId, StringComparison.Ordinal), "replacement belongs to a newly created account after deletion");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentIdempotencyForTest), "successful candidate commit clears pending idempotency");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentInviteFingerprintForTest), "successful candidate commit clears pending invite fingerprint");
                Assert(!client.EnrollmentCandidateExistsForTest, "successful candidate commit removes the sidecar");
                Assert(replaced.ConfigVersion > 0, "replacement commits a real signed configuration");

                var activeDevice = client.DeviceIdForTest;
                var activePublicId = client.PublicIdForTest;
                client.MarkPendingEnrollmentForTest(replacementInvite);
                var resumed = client.EnrollAsync(unusedInvite).GetAwaiter().GetResult();
                Assert(resumed.Ok && client.IsEnrolled, "active retained identity resumes when a different code is typed");
                Assert(string.Equals(client.DeviceIdForTest, activeDevice, StringComparison.Ordinal), "active retained identity is not replaced");
                Assert(string.Equals(client.PublicIdForTest, activePublicId, StringComparison.Ordinal), "active retained identity keeps its account");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentIdempotencyForTest), "successful retained-identity resume clears pending idempotency");
                Assert(string.IsNullOrWhiteSpace(client.EnrollmentInviteFingerprintForTest), "successful retained-identity resume clears pending invite fingerprint");
                Assert(!client.EnrollmentCandidateExistsForTest, "retained-identity resume never creates a candidate sidecar");
                Console.WriteLine($"ENROLLMENT-REAL-REPLACE PASS public_id={client.PublicIdForTest} device_id={client.DeviceIdForTest} config={resumed.ConfigVersion} unused_invite_preserved=pending-server-check");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"ENROLLMENT-REAL-REPLACE FAIL {error}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--release-resume-download", StringComparison.Ordinal))
            return UpdateResumeFixture.Run();
        if (args.Length == 1 && string.Equals(args[0], "--release-session-renewal", StringComparison.Ordinal))
            return UpdateResumeFixture.RunRenewedSessionFlow();
        if (args.Length == 1 && string.Equals(args[0], "--program-update-loop", StringComparison.Ordinal))
            return ProgramUpdateLoopBehavior();
        if (args.Length == 1 && string.Equals(args[0], "--historical-production-origin-migration", StringComparison.Ordinal))
        {
            var migrationRoot = Path.Combine(Path.GetTempPath(), "bifrost-origin-migration-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(migrationRoot);
                var stateFile = Path.Combine(migrationRoot, "control-state.bin");
                var ok = BifrostControlClient.HistoricalProductionOriginMigrationForTest(stateFile);
                Console.WriteLine($"HISTORICAL-PRODUCTION-ORIGIN-MIGRATION {(ok ? "PASS" : "FAIL")}");
                return ok ? 0 : 1;
            }
            finally
            {
                try { Directory.Delete(migrationRoot, true); } catch { }
            }
        }
        if (args.Length == 1 && (string.Equals(args[0], "--check-live-release", StringComparison.Ordinal) ||
            string.Equals(args[0], "--benchmark-live-release", StringComparison.Ordinal)))
        {
            try
            {
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                if (!client.IsEnrolled || string.IsNullOrWhiteSpace(client.ControlUrl) || string.IsNullOrWhiteSpace(client.SessionToken))
                    throw new InvalidOperationException("BF-RELEASE-CONTROL-NOT-CONFIGURED");
                using var http = new HttpClient(new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    UseProxy = true,
                    DefaultProxyCredentials = null,
                    ConnectTimeout = TimeSpan.FromSeconds(5),
                }) { Timeout = TimeSpan.FromSeconds(45) };
                var uri = new Uri(new Uri(client.ControlUrl.TrimEnd('/') + "/"), "v1/releases/manifest");
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", client.SessionToken);
                foreach (var pair in client.CreateSenderProof(HttpMethod.Get, uri, null))
                    request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
                var timer = Stopwatch.StartNew();
                using var response = http.Send(request, HttpCompletionOption.ResponseHeadersRead);
                var body = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                timer.Stop();
                if (!response.IsSuccessStatusCode)
                {
                    string code = "unknown";
                    try { code = JsonNode.Parse(body)?["code"]?.GetValue<string>() ?? code; } catch { }
                    Console.WriteLine($"LIVE-RELEASE FAIL status={(int)response.StatusCode} code={code} bytes={body.Length} elapsed_ms={timer.ElapsedMilliseconds}");
                    return 1;
                }
                using var envelope = JsonDocument.Parse(body);
                var manifestText = envelope.RootElement.GetProperty("manifest_text").GetString() ?? throw new InvalidDataException("BF-RELEASE-MANIFEST-MISSING");
                using var manifest = JsonDocument.Parse(manifestText);
                Console.WriteLine($"LIVE-RELEASE PASS status={(int)response.StatusCode} sequence={manifest.RootElement.GetProperty("release_sequence").GetInt64()} minimum_client={manifest.RootElement.GetProperty("minimum_client_version").GetString()} bytes={body.Length} elapsed_ms={timer.ElapsedMilliseconds}");
                if (string.Equals(args[0], "--benchmark-live-release", StringComparison.Ordinal))
                {
                    var artifact = manifest.RootElement.GetProperty("build").GetProperty("artifacts").EnumerateArray()
                        .First(item => item.GetProperty("id").GetString() == "app");
                    var artifactPath = artifact.GetProperty("path").GetString() ?? throw new InvalidDataException("BF-RELEASE-ARTIFACT");
                    var artifactBytes = artifact.GetProperty("bytes").GetInt64();
                    long received = 0;
                    var rangeCacheStatuses = new List<string>();
                    var downloadTimer = Stopwatch.StartNew();
                    for (var index = 0; index < 2; index++)
                    {
                        var start = index * 1024L * 1024L;
                        var end = Math.Min(artifactBytes - 1, start + 1024L * 1024L - 1);
                        var artifactUri = new Uri(new Uri(client.ControlUrl.TrimEnd('/') + "/"), "v1/releases/artifacts/" +
                            string.Join('/', artifactPath.Split('/').Select(Uri.EscapeDataString)));
                        using var rangeRequest = new HttpRequestMessage(HttpMethod.Get, artifactUri);
                        rangeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", client.SessionToken);
                        rangeRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(start, end);
                        foreach (var pair in client.CreateSenderProof(HttpMethod.Get, artifactUri, null))
                            rangeRequest.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
                        using var rangeResponse = http.Send(rangeRequest, HttpCompletionOption.ResponseHeadersRead);
                        if (rangeResponse.StatusCode != HttpStatusCode.PartialContent) throw new HttpRequestException($"BF-RELEASE-RANGE-{(int)rangeResponse.StatusCode}");
                        rangeCacheStatuses.Add(rangeResponse.Headers.TryGetValues("CF-Cache-Status", out var cacheValues)
                            ? cacheValues.FirstOrDefault() ?? "unknown"
                            : "absent");
                        var chunk = rangeResponse.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                        received += chunk.LongLength;
                    }
                    downloadTimer.Stop();
                    var megabytesPerSecond = received / 1024d / 1024d / Math.Max(0.001d, downloadTimer.Elapsed.TotalSeconds);
                    Console.WriteLine($"LIVE-RELEASE-RANGE PASS requests=2 bytes={received} elapsed_ms={downloadTimer.ElapsedMilliseconds} mib_per_second={megabytesPerSecond:F2} cf_cache={string.Join(',', rangeCacheStatuses)}");

                    var parallelRequests = new List<HttpRequestMessage>();
                    for (var index = 0; index < 3; index++)
                    {
                        var start = index * 4L * 1024L * 1024L;
                        var end = Math.Min(artifactBytes - 1, start + 4L * 1024L * 1024L - 1);
                        var artifactUri = new Uri(new Uri(client.ControlUrl.TrimEnd('/') + "/"), "v1/releases/artifacts/" +
                            string.Join('/', artifactPath.Split('/').Select(Uri.EscapeDataString)));
                        var rangeRequest = new HttpRequestMessage(HttpMethod.Get, artifactUri);
                        rangeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", client.SessionToken);
                        rangeRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(start, end);
                        foreach (var pair in client.CreateSenderProof(HttpMethod.Get, artifactUri, null))
                            rangeRequest.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
                        parallelRequests.Add(rangeRequest);
                    }
                    var parallelTimer = Stopwatch.StartNew();
                    try
                    {
                        var parallelBodies = Task.WhenAll(parallelRequests.Select(async rangeRequest =>
                        {
                            using var rangeResponse = await http.SendAsync(rangeRequest, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                            if (rangeResponse.StatusCode != HttpStatusCode.PartialContent) throw new HttpRequestException($"BF-RELEASE-RANGE-{(int)rangeResponse.StatusCode}");
                            return await rangeResponse.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        })).GetAwaiter().GetResult();
                        parallelTimer.Stop();
                        var parallelBytes = parallelBodies.Sum(chunk => (long)chunk.LongLength);
                        var parallelMiBPerSecond = parallelBytes / 1024d / 1024d / Math.Max(0.001d, parallelTimer.Elapsed.TotalSeconds);
                        Console.WriteLine($"LIVE-RELEASE-PARALLEL PASS requests=3 bytes={parallelBytes} elapsed_ms={parallelTimer.ElapsedMilliseconds} mib_per_second={parallelMiBPerSecond:F2}");
                    }
                    finally
                    {
                        foreach (var rangeRequest in parallelRequests) rangeRequest.Dispose();
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-RELEASE FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--refresh-live", StringComparison.Ordinal))
        {
            try
            {
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                Console.WriteLine($"LIVE-REFRESH enrolled={client.IsEnrolled} local={client.IsLocalEvaluation} before={client.LastConfigVersion} origin={client.CompiledOriginDisplay}");
                var result = client.RefreshAsync().GetAwaiter().GetResult();
                Console.WriteLine($"LIVE-REFRESH PASS ok={result.Ok} version={result.ConfigVersion} message={result.Message}");
                return result.Ok ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-REFRESH FAIL {error}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--rotate-live-recovery", StringComparison.Ordinal))
        {
            try
            {
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                var result = client.RotateRecoveryCodeAsync().GetAwaiter().GetResult();
                var stored = client.RecoveryCode;
                Console.WriteLine($"LIVE-RECOVERY-ROTATE PASS ok={result.Ok} stored={!string.IsNullOrWhiteSpace(stored)} length={stored?.Length ?? 0} config={client.LastConfigVersion}");
                return result.Ok && !string.IsNullOrWhiteSpace(stored) ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-RECOVERY-ROTATE FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--inspect-live-client", StringComparison.Ordinal))
        {
            try
            {
                using var client = new BifrostControlClient();
                Console.WriteLine($"LIVE-CLIENT enrolled={client.IsEnrolled} pending_enrollment={client.HasPendingEnrollment} pending_recovery={client.HasPendingRecovery} recovery_stored={!string.IsNullOrWhiteSpace(client.RecoveryCode)} config={client.LastConfigVersion} origin={client.CompiledOriginDisplay} status={client.ConfigurationStatus}");
                return client.IsEnrolled && client.LastConfigVersion > 0 ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-CLIENT FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--service-status", StringComparison.Ordinal))
        {
            try
            {
                var status = new ClientServiceContract().GetStatusAsync().GetAwaiter().GetResult();
                Console.WriteLine($"SERVICE-STATUS ok={status.Ok} connected={status.Connected} state={status.State} code={status.Code ?? "null"} core={status.Core ?? "null"} mode={status.Mode ?? "null"} source={status.Source ?? "null"} config={status.ConfigId ?? "null"}");
                if (status.Enforcement is not null)
                    Console.WriteLine($"SERVICE-ENFORCEMENT route={status.Enforcement.Route} policy={status.Enforcement.Policy} identities={status.Enforcement.IdentityCount} readback={status.Enforcement.ReadbackVerified}");
                if (status.Mihomo is not null)
                {
                    Console.WriteLine($"SERVICE-MIHOMO group={status.Mihomo.Group} active={status.Mihomo.ActiveCandidate} process={status.Mihomo.ProcessId} tun={status.Mihomo.TunInterfaceIndex}");
                    foreach (var candidate in status.Mihomo.Candidates.Where(candidate => candidate.Alive).OrderBy(candidate => candidate.DelayMs))
                        Console.WriteLine($"SERVICE-MIHOMO-CANDIDATE name={candidate.Name} alive={candidate.Alive} delay_ms={candidate.DelayMs}");
                }
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"SERVICE-STATUS FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--live-auto-connect-cycle", StringComparison.Ordinal))
        {
            BifrostControlClient? client = null;
            var service = new ClientServiceContract();
            var connectedByFixture = false;
            try
            {
                client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                var before = service.GetStatusAsync(CancellationToken.None).GetAwaiter().GetResult();
                if (before.Connected)
                    throw new InvalidOperationException("diagnostic requires an initially disconnected service");

                // Reuse the production-verified DPAPI/LKG package already on
                // disk. The freshly rebuilt diagnostic assembly intentionally
                // does not carry production config-signing test overrides;
                // LocalSystem will re-validate the signed package at stage.
                if (!client.IsEnrolled || client.LastConfigVersion <= 0)
                    throw new InvalidOperationException("no verified cached configuration");
                var options = client.GetUiConfigOptions();
                var persisted = new ProtectedUiShellPersistence().Load();
                var source = options.Sources.Any(item => string.Equals(item.Code, persisted.Source, StringComparison.OrdinalIgnoreCase))
                    ? persisted.Source
                    : options.Sources.FirstOrDefault()?.Code ?? throw new InvalidDataException("no signed source");
                if (options.CandidatesBySource is null ||
                    !options.CandidatesBySource.TryGetValue(source, out var candidates) ||
                    candidates.Count == 0)
                    throw new InvalidDataException("no signed candidates");

                var routeMode = string.IsNullOrWhiteSpace(persisted.RouteMode) ? ProtocolCodes.ModeSmart : persisted.RouteMode;
                var snapshot = ApplicationPolicySnapshot.Create(routeMode, "none",
                    Array.Empty<string>(), Array.Empty<string>(), Guid.NewGuid().ToString("N"));
                var package = client.PrepareSignedPackageAsync(source, "default", routeMode, ProtocolCodes.CoreAuto,
                    candidates[0].Code, Array.Empty<string>(), Array.Empty<string>(), null, "none",
                    CancellationToken.None, snapshot, "direct-vmess").GetAwaiter().GetResult();
                var staged = service.StageConfigAsync(package, CancellationToken.None).GetAwaiter().GetResult();
                if (!staged.Ok || string.IsNullOrWhiteSpace(staged.ConfigId) || string.IsNullOrWhiteSpace(staged.Core))
                    throw new InvalidOperationException($"stage failed: {staged.Code}");
                var connected = service.ConnectAsync(routeMode, staged.Core, source, "default", staged.ConfigId,
                    snapshot.PolicyMode, CancellationToken.None, snapshot, "direct-vmess")
                    .GetAwaiter().GetResult();
                connectedByFixture = connected.Connected;
                if (!connected.Ok || !connected.Connected)
                    throw new InvalidOperationException($"connect failed: {connected.Code}");

                var status = service.GetStatusAsync(CancellationToken.None).GetAwaiter().GetResult();
                Console.WriteLine($"LIVE-AUTO-CONNECT PASS source={source} config={client.LastConfigVersion} active={status.Mihomo?.ActiveCandidate ?? "null"} group={status.Mihomo?.Group ?? "null"}");
                if (status.Mihomo is not null)
                    foreach (var candidate in status.Mihomo.Candidates.Where(item => item.Alive).OrderBy(item => item.DelayMs).Take(8))
                        Console.WriteLine($"LIVE-AUTO-CANDIDATE name={candidate.Name} delay_ms={candidate.DelayMs}");
                return status.Ok && status.Connected && !string.IsNullOrWhiteSpace(status.Mihomo?.ActiveCandidate) ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-AUTO-CONNECT FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
            finally
            {
                if (client is not null)
                {
                    if (connectedByFixture)
                    {
                        try
                        {
                            var disconnected = service.DisconnectAsync(CancellationToken.None).GetAwaiter().GetResult();
                            Console.WriteLine($"LIVE-AUTO-DISCONNECT ok={disconnected.Ok} connected={disconnected.Connected} state={disconnected.State}");
                        }
                        catch (Exception error)
                        {
                            Console.Error.WriteLine($"LIVE-AUTO-DISCONNECT FAIL {error.GetType().Name}: {error.Message}");
                        }
                    }
                    client.Dispose();
                }
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--connect-staged-package", StringComparison.Ordinal))
        {
            try
            {
                var packagePath = Path.GetFullPath(args[1]);
                using var package = JsonDocument.Parse(File.ReadAllBytes(packagePath));
                var packageRoot = package.RootElement;
                var configId = packageRoot.GetProperty("config_id").GetString() ?? throw new InvalidDataException("config id missing");
                var source = packageRoot.GetProperty("source").GetString() ?? throw new InvalidDataException("source missing");
                var country = packageRoot.GetProperty("country").GetString() ?? throw new InvalidDataException("country missing");
                var mode = packageRoot.GetProperty("mode").GetString() ?? throw new InvalidDataException("mode missing");
                var snapshotText = packageRoot.GetProperty("app_policy_snapshot").GetString() ?? throw new InvalidDataException("application policy missing");
                var snapshot = ApplicationPolicySnapshot.Parse(snapshotText);
                var connectionType = string.Equals(country, "default", StringComparison.OrdinalIgnoreCase)
                    ? "direct-vmess"
                    : "smartgate";
                var status = new ClientServiceContract().ConnectAsync(
                    mode, ProtocolCodes.CoreMihomo, source, country, configId, snapshot.PolicyMode,
                    CancellationToken.None, snapshot, connectionType).GetAwaiter().GetResult();
                Console.WriteLine($"SERVICE-CONNECT ok={status.Ok} connected={status.Connected} state={status.State} code={status.Code ?? "null"} core={status.Core ?? "null"} mode={status.Mode ?? "null"} source={status.Source ?? "null"} config={status.ConfigId ?? "null"}");
                return status.Ok && status.Connected ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"SERVICE-CONNECT FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--probe-live-sources", StringComparison.Ordinal))
        {
            try
            {
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                Console.WriteLine($"LIVE-CONTROL enrolled={client.IsEnrolled} local={client.IsLocalEvaluation} config={client.LastConfigVersion} origin={client.CompiledOriginDisplay}");
                var options = client.GetUiConfigOptions();
                foreach (var source in options.Sources)
                {
                    try
                    {
                        var selected = client.ProbeSelectedCandidateAsync(source.Code).GetAwaiter().GetResult();
                        Console.WriteLine($"LIVE-PROBE source={source.Code} selected={selected ?? "null"}");
                    }
                    catch (Exception error)
                    {
                        Console.WriteLine($"LIVE-PROBE source={source.Code} fail={error.Message}");
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-PROBE FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--probe-live-source-all", StringComparison.Ordinal))
        {
            try
            {
                var requestedSource = args[1].Trim().ToUpperInvariant();
                if (requestedSource is not ("A" or "B")) throw new InvalidDataException("BF-CONFIG-SOURCE");
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                var stateField = typeof(BifrostControlClient).GetField("_state", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("state field unavailable");
                var state = stateField.GetValue(client) ?? throw new InvalidOperationException("state unavailable");
                var configProperty = state.GetType().GetProperty("ConfigJson", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("config property unavailable");
                var configText = configProperty.GetValue(state) as string ?? throw new InvalidOperationException("config unavailable");
                var config = JsonNode.Parse(configText)?.AsObject() ?? throw new InvalidOperationException("config parse failed");
                var source = config["sources"]?.AsArray().OfType<JsonObject>()
                    .SingleOrDefault(item => string.Equals(item["code"]?.GetValue<string>(), requestedSource, StringComparison.Ordinal))
                    ?? throw new InvalidDataException("BF-CONFIG-SOURCE");
                var serverName = source["server_name"]?.GetValue<string>() ?? string.Empty;
                var wsPath = source["ws_path"]?.GetValue<string>() ?? "/";
                var transport = source["transport"]?.AsObject();
                var descriptor = new ProbeDescriptor(
                    transport?["host"]?.GetValue<string>() ?? serverName,
                    transport?["sni"]?.GetValue<string>() ?? serverName,
                    wsPath,
                    true,
                    transport?["network"]?.GetValue<string>() ?? string.Empty);
                var candidates = source["candidates"]?.AsArray().OfType<JsonObject>().ToArray()
                    ?? throw new InvalidDataException("BF-CONFIG-CANDIDATE");
                using var concurrency = new SemaphoreSlim(4, 4);
                var probes = candidates.Select(async candidate =>
                {
                    var label = candidate["label"]?.GetValue<string>() ?? "?";
                    var dial = candidate["dial_address"]?.GetValue<string>() ?? candidate["address"]?.GetValue<string>() ?? string.Empty;
                    var port = candidate["port"]?.GetValue<int>() ?? 443;
                    await concurrency.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                        var budget = new ProbeBudget(64 * 1024);
                        var diagnostic = await new CandidateProbeEngine().ProbeAsyncForDiagnostics(dial, port, descriptor, budget, timeout.Token).ConfigureAwait(false);
                        return (Label: label, Result: diagnostic.Result, Bytes: budget.ConsumedBytes);
                    }
                    catch
                    {
                        return (Label: label, Result: (ProbeResult?)null, Bytes: 0L);
                    }
                    finally { concurrency.Release(); }
                }).ToArray();
                var results = Task.WhenAll(probes).GetAwaiter().GetResult().OrderBy(item => item.Label, StringComparer.Ordinal).ToArray();
                foreach (var item in results)
                    Console.WriteLine($"LIVE-ALL source={requestedSource} label={item.Label} success={item.Result?.Success.ToString() ?? "false"} tls={item.Result?.TlsSuccess.ToString() ?? "false"} rtt={item.Result?.RttMs.ToString("F1") ?? "null"} bytes={item.Bytes}");
                var alive = results.Count(item => item.Result is { Success: true });
                Console.WriteLine($"LIVE-ALL-SUMMARY source={requestedSource} alive={alive} total={results.Length}");
                return alive > 0 ? 0 : 1;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-ALL FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--export-live-config", StringComparison.Ordinal))
        {
            try
            {
                var destination = Path.GetFullPath(args[1]);
                if (!destination.StartsWith(@"H:\CodexTemp\work\", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("BF-TEST-SCOPE");
                var parent = Path.GetDirectoryName(destination) ?? throw new InvalidDataException("BF-TEST-SCOPE");
                Directory.CreateDirectory(parent);
                using var client = BifrostControlClient.CreateLiveDiagnosticClientForTest();
                var stateField = typeof(BifrostControlClient).GetField("_state", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("state field unavailable");
                var state = stateField.GetValue(client) ?? throw new InvalidOperationException("state unavailable");
                var configProperty = state.GetType().GetProperty("ConfigJson", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("config property unavailable");
                var configText = configProperty.GetValue(state) as string ?? throw new InvalidOperationException("config unavailable");
                File.WriteAllText(destination, configText, new UTF8Encoding(false));
                Console.WriteLine($"LIVE-CONFIG-EXPORT PASS version={client.LastConfigVersion} bytes={Encoding.UTF8.GetByteCount(configText)}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-CONFIG-EXPORT FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--live-probe-metadata", StringComparison.Ordinal))
        {
            try
            {
                using var client = new BifrostControlClient();
                var stateField = typeof(BifrostControlClient).GetField("_state", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("state field unavailable");
                var state = stateField.GetValue(client) ?? throw new InvalidOperationException("state unavailable");
                var configProperty = state.GetType().GetProperty("ConfigJson", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("config property unavailable");
                var configText = configProperty.GetValue(state) as string ?? throw new InvalidOperationException("config unavailable");
                var config = JsonNode.Parse(configText)?.AsObject() ?? throw new InvalidOperationException("config parse failed");
                foreach (var source in config["sources"]?.AsArray().OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                {
                    if (source["configured"]?.GetValue<bool>() != true) continue;
                    var code = source["code"]?.GetValue<string>() ?? "?";
                    var serverName = source["server_name"]?.GetValue<string>() ?? "";
                    var wsPath = source["ws_path"]?.GetValue<string>() ?? "/";
                    var transport = source["transport"]?.AsObject();
                    var host = transport?["host"]?.GetValue<string>() ?? serverName;
                    var sni = transport?["sni"]?.GetValue<string>() ?? serverName;
                    var network = transport?["network"]?.GetValue<string>() ?? "";
                    foreach (var candidate in source["candidates"]?.AsArray().OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                    {
                        var label = candidate["label"]?.GetValue<string>() ?? "?";
                        var dial = candidate["dial_address"]?.GetValue<string>() ?? candidate["address"]?.GetValue<string>() ?? "?";
                        var port = candidate["port"]?.GetValue<int>() ?? 443;
                        Console.WriteLine($"LIVE-CANDIDATE source={code} label={label} dial={dial} port={port} host={host} sni={sni} network={network} path={wsPath}");
                        var descriptor = new ProbeDescriptor(host, sni, wsPath, true, network);
                        foreach (var limit in new[] { CandidateProbeEngine.DefaultRoundBudgetBytes, 64 * 1024 })
                        {
                            var budget = new ProbeBudget(limit);
                            var diagnostic = new CandidateProbeEngine().ProbeAsyncForDiagnostics(dial, port, descriptor, budget, CancellationToken.None).GetAwaiter().GetResult();
                            var result = diagnostic.Result;
                            Console.WriteLine($"LIVE-DIRECT-PROBE source={code} label={label} budget={limit} success={result?.Success.ToString() ?? "null"} tls={result?.TlsSuccess.ToString() ?? "null"} rtt={result?.RttMs.ToString("F1") ?? "null"} loss={result?.LossPercent.ToString("F1") ?? "null"} result_bytes={result?.Bytes.ToString() ?? "null"} consumed={budget.ConsumedBytes} exhausted={budget.IsExhausted}");
                            foreach (var item in diagnostic.Events) Console.WriteLine($"LIVE-DIRECT-PROBE-EVENT source={code} label={label} {item}");
                        }
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"LIVE-CANDIDATE FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--inspect-live-selection", StringComparison.Ordinal))
        {
            try
            {
                var state = new UiStateStore().Load();
                static string Value(JsonObject value, string key, string fallback) =>
                    value[key] is JsonValue node && node.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)
                        ? text
                        : fallback;
                Console.WriteLine($"LIVE-SELECTION mode={Value(state, "mode", "smart")} core={Value(state, "core", "auto")} source={Value(state, "source", "unset")} country={Value(state, "country", "default")} connection={Value(state, "connection_type", "direct-vmess")} route={Value(state, "route_mode", "smart")} candidate_mode={Value(state, "candidate_mode", "auto")} candidate_label={Value(state, "candidate_label", "unset")}");
                return 0;
            }
            catch (Exception error)
            {
                Console.WriteLine($"LIVE-SELECTION FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--release-corpus", StringComparison.Ordinal))
        {
            try
            {
                var count = ReleaseCorpusFixture.Run(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "release-golden-vectors-v1.json")));
                Console.WriteLine($"RELEASE-CORPUS PASS vectors={count}");
                return 0;
            }
            catch (Exception error)
            {
                Console.WriteLine($"RELEASE-CORPUS FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--release-trust-binding", StringComparison.Ordinal))
        {
            Console.WriteLine($"RELEASE-TRUST-BINDING provisioned={ReleaseContract.TrustRootProvisioned} fingerprint={ReleaseContract.TrustRootFingerprint ?? "null"}");
            return ReleaseContract.TrustRootProvisioned && !string.IsNullOrWhiteSpace(ReleaseContract.TrustRootFingerprint) ? 0 : 1;
        }
        if (args.Length == 1 && string.Equals(args[0], "--release-envelope-corpus", StringComparison.Ordinal))
        {
            try
            {
                var count = ReleaseCorpusFixture.RunFullEnvelope(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "release-envelope-corpus-v2.json")));
                Console.WriteLine($"RELEASE-ENVELOPE-CORPUS PASS vectors={count}");
                return 0;
            }
            catch (Exception error)
            {
                Console.WriteLine($"RELEASE-ENVELOPE-CORPUS FAIL {error.GetType().Name}: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--release-compiled-binding", StringComparison.Ordinal))
        {
            try
            {
                var corpus = JsonNode.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "release-envelope-corpus-v2.json")))?.AsObject() ?? throw new InvalidDataException("BF-RELEASE-CORPUS");
                var envelope = corpus["base_envelope"]?.AsObject() ?? throw new InvalidDataException("BF-RELEASE-CORPUS");
                Console.WriteLine($"RELEASE-COMPILED-BINDING INPUT provisioned={ReleaseContract.TrustRootProvisioned} key_id={ReleaseContract.TrustRootKeyId} fp={ReleaseContract.TrustRootFingerprint ?? "null"}");
                var envelopeBytes = Encoding.UTF8.GetBytes(envelope.ToJsonString());
                Bifrost.Release.ReleaseUpdateManager.VerifiedEnvelope verified;
                try { verified = ReleaseUpdateManager.VerifyEnvelope(envelopeBytes); }
                catch (Exception compiledError)
                {
                    try { _ = ReleaseUpdateManager.VerifyEnvelopeForCorpus(envelopeBytes, corpus["trust"]!["public_key_pem"]!.GetValue<string>()); }
                    catch (Exception harnessError) { throw new InvalidDataException($"compiled={compiledError.Message};harness={harnessError.Message}", compiledError); }
                    throw new InvalidDataException($"compiled={compiledError.Message}", compiledError);
                }
                if (verified.Plan is null || verified.Plan.RootFingerprint != ReleaseContract.TrustRootFingerprint) throw new InvalidDataException("BF-RELEASE-TRUST-ROOT");
                var tampered = JsonNode.Parse(envelope.ToJsonString())!.AsObject();
                var originalSignature = tampered["signature"]!.GetValue<string>();
                tampered["signature"] = (originalSignature[0] == 'A' ? 'B' : 'A') + originalSignature[1..];
                var rejected = false;
                try { ReleaseUpdateManager.VerifyEnvelope(Encoding.UTF8.GetBytes(tampered.ToJsonString())); } catch (Exception) { rejected = true; }
                if (!rejected) throw new InvalidDataException("BF-RELEASE-SIGNATURE");
                Console.WriteLine($"RELEASE-COMPILED-BINDING PASS provisioned={ReleaseContract.TrustRootProvisioned} sequence={verified.Sequence} root_fingerprint={verified.Plan.RootFingerprint}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"RELEASE-COMPILED-BINDING REJECTED: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 1 && string.Equals(args[0], "--config-key-trust", StringComparison.Ordinal))
        {
            try
            {
                ConfigKeyTrustBehavior();
                Console.WriteLine("CONFIG-KEY-TRUST PASS");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CONFIG-KEY-TRUST FAIL: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--validate-manifest", StringComparison.Ordinal))
        {
            try
            {
                ValidateExternalResponse(args[1], "/v1/config/manifest");
                Console.WriteLine("CLIENT-MANIFEST-PASS");
                return 0;
            }
            catch
            {
                Console.WriteLine("CLIENT-MANIFEST-REJECTED");
                return 1;
            }
        }
        if ((args.Length == 2 || args.Length == 3) && string.Equals(args[0], "--validate-envelope", StringComparison.Ordinal))
        {
            try
            {
                long? expectedVersion = args.Length == 3 && long.TryParse(args[2], out var parsedVersion) ? parsedVersion : null;
                ValidateExternalResponse(args[1], "/v1/config/packages/1", expectedVersion);
                Console.WriteLine("CLIENT-ENVELOPE-PASS");
                return 0;
            }
            catch
            {
                Console.WriteLine("CLIENT-ENVELOPE-REJECTED");
                return 1;
            }
        }
        if (args.Length == 6 && string.Equals(args[0], "--consume-envelope", StringComparison.Ordinal))
        {
            try
            {
                var envelopeBytes = File.ReadAllBytes(args[1]);
                var privateKey = File.ReadAllBytes(args[2]);
                var trustedKey = File.ReadAllBytes(args[5]);
                try
                {
                    using var strict = PipeClientProtocol.ParseStrict(envelopeBytes);
                    var envelope = JsonNode.Parse(envelopeBytes)?.AsObject() ?? throw new InvalidDataException("envelope");
                    if (!long.TryParse(args[4], out var version) || version <= 0) throw new InvalidDataException("version");
                    using var client = new BifrostControlClient(screenshotOnly: true);
                    var result = client.ConsumePackageForLifecycleTest(envelope, version, privateKey, args[3], trustedKey);
                    var contentDigest = SemanticContentDigest(result.Content);
                    Console.WriteLine($"CLIENT-PACKAGE-COMMIT PASS device=windows version={result.Version} digest={result.Digest} content_digest={contentDigest} persistence=atomic_dpapi");
                    return 0;
                }
                finally { CryptographicOperations.ZeroMemory(privateKey); CryptographicOperations.ZeroMemory(trustedKey); CryptographicOperations.ZeroMemory(envelopeBytes); }
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CLIENT-PACKAGE-COMMIT REJECTED: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--readback-state", StringComparison.Ordinal))
        {
            try
            {
                using var client = new BifrostControlClient(screenshotOnly: true);
                var result = client.ReadPersistedLifecycleStateForTest(args[1]);
                Console.WriteLine($"CLIENT-PACKAGE-READBACK PASS device=windows version={result.Version} digest={result.Digest} content_digest={SemanticContentDigest(result.Content)} persistence={result.Persistence}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CLIENT-PACKAGE-READBACK REJECTED: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--compile-matrix", StringComparison.Ordinal))
        {
            try
            {
                using var client = new BifrostControlClient(screenshotOnly: true);
                var matrix = client.CompileSelectionMatrixForLifecycleTest(args[1]).GetAwaiter().GetResult();
                Console.WriteLine($"CLIENT-SELECTION-MATRIX PASS cases={matrix.Cases} cross_source_rejected={matrix.CrossSourceRejected.ToString().ToLowerInvariant()} digests={matrix.Digests}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CLIENT-SELECTION-MATRIX REJECTED: {error.Message}");
                return 1;
            }
        }
        if (args.Length == 2 && string.Equals(args[0], "--controlled-runtime", StringComparison.Ordinal))
        {
            try
            {
                using var client = new BifrostControlClient(screenshotOnly: true);
                var matrix = client.RunControlledRuntimeMatrixForLifecycleTest(args[1]).GetAwaiter().GetResult();
                Console.WriteLine($"CLIENT-CONTROLLED-RUNTIME PASS cases={matrix.Cases} fail_closed={matrix.FailClosedFailures} routes={matrix.Routes}");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CLIENT-CONTROLLED-RUNTIME REJECTED: {error.Message}");
                return 1;
            }
        }
        if ((args.Length == 3 || args.Length == 4) && string.Equals(args[0], "--offline-refresh", StringComparison.Ordinal))
        {
            try
            {
                using var client = BifrostControlClient.CreateLifecycleRefreshClient(args[1], args[2], new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false });
                var result = client.RefreshAsync().GetAwaiter().GetResult();
                if (!result.Ok || !result.Message.StartsWith("offline:", StringComparison.Ordinal)) throw new InvalidDataException("BF-CONTROL-OFFLINE-EVIDENCE");
                var readback = client.ReadPersistedLifecycleStateForTest(args[1]);
                var contentDigest = SemanticContentDigest(readback.Content);
                var marker = $"CLIENT-OFFLINE-REFRESH PASS outcome=offline version={readback.Version} digest={readback.Digest} content_digest={contentDigest} persistence={readback.Persistence}";
                if (args.Length == 4) File.WriteAllText(args[3], marker, Encoding.UTF8); else Console.WriteLine(marker);
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"CLIENT-OFFLINE-REFRESH REJECTED: {error.Message}");
                return 1;
            }
        }
        var root = Path.Combine(Path.GetTempPath(), $"bifrost-ui-state-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            RoundTripAndClear(root);
            LegacyMigration(root);
            EncryptedValueWinsAndLegacyIsScrubbed(root);
            MigrationWriteFailureKeepsLegacy(root);
            MigrationScrubFailureIsVisible(root);
            MalformedLegacyIsRejected(root);
            ReparseLegacyIsRejectedWhenSupported(root);
            ErrorMappingNeverLeaksExceptionTextV2();
            WindowsAvailabilityClassifierBehavior();
            WindowsGatewayContentTypeOrderingBehavior();
            WindowsProductionRefreshBoundaryBehavior();
            ProtocolVectorsAndGeneratedResponseBinding();
            SensitiveLifecycleBehavior();
            PresentationStateBehavior();
            UiShellViewModelBehavior();
            UiShellFunctionalControlsBehavior();
            StartupEnrollmentResumeBehavior();
            UiShellPersistenceFailureBehavior();
            DynamicOptionPersistenceBehavior();
            OriginConfigurationBehavior(args.Contains("--configured", StringComparer.Ordinal));
            CandidateSelectionContractBehavior();
            CandidateSelectionNoDuplicateBehavior();
            ActivationProbeLifecycleBehavior();
            ProbeLifecycleBehavior();
            Console.WriteLine("UI-STATE-FIXTURE PASS");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"UI-STATE-FIXTURE FAIL: {error.Message}");
            return 1;
        }
        finally
        {
            try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static void RoundTripAndClear(string root)
    {
        var store = NewStore(root);
        store.Save(State("new-source"));
        var loaded = store.Load();
        Assert(loaded["source"]?.GetValue<string>() == "new-source", "encrypted round-trip");

        File.WriteAllText(Path.Combine(root, ".ui-state.tmp-stale"), "stale", Encoding.UTF8);
        store.Clear();
        Assert(!File.Exists(Path.Combine(root, "ui-state.bin")), "clear removes encrypted state");
        Assert(!File.Exists(Path.Combine(root, ".ui-state.tmp-stale")), "clear removes stale temp");
    }

    private static void LegacyMigration(string root)
    {
        Reset(root);
        File.WriteAllText(Path.Combine(root, "ui-state.json"), "{\"mode\":\"smart\",\"source\":\"legacy-source\"}", new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(root, "theme.txt"), "dark", new UTF8Encoding(false));
        var loaded = NewStore(root).Load();
        Assert(loaded["source"]?.GetValue<string>() == "legacy-source", "legacy source migration");
        Assert(loaded["theme"]?.GetValue<string>() == "dark", "legacy theme migration");
        Assert(loaded["design_direction"]?.GetValue<string>() == "a", "legacy migration defaults to recommended design direction");
        Assert(File.Exists(Path.Combine(root, "ui-state.bin")), "migration writes protected state");
        Assert(!File.Exists(Path.Combine(root, "ui-state.json")), "migration scrubs legacy json");
        Assert(!File.Exists(Path.Combine(root, "theme.txt")), "migration scrubs legacy theme");
    }

    private static void EncryptedValueWinsAndLegacyIsScrubbed(string root)
    {
        Reset(root);
        NewStore(root).Save(State("encrypted-source"));
        File.WriteAllText(Path.Combine(root, "ui-state.json"), "{\"source\":\"stale-source\"}", new UTF8Encoding(false));
        var loaded = NewStore(root).Load();
        Assert(loaded["source"]?.GetValue<string>() == "encrypted-source", "encrypted value remains authoritative");
        Assert(!File.Exists(Path.Combine(root, "ui-state.json")), "stale legacy value scrubbed");
    }

    private static void MigrationWriteFailureKeepsLegacy(string root)
    {
        Reset(root);
        var legacyPath = Path.Combine(root, "ui-state.json");
        File.WriteAllText(legacyPath, "{\"source\":\"legacy-source\"}", new UTF8Encoding(false));
        var code = ExpectCode(() => new UiStateStore(root, _ => throw new InvalidOperationException("protect"), IdentityUnprotect).Load());
        Assert(code == "BF-UI-STATE-CORRUPT", "migration write failure is visible");
        Assert(File.Exists(legacyPath), "failed migration retains legacy");
        Assert(!File.Exists(Path.Combine(root, "ui-state.bin")), "failed migration has no binary");
    }

    private static void MigrationScrubFailureIsVisible(string root)
    {
        Reset(root);
        var legacyPath = Path.Combine(root, "ui-state.json");
        File.WriteAllText(legacyPath, "{\"source\":\"legacy-source\"}", new UTF8Encoding(false));
        var code = ExpectCode(() => new UiStateStore(
            root,
            IdentityProtect,
            IdentityUnprotect,
            path => path.EndsWith("ui-state.json", StringComparison.OrdinalIgnoreCase) ? false : Delete(path)).Load());
        Assert(code == "BF-UI-STATE-MIGRATION", "scrub failure is visible");
        Assert(File.Exists(legacyPath), "failed scrub retains legacy");
        Assert(File.Exists(Path.Combine(root, "ui-state.bin")), "protected candidate remains recoverable");
        Assert(NewStore(root).Load()["source"]?.GetValue<string>() == "legacy-source", "retry completes migration");
    }

    private static void MalformedLegacyIsRejected(string root)
    {
        Reset(root);
        File.WriteAllText(Path.Combine(root, "ui-state.json"), "{\"unknown\":\"value\"}", new UTF8Encoding(false));
        var code = ExpectCode(() => NewStore(root).Load());
        Assert(code == "BF-UI-STATE-MIGRATION", "unknown legacy field rejected");
        Assert(File.Exists(Path.Combine(root, "ui-state.json")), "malformed legacy retained");
    }

    private static void ReparseLegacyIsRejectedWhenSupported(string root)
    {
        Reset(root);
        var target = Path.Combine(root, "legacy-target.json");
        var link = Path.Combine(root, "ui-state.json");
        File.WriteAllText(target, "{\"source\":\"legacy-source\"}", new UTF8Encoding(false));
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (UnauthorizedAccessException) { Console.WriteLine("PENDING-REPARSE-CAPABILITY"); return; }
        catch (PlatformNotSupportedException) { Console.WriteLine("PENDING-REPARSE-CAPABILITY"); return; }
        catch (IOException) { Console.WriteLine("PENDING-REPARSE-CAPABILITY"); return; }

        var code = ExpectCode(() => NewStore(root).Load());
        Assert(code is "BF-UI-STATE-CORRUPT" or "BF-UI-STATE-MIGRATION", "reparse legacy rejected");
    }

    private static void ErrorMappingNeverLeaksExceptionTextV2()
    {
        const string secret = "https://node.test.invalid/uuid?token=TEST-ONLY";
        var generic = UiErrorMapper.ToUserMessage(new InvalidOperationException(secret), "连接");
        Assert(generic == ErrorRegistry.Describe("BF-INTERNAL").MessageZh, "unknown error maps through generated registry");
        Assert(!generic.Contains("node.test", StringComparison.OrdinalIgnoreCase), "URL is not exposed");
        Assert(!generic.Contains("TEST-ONLY", StringComparison.Ordinal), "secret marker is not exposed");
        var known = UiErrorMapper.ToUserMessage(new InvalidOperationException("BF-CONFIG-CACHE-MISSING"), "连接");
        Assert(known == "没有可用的已验证配置，请先完成设备激活", "known code maps to stable Chinese text");
        var tainted = UiErrorMapper.ToUserMessage(new InvalidOperationException("BF-CONFIG-CACHE-MISSING: " + secret), "连接");
        Assert(tainted == ErrorRegistry.Describe("BF-INTERNAL").MessageZh, "code with a suffix is generic");
        Assert(!tainted.Contains("node.test", StringComparison.OrdinalIgnoreCase), "tainted code does not expose URL");
        Assert(!tainted.Contains("TEST-ONLY", StringComparison.Ordinal), "tainted code does not expose secret");
    }

    private static void ValidateExternalResponse(string path, string route, long? expectedVersion = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new InvalidDataException("manifest path");
        var bytes = File.ReadAllBytes(path);
        try
        {
            using var strict = PipeClientProtocol.ParseStrict(bytes);
            var value = JsonNode.Parse(bytes)?.AsObject() ?? throw new InvalidDataException("manifest shape");
            ProtocolContract.ValidateResponse(route, value);
            if (expectedVersion is long version && value["config_version"]?.GetValue<long>() != version) throw new InvalidDataException("config version");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string SemanticContentDigest(string content)
    {
        var value = JsonNode.Parse(content)?.AsObject() ?? throw new InvalidDataException("config content");
        value.Remove("config_version"); value.Remove("anti_rollback"); value.Remove("generated_at");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(value)))).ToLowerInvariant();
    }

    private static void ConfigKeyTrustBehavior()
    {
        var rootSeed = RandomNumberGenerator.GetBytes(32);
        var v1Seed = RandomNumberGenerator.GetBytes(32);
        var v2Seed = RandomNumberGenerator.GetBytes(32);
        byte[]? rootPublic = null, v1Public = null, v2Public = null;
        try
        {
            _ = Ed25519.Sign(Array.Empty<byte>(), rootSeed, out rootPublic);
            _ = Ed25519.Sign(Array.Empty<byte>(), v1Seed, out v1Public);
            _ = Ed25519.Sign(Array.Empty<byte>(), v2Seed, out v2Public);
            var rootPem = Ed25519Pem(rootPublic);
            var rootFingerprint = Ed25519Fingerprint(rootPublic);
            var v1Pem = Ed25519Pem(v1Public);
            var v1Fingerprint = Ed25519Fingerprint(v1Public);
            var v2Pem = Ed25519Pem(v2Public);
            var v2Fingerprint = Ed25519Fingerprint(v2Public);

            JsonObject Trusted(string id, string pem, string fingerprint, long activation, long? retirement = null) => new()
            {
                ["key_id"] = id, ["public_key_pem"] = pem, ["fingerprint"] = fingerprint,
                ["activation_floor"] = activation, ["retirement_floor"] = retirement,
            };

            JsonObject SignState(long generation, string active, JsonArray trusted, string? previous)
            {
                var value = new JsonObject
                {
                    ["version"] = 1, ["purpose"] = "config-signing-key-state",
                    ["root_key_id"] = "bifrost-root-v1", ["root_fingerprint"] = rootFingerprint,
                    ["generation"] = generation, ["active_key_id"] = active,
                    ["trusted_keys"] = trusted, ["previous_state_digest"] = previous,
                };
                var bytes = Encoding.UTF8.GetBytes(ConfigKeyTrust.Canonical(value));
                byte[]? signature = null, signedPublic = null;
                try
                {
                    signature = Ed25519.Sign(bytes, rootSeed, out signedPublic);
                    Assert(signedPublic.AsSpan().SequenceEqual(rootPublic), "config trust root identity");
                    value["signature"] = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    return value;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                    if (signature is not null) CryptographicOperations.ZeroMemory(signature);
                    if (signedPublic is not null) CryptographicOperations.ZeroMemory(signedPublic);
                }
            }

            var firstState = SignState(1, "config-signing-v1", new JsonArray(Trusted("config-signing-v1", v1Pem, v1Fingerprint, 1)), null);
            var first = ConfigKeyTrust.Verify(firstState, "bifrost-root-v1", rootPem, rootFingerprint, currentConfigVersion: 1);
            Assert(first.Select("config-signing-v1", 1).KeyId == "config-signing-v1", "v1 active");

            var overlapState = SignState(2, "config-signing-v1", new JsonArray(
                Trusted("config-signing-v1", v1Pem, v1Fingerprint, 1),
                Trusted("config-signing-v2", v2Pem, v2Fingerprint, 20)), first.Digest);
            var overlap = ConfigKeyTrust.Verify(overlapState, "bifrost-root-v1", rootPem, rootFingerprint, first.Generation, first.Digest, 19);
            Assert(ExpectInvalidData(() => overlap.Select("config-signing-v2", 19)) == "BF-CONFIG-KEY-NOT-ACTIVE", "v2 activation floor");
            Assert(overlap.Select("config-signing-v2", 20).KeyId == "config-signing-v2", "v2 accepted after overlap");

            var activeV2State = SignState(3, "config-signing-v2", new JsonArray(
                Trusted("config-signing-v1", v1Pem, v1Fingerprint, 1, 40),
                Trusted("config-signing-v2", v2Pem, v2Fingerprint, 20)), overlap.Digest);
            var activeV2 = ConfigKeyTrust.Verify(activeV2State, "bifrost-root-v1", rootPem, rootFingerprint, overlap.Generation, overlap.Digest, 20);
            Assert(activeV2.ActiveKeyId == "config-signing-v2", "v2 active");
            Assert(ExpectInvalidData(() => activeV2.Select("config-signing-v1", 40)) == "BF-CONFIG-KEY-RETIRED", "v1 retired");
            Assert(ExpectInvalidData(() => activeV2.Select("config-signing-v3", 40)) == "BF-CONFIG-KEY-UNKNOWN", "unknown key rejected");

            // A device can legitimately miss multiple key-state generations
            // while offline. Generation 5 is independently signed by the
            // immutable compiled root, so it may advance monotonically even
            // though generation 4 was never observed locally.
            var skipped = SignState(5, "config-signing-v2", new JsonArray(Trusted("config-signing-v2", v2Pem, v2Fingerprint, 20)), "c".PadLeft(64, 'c'));
            var caughtUp = ConfigKeyTrust.Verify(skipped, "bifrost-root-v1", rootPem, rootFingerprint, activeV2.Generation, activeV2.Digest, 20);
            Assert(caughtUp.Generation == 5 && caughtUp.ActiveKeyId == "config-signing-v2", "skipped generation root-signed catch-up");

            var wrongContiguous = SignState(4, "config-signing-v2", new JsonArray(Trusted("config-signing-v2", v2Pem, v2Fingerprint, 20)), "b".PadLeft(64, 'b'));
            Assert(ExpectInvalidData(() => ConfigKeyTrust.Verify(wrongContiguous, "bifrost-root-v1", rootPem, rootFingerprint, activeV2.Generation, activeV2.Digest, 20)) == "BF-CONFIG-KEY-ROLLBACK", "contiguous chain mismatch rejected");
            var tampered = activeV2State.DeepClone().AsObject(); tampered["active_key_id"] = "config-signing-v1";
            Assert(ExpectInvalidData(() => ConfigKeyTrust.Verify(tampered, "bifrost-root-v1", rootPem, rootFingerprint)) == "BF-CONFIG-KEY-SIGNATURE", "tamper rejected");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootSeed); CryptographicOperations.ZeroMemory(v1Seed); CryptographicOperations.ZeroMemory(v2Seed);
            if (rootPublic is not null) CryptographicOperations.ZeroMemory(rootPublic);
            if (v1Public is not null) CryptographicOperations.ZeroMemory(v1Public);
            if (v2Public is not null) CryptographicOperations.ZeroMemory(v2Public);
        }
    }

    private static string ExpectInvalidData(Action action)
    {
        try { action(); } catch (InvalidDataException error) { return error.Message ?? string.Empty; }
        throw new InvalidOperationException("expected InvalidDataException");
    }

    private static string Ed25519Pem(byte[] rawPublic)
    {
        var der = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }.Concat(rawPublic).ToArray();
        try { return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(der) + "\n-----END PUBLIC KEY-----\n"; }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    private static string Ed25519Fingerprint(byte[] rawPublic)
    {
        var der = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }.Concat(rawPublic).ToArray();
        try { return Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    private static string Canonical(JsonNode? node) => node switch
    {
        null => "null",
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => JsonSerializer.Serialize(pair.Key) + ":" + Canonical(pair.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonical)) + "]",
        JsonValue value => value.ToJsonString(new JsonSerializerOptions { WriteIndented = false }),
        _ => node.ToJsonString()
    };

    private static void ErrorMappingNeverLeaksExceptionText()
    {
        const string secret = "https://node.test.invalid/uuid?token=TEST-ONLY";
        var generic = UiErrorMapper.ToUserMessage(new InvalidOperationException(secret), "激活");
        Assert(generic == "激活失败，请检查网络或稍后重试", "unknown error maps to stable action text");
        Assert(!generic.Contains("node.test", StringComparison.OrdinalIgnoreCase), "URL is not exposed");
        Assert(!generic.Contains("TEST-ONLY", StringComparison.Ordinal), "secret marker is not exposed");

        var known = UiErrorMapper.ToUserMessage(new InvalidOperationException("BF-CONFIG-CACHE-MISSING"), "连接");
        Assert(known == "没有可用的已验证配置，请先完成设备激活", "known code maps to stable Chinese text");
        Assert(!known.Contains("node.test", StringComparison.OrdinalIgnoreCase), "known error does not expose URL");

        var unconfigured = UiErrorMapper.ToUserMessage(new InvalidOperationException("BF-CONTROL-UNCONFIGURED"), "激活");
        Assert(unconfigured == "此测试构建未配置控制面", "unconfigured origin maps to generic Chinese text");

        var tainted = UiErrorMapper.ToUserMessage(new InvalidOperationException("BF-CONFIG-CACHE-MISSING: " + secret), "连接");
        Assert(tainted == "连接失败，请检查网络或稍后重试", "code with a suffix is generic");
        Assert(!tainted.Contains("node.test", StringComparison.OrdinalIgnoreCase), "tainted code does not expose URL");
        Assert(!tainted.Contains("TEST-ONLY", StringComparison.Ordinal), "tainted code does not expose secret");
    }

    private static void ProtocolVectorsAndGeneratedResponseBinding()
    {
        var vectorPath = Path.Combine(AppContext.BaseDirectory, "protocol-golden-vectors-v1.json");
        var root = JsonNode.Parse(File.ReadAllText(vectorPath, Encoding.UTF8))?.AsObject()
            ?? throw new InvalidOperationException("protocol vectors missing");
        var vectors = root["vectors"]?.AsArray() ?? throw new InvalidOperationException("protocol vectors malformed");
        var verified = false;
        foreach (var item in vectors)
        {
            var vector = item?.AsObject() ?? throw new InvalidOperationException("protocol vector item malformed");
            var canonical = vector["canonical_json"]?.GetValue<string>() ?? throw new InvalidOperationException("canonical bytes missing");
            var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            Assert(digest == vector["sha256"]?.GetValue<string>(), "shared vector digest");
            if (vector["schema"] is JsonValue schema && schema.GetValue<string>() != "SignedBytes" && canonical.Length > 0)
            {
                try { ProtocolContract.ValidateSchema(schema.GetValue<string>(), JsonNode.Parse(canonical)?.AsObject() ?? throw new InvalidDataException("vector is not object")); }
                catch (Exception error) { throw new InvalidDataException($"{vector["id"]}: {error.Message}", error); }
            }
            if (vector["signature_base64url"] is JsonValue signature && vector["public_key_raw_base64url"] is JsonValue publicKey)
            {
                var decode = (string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
                Assert(Ed25519.Verify(decode(signature.GetValue<string>()), Encoding.UTF8.GetBytes(canonical), decode(publicKey.GetValue<string>())), $"shared Ed25519 vector: {vector["id"]}");
                verified = true;
            }
        }
        Assert(verified, "shared signed vector present");
        foreach (var item in root["schema_vectors"]?.AsArray() ?? throw new InvalidOperationException("shared schema vectors missing"))
        {
            var vector = item!.AsObject();
            var value = JsonNode.Parse(vector["json"]!.GetValue<string>())!.AsObject();
            var accepted = vector["expected"]!.GetValue<string>() == "accept";
            var threw = false;
            try { ProtocolContract.ValidateSchema(vector["schema"]!.GetValue<string>(), value); }
            catch (InvalidDataException error) { threw = true; if (accepted) throw new InvalidDataException($"{vector["id"]}: {error.Message}", error); }
            Assert(accepted ? !threw : threw, $"shared schema vector: {vector["id"]}");
        }
        var signedBase = vectors.First(item => item?["id"]?.GetValue<string>() == "node-ack-signed-test-only")!.AsObject();
        var decodeBase64 = (string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        var signedMessage = Encoding.UTF8.GetBytes(signedBase["canonical_json"]!.GetValue<string>());
        var signedBytes = decodeBase64(signedBase["signature_base64url"]!.GetValue<string>());
        var signedPublic = decodeBase64(signedBase["public_key_raw_base64url"]!.GetValue<string>());
        Assert(Ed25519.Verify(signedBytes, signedMessage, signedPublic), "valid signed vector verifies");
        var alteredMessage = signedMessage.ToArray(); alteredMessage[^1] ^= 1; Assert(!Ed25519.Verify(signedBytes, alteredMessage, signedPublic), "tampered message rejected cryptographically");
        var alteredSignature = signedBytes.ToArray(); alteredSignature[0] ^= 1; Assert(!Ed25519.Verify(alteredSignature, signedMessage, signedPublic), "tampered signature rejected cryptographically");
        Assert(!Ed25519.Verify(signedBytes, signedMessage, new byte[32]), "wrong key rejected cryptographically");
        Assert(!Ed25519.Verify(signedBytes[..63], signedMessage, signedPublic), "truncated signature rejected cryptographically");
        foreach (var item in root["signature_vectors"]?.AsArray() ?? throw new InvalidOperationException("shared signature vectors missing"))
        {
            var vector = item!.AsObject();
            Assert(vector["schema"]?.GetValue<string>() == "NodeAckSignedBytes", "signature vector schema");
            Assert(vector["input_encoding"]?.GetValue<string>() == "canonical-utf8", "signature vector encoding");
            Assert(vector["expected_crypto_stage"]?.GetValue<string>() == "signature-verification", "signature vector crypto stage");
            var candidateMessage = signedMessage.ToArray();
            var candidateSignature = signedBytes.ToArray();
            var candidatePublic = signedPublic.ToArray();
            switch (vector["mutation"]?.GetValue<string>())
            {
                case "message-byte": candidateMessage[^1] ^= 1; break;
                case "signature-byte": candidateSignature[0] ^= 1; break;
                case "wrong-key": candidatePublic = new byte[32]; break;
                case "truncate-signature": candidateSignature = signedBytes[..63]; break;
                default: throw new InvalidDataException("unknown signature vector mutation");
            }
            Assert(!Ed25519.Verify(candidateSignature, candidateMessage, candidatePublic), $"signature vector rejected: {vector["id"]}");
        }
        var negatives = root["negative_vectors"]?.AsArray() ?? throw new InvalidOperationException("shared negatives missing");
        Assert(negatives.Count >= 8, "shared negative vectors present");
        foreach (var item in negatives)
        {
            var vector = item?.AsObject() ?? throw new InvalidOperationException("negative vector malformed");
            if (vector["raw_utf8_base64"] is JsonValue raw)
            {
                var rawBytes = Convert.FromBase64String(raw.GetValue<string>());
                var rawRejected = false;
                try
                {
                    using var parsed = PipeClientProtocol.ParseStrict(rawBytes);
                }
                catch (Exception error) when (error is JsonException or InvalidDataException or ArgumentException or FormatException)
                {
                    rawRejected = true;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(rawBytes);
                }
                Assert(rawRejected, $"shared raw negative vector rejected: {vector["id"]}");
            }
            if (vector["json"] is JsonValue json && vector["schema"] is JsonValue schema)
            {
                var text = json.GetValue<string>();
                if (vector["id"]?.GetValue<string>() == "oversize-string") text = text.Replace("<oversize>", new string('X', 5000), StringComparison.Ordinal);
                if (vector["id"]?.GetValue<string>() == "unicode-non-normalized")
                {
                    Assert(text.Contains("\\u0301", StringComparison.Ordinal), "unicode vector keeps original escape bytes");
                    continue;
                }
                var vectorRejected = false;
                try
                {
                    var value = JsonNode.Parse(text)?.AsObject() ?? throw new InvalidDataException("not object");
                    if (schema.GetValue<string>() != "SignedBytes") ProtocolContract.ValidateSchema(schema.GetValue<string>(), value);
                }
                catch (Exception error) when (error is JsonException or InvalidDataException or ArgumentException) { vectorRejected = true; }
                Assert(vectorRejected, $"shared negative vector rejected: {vector["id"]}");
            }
        }

        var valid = new JsonObject { ["config_version"] = 7, ["schema_version"] = "1.0", ["digest"] = new string('a', 64), ["rollback_floor"] = 7 };
        ProtocolContract.ValidateResponse("/v1/config/manifest", valid);
        var rejected = false;
        var invalid = valid.DeepClone().AsObject();
        invalid["unknown"] = true;
        try { ProtocolContract.ValidateResponse("/v1/config/manifest", invalid); }
        catch (InvalidDataException error) { rejected = error.Message == "BF-CONTRACT-SHAPE"; }
        Assert(rejected, "generated response binding rejects unknown field");
    }

    private static UiStateStore NewStore(string root, Func<byte[], byte[]>? protect = null, Func<byte[], byte[]>? unprotect = null, Func<string, bool>? delete = null) =>
        new(root, protect ?? IdentityProtect, unprotect ?? IdentityUnprotect, delete);

    private static JsonObject State(string source) => new()
    {
        ["mode"] = "smart", ["connection_type"] = "direct-vmess", ["route_mode"] = "smart",
        ["core"] = "auto", ["source"] = source, ["country"] = "default", ["front_source"] = "auto",
        ["candidate_mode"] = "auto", ["candidate_label"] = "", ["app_policy"] = "allow",
        ["app_policy_enabled"] = false, ["include_apps"] = "", ["exclude_apps"] = "", ["theme"] = "system", ["design_direction"] = "a",
    };

    private static void Reset(string root)
    {
        foreach (var path in Directory.EnumerateFiles(root)) File.Delete(path);
    }

    private static bool Delete(string path)
    {
        try { File.Delete(path); return !File.Exists(path); } catch { return false; }
    }

    private static string ExpectCode(Action action)
    {
        try { action(); }
        catch (InvalidOperationException error) { return error.Message ?? ""; }
        throw new InvalidOperationException("expected stable failure");
    }

    private static void SensitiveLifecycleBehavior()
    {
        var now = DateTimeOffset.UnixEpoch;
        var clipboard = new FakeSensitiveClipboard();
        var recovery = new SensitiveCodeController(clipboard, TimeSpan.FromMinutes(10));
        var pairing = new SensitiveCodeController(clipboard, TimeSpan.FromMinutes(10));

        Assert(recovery.Publish("TEST-ONLY-RECOVERY", now), "recovery publish");
        Assert(pairing.Publish("TEST-ONLY-PAIRING", now), "pairing publish");
        Assert(recovery.Reveal(now) == "TEST-ONLY-RECOVERY", "recovery reveal");
        Assert(pairing.Reveal(now) == "TEST-ONLY-PAIRING", "pairing reveal");

        Assert(recovery.Copy(now), "recovery copy");
        clipboard.Value = "user replacement";
        Assert(recovery.ClearClipboard(), "replacement is a safe no-op");
        Assert(clipboard.Value == "user replacement", "replacement preserved");

        Assert(recovery.Copy(now), "copy for read failure");
        clipboard.ReadSucceeds = false;
        Assert(!recovery.ClearClipboard(), "clipboard read failure visible");
        Assert(clipboard.Value == "TEST-ONLY-RECOVERY", "read failure retains ownership");
        clipboard.ReadSucceeds = true;
        clipboard.ClearSucceeds = false;
        Assert(!recovery.ClearClipboard(), "clipboard clear failure visible");
        Assert(clipboard.Value == "TEST-ONLY-RECOVERY", "clear failure retains value");
        clipboard.ClearSucceeds = true;
        Assert(recovery.ClearClipboard(), "clear retry succeeds");
        Assert(clipboard.Value is null, "clear retry removes owned value");

        clipboard.WriteSucceeds = false;
        Assert(!recovery.Copy(now), "copy failure visible");
        clipboard.WriteSucceeds = true;
        Assert(recovery.Copy(now), "next copy after replacement");
        Assert(clipboard.Value == "TEST-ONLY-RECOVERY", "next copy owns new value");

        var lease = new SensitiveClipboardLease(recovery);
        lease.Arm(now);
        Assert(lease.Expire(now.AddSeconds(29)), "clipboard remains armed before deadline");
        Assert(clipboard.Value == "TEST-ONLY-RECOVERY", "clipboard remains before deadline");
        Assert(lease.Expire(now.AddSeconds(30)), "clipboard expires at deadline");
        Assert(clipboard.Value is null, "clipboard cleared at deadline");

        Assert(recovery.Copy(now), "copy survives hiding the dialog value");
        lease.Arm(now);
        recovery.HideValue();
        Assert(recovery.Reveal(now) is null, "closing removes the revealed secret");
        Assert(clipboard.Value == "TEST-ONLY-RECOVERY", "explicit copy remains available after close");
        Assert(lease.Expire(now.AddSeconds(30)) && !lease.IsArmed, "hidden copy expires at its deadline");
        Assert(clipboard.Value is null, "hidden copy removed at deadline");
        Assert(recovery.Publish("TEST-ONLY-RECOVERY", now) && recovery.Copy(now), "first dialog copy");
        lease.Arm(now);
        Assert(recovery.Publish("TEST-ONLY-NEW-RECOVERY", now) && recovery.Copy(now), "new dialog copy");
        Assert(lease.Expire(now.AddSeconds(30)) && !lease.IsArmed, "old dialog deadline retires");
        Assert(clipboard.Value == "TEST-ONLY-NEW-RECOVERY", "old deadline preserves a new explicit copy");
        Assert(recovery.Publish("TEST-ONLY-RECOVERY", now), "restore value for remaining lifecycle checks");

        var reveal = new SensitiveRevealState();
        Assert(reveal.Reveal("TEST-ONLY-RECOVERY", now), "explicit reveal state");
        Assert(reveal.Read(now.AddSeconds(29)) == "TEST-ONLY-RECOVERY", "reveal visible before deadline");
        Assert(reveal.Read(now.AddSeconds(30)) is null, "reveal remasks at deadline");

        Assert(!recovery.Publish("bad\nvalue", now), "invalid publish rejected");
        Assert(recovery.Reveal(now) is null, "invalid publish clears old recovery");

        Assert(recovery.Publish("TEST-ONLY-RECOVERY-2", now), "recovery republish");
        Assert(pairing.Publish("TEST-ONLY-PAIRING-2", now), "pairing republish");
        Assert(recovery.Acknowledge(now), "recovery acknowledge");
        Assert(pairing.Reveal(now) == "TEST-ONLY-PAIRING-2", "pairing slot remains independent");
        Assert(recovery.Reveal(now) is null, "acknowledged recovery is cleared");

        clipboard.Value = null;
        Assert(pairing.Copy(now), "pairing copy");
        Assert(pairing.ClearClipboard(), "pairing clear");
        Assert(clipboard.Value is null, "pairing clipboard cleared");
        Assert(recovery.Reveal(now.AddMinutes(11)) is null, "expired recovery cannot reveal");
        Assert(!recovery.Copy(now.AddMinutes(11)), "expired recovery cannot copy");
    }

    private static void PresentationStateBehavior()
    {
        var idle = UiPresentationState.Idle();
        Assert(idle.State == UiConnectionState.Idle, "idle state is explicit");
        Assert(idle.Download == "—" && idle.Upload == "—" && idle.Duration == "—", "idle has no telemetry");
        var protectedState = UiPresentationState.TestProtected();
        Assert(protectedState.IsProtected && protectedState.IsTestState, "test protected state is explicit");
        Assert(protectedState.Samples.Length > 0, "test samples are deterministic");
        Assert(UiPresentationReducer.FromServiceStatus(new Bifrost.ClientService.ServiceStatus(false, false, "error", "BF-TEST", null, null, null, null, null, null)).State == UiConnectionState.Error, "service error reduces to error");
        Assert(UiPresentationReducer.FromServiceStatus(ServiceStatus.Reconnecting()).State == UiConnectionState.Reconnecting,
            "Service recovery is displayed as reconnecting instead of an IPC error or disconnected");
        var recoveringState = new UiShellState(Presentation: UiPresentationState.Reconnecting(), IsEnrolled: true);
        var recoveryPersistence = new CountingPersistence(recoveringState);
        using (var recovering = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Reconnecting()), recoveryPersistence, recoveringState))
        {
            Assert(recovering.CanUsePrimaryAction && recovering.PrimaryActionLabel == "取消重连", "Service recovery remains cancellable");
            recovering.ConnectAsync().GetAwaiter().GetResult();
            Assert(recovering.Presentation.State == UiConnectionState.Idle, "Cancel recovery disconnects instead of starting another connection");
            var healthStatus = ServiceStatus.Blocked("BF-RUNTIME-HEALTH", "BF-TRANSPORT-PROBE-TLS-TIMEOUT+BF-TRANSPORT-PROBE-HTTP");
            recovering.ApplyStatus(ServiceStatusProtocol.Parse(JsonSerializer.SerializeToElement(healthStatus)));
            Assert(recovering.LiveEvents[0].Status.Contains("BF-TRANSPORT-PROBE-TLS-TIMEOUT+BF-TRANSPORT-PROBE-HTTP"),
                "Runtime health activity preserves the bounded underlying probe causes");
            recovering.ApplyStatus(ServiceStatus.Blocked("BF-RUNTIME-HEALTH", "https://private.example/secret"));
            Assert(!recovering.LiveEvents[0].Status.Contains("private.example"), "Activity never renders arbitrary diagnostic payloads");
        }
        var unverified = new Bifrost.ClientService.ServiceStatus(true, true, "connected", null, null, "auto", "smart", "cfg_fixture", "A", null);
        Assert(!UiPresentationReducer.FromServiceStatus(unverified).IsProtected, "missing enforcement cannot forge protected state");
        var contradictory = new Bifrost.ClientService.ServiceStatus(true, true, "connected", null, null, "auto", "smart", "cfg_fixture", "A", new Bifrost.ClientService.EnforcementSummary("global", "none", 0, new string('f', 64), new string('a', 32), true));
        Assert(!UiPresentationReducer.FromServiceStatus(contradictory).IsProtected, "mismatched enforcement cannot forge protected state");
    }

    private static void UiShellViewModelBehavior()
    {
        var legacyTypedState = new UiShellState(
            Mode: ProtocolCodes.ModeSmart,
            ConnectionType: "",
            RouteMode: "",
            Source: "A",
            Country: "default",
            Presentation: UiPresentationState.Idle(),
            IsEnrolled: true);
        var legacyTypedPersistence = new InMemoryUiShellPersistence(legacyTypedState);
        using (var repaired = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), legacyTypedPersistence, legacyTypedState))
        {
            Assert(repaired.ConnectionType == "direct-vmess" && repaired.RouteMode == ProtocolCodes.ModeSmart,
                "empty persisted typed route is reconstructed from the presentation mode");
            Assert(legacyTypedPersistence.Load().ConnectionType == "direct-vmess" && legacyTypedPersistence.Load().RouteMode == ProtocolCodes.ModeSmart,
                "reconstructed typed route is persisted before the next Connect");
        }

        var initial = new UiShellState(
            Source: "A",
            Country: "default",
            Presentation: UiPresentationState.Idle(),
            IsEnrolled: true);
        var persistence = new InMemoryUiShellPersistence(initial);
        using var viewModel = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), persistence, initial);

        // Commands and immutable state are exercised without constructing any
        // WPF control or opening a service/control/update handle.
        viewModel.NavigateCommand.Execute("routing");
        viewModel.SetTheme("dark");
        viewModel.SetDesignDirection("b");
        viewModel.Mode = ProtocolCodes.ModeSmartGate;
        viewModel.AppPolicyEnabled = false;
        viewModel.IncludeApps = "malformed\nlegacy-value";
        Assert(viewModel.Page == "routing" && viewModel.Theme == "dark" && viewModel.DesignDirection == "b" && viewModel.Mode == ProtocolCodes.ModeSmartGate, "VM command/state routing");
        Assert(persistence.Load().Theme == "dark" && persistence.Load().DesignDirection == "b" && persistence.Load().Page == "routing", "VM preference persistence");
        viewModel.SetDesignDirection("unsupported");
        Assert(viewModel.DesignDirection == "a", "invalid visual direction falls back to the recommended product direction");

        // This command-routing fixture has no explicit SmartGate country.
        // Exercise ordinary connect here; country selection has its own fixture.
        viewModel.Mode = ProtocolCodes.ModeSmart;
        viewModel.SetPage("home");
        viewModel.ConnectAsync().GetAwaiter().GetResult();
        Assert(viewModel.IsProtected, $"fixture coordinator produces typed protected state: {viewModel.StatusText} / {viewModel.UpdateText}");

        viewModel.SetPresentation(UiPresentationState.Idle());
        viewModel.Source = "";
        viewModel.ConnectAsync().GetAwaiter().GetResult();
        Assert(viewModel.Source == "A", "primary connect retry rehydrates the signed catalogue and restores a safe source default");
        Assert(viewModel.IsProtected, "primary connect retry can recover from an empty transient UI selection without visiting the lines page first");
        Assert(viewModel.EnrollCommand is not null && viewModel.RecoverCommand is not null && viewModel.PairCommand is not null, "typed command routing exists");

        var failedProbeCoordinator = new ProbeCoordinator();
        using var failedProbeViewModel = new UiShellViewModel(failedProbeCoordinator,
            new InMemoryUiShellPersistence(initial), initial);
        failedProbeViewModel.StartAsync().GetAwaiter().GetResult();
        failedProbeViewModel.NavigateAsync("nodes").GetAwaiter().GetResult();
        WaitUntil(() => failedProbeCoordinator.Probes.Count == 1, "failed probe fixture did not start");
        failedProbeCoordinator.Fail(0, "BF-CANDIDATE-PROBE-FAILED");
        WaitUntil(() => !failedProbeViewModel.IsCandidateProbeRunning, "failed probe fixture did not reach a terminal state");
        Assert(failedProbeViewModel.CandidateRoutes.All(route => route.StatusKind == "unavailable"),
            "a zero-row terminal probe error renders every route as failed instead of waiting for a test");
    }

    private static void UiShellFunctionalControlsBehavior()
    {
        var initial = new UiShellState(
            Source: "A",
            Country: "default",
            CandidateMode: "auto",
            CandidateLabel: "",
            Presentation: UiPresentationState.Idle(),
            IsEnrolled: true);
        var coordinator = new ProbeCoordinator(updateResult: ReleaseCheckResult.UpToDate(42));
        var persistence = new InMemoryUiShellPersistence(initial);
        using var viewModel = new UiShellViewModel(coordinator, persistence, initial);

        // Startup exposes the cached signed catalogue without immediately
        // launching a heavyweight real-delay sweep. Opening Lines starts the
        // owned probe lifecycle on demand.
        viewModel.StartAsync().GetAwaiter().GetResult();
        Assert(viewModel.CandidateOptions.Count == 3 && viewModel.SourceRouteGroups.Single(group => group.Code == "A").CandidateCount == 3, "functional startup exposes every optimized node in source A and its count");
        Assert(coordinator.Probes.Count == 0, "startup does not spend the first interactive frame on a full real-delay sweep");
        viewModel.NavigateAsync("nodes").GetAwaiter().GetResult();
        WaitUntil(() => coordinator.Probes.Count >= 1, "opening Lines did not start candidate probe");
        coordinator.Complete(0, "A-01");
        WaitUntil(() => viewModel.EffectiveCandidateLabel.Contains("A-01", StringComparison.Ordinal), "auto candidate result did not repaint ViewModel");
        Assert(viewModel.IsAutoCandidateMode && viewModel.EffectiveCandidateLabel.Contains("A-01", StringComparison.Ordinal), "auto probe result is visible in route controls");
        viewModel.SetPage("home");
        var smartConnect = viewModel.ConnectAsync();
        WaitUntil(() => coordinator.Probes.Count >= 2 || coordinator.ConnectAttempts.Count >= 1,
            "smart connect neither staged the provider nor started a legacy measurement");
        var startedLegacyMeasurement = coordinator.Probes.Count >= 2;
        if (startedLegacyMeasurement) coordinator.Complete(1, "A-01");
        smartConnect.GetAwaiter().GetResult();
        Assert(!startedLegacyMeasurement && coordinator.Probes.Count == 1, "smart connect does not run a second pre-connect sweep; Mihomo owns selection");
        Assert(coordinator.ConnectAttempts.SequenceEqual(new[] { "A-01" }), "smart connect stages one provider-backed runtime");
        Assert(coordinator.LastPreparedState is { CandidateMode: "manual", CandidateLabel: "A-01" }, "placeholder candidate supplies signed stage authority only");
        Assert(coordinator.DisconnectCalls == 0 && viewModel.IsProtected, "one provider-backed start reaches protected state without TUN restart cleanup");
        Assert(viewModel.IsAutoCandidateMode && string.IsNullOrEmpty(viewModel.CandidateLabel), "Mihomo automatic selection never converts persisted mode to manual");
        viewModel.SetPresentation(UiPresentationState.Idle());
        viewModel.SetPage("nodes");
        Assert(viewModel.CandidateRoutes.Select(route => route.Code).SequenceEqual(new[] { "A-01", "A-02", "A-03" }) && viewModel.CandidateRoutes.All(route => route.LatencyText.EndsWith(" ms", StringComparison.Ordinal)), "manual route details expose every A optimized node with an independent real latency value");

        viewModel.CandidateMode = "manual";
        Assert(!viewModel.CanConnect, "manual mode without a signed candidate disables Connect");
        Assert(viewModel.CanUsePrimaryAction, "primary dial stays clickable so an invalid/unfinished selection cannot become a silent dead surface");

        // The candidate-row Button executes this command in production XAML.
        viewModel.SelectCandidateCommand.Execute("A-01");
        WaitUntil(() => viewModel.IsManualCandidateMode && viewModel.CandidateLabel == "A-01", "candidate command did not persist manual selection");
        Assert(persistence.Load().CandidateMode == "manual" && persistence.Load().CandidateLabel == "A-01", "candidate click persists manual selection");
        Assert(viewModel.CanConnect, "signed manual candidate restores Connect readiness");

        // Changing the source refreshes the visible manual catalogue and
        // cannot retain a candidate owned by the previous source.
        viewModel.Source = "B";
        Assert(viewModel.CandidateOptions.Select(option => option.Code).SequenceEqual(new[] { "B-01", "B-02", "B-03" }) && viewModel.SourceRouteGroups.Single(group => group.Code == "B").CandidateCount == 3, "manual selector lists every optimized node in source B and its count");
        Assert(viewModel.IsManualCandidateMode && string.IsNullOrEmpty(viewModel.CandidateLabel), "source change clears an incompatible manual candidate");
        Assert(!viewModel.CanConnect, "source-scoped manual mode requires a new listed candidate");
        viewModel.SelectCandidateCommand.Execute("B-03");
        Assert(viewModel.CandidateLabel == "B-03" && viewModel.CanConnect, "any B optimized node can be selected directly from the signed list");

        // SmartGate keeps the customer's explicit transport choice, but the
        // SmartGate egress itself must be selected by the customer.
        viewModel.Mode = ProtocolCodes.ModeSmartGate;
        Assert(viewModel.CandidateMode == "auto" && string.IsNullOrEmpty(viewModel.CandidateLabel), "SmartGate remains a separate country-exit contract and uses source-scoped automatic access selection");
        Assert(viewModel.ConnectionType == "smartgate", "SmartGate button selects typed connection contract");
        Assert(viewModel.IsSmartGateMode && !viewModel.IsSmartMode && !viewModel.IsGlobalMode, "SmartGate exposes a distinct mode panel state");
        Assert(!viewModel.HasSelectedSmartGateNode && !viewModel.CanConnect && !viewModel.CanUseSmartGateAction, "SmartGate blocks until the customer explicitly selects a published node");

        viewModel.AppPolicyEnabled = true;
        Assert(!viewModel.AppPolicyEnabled && !viewModel.CanConnect, "SmartGate stays a pure smartgate route and remains blocked without a customer-selected node");
        viewModel.Mode = ProtocolCodes.ModeSmart;
        Assert(viewModel.IsSmartMode && !viewModel.IsSmartGateMode, "smart routing exposes its own panel state");
        viewModel.AppPolicyEnabled = true;
        Assert(!viewModel.CanConnect, "enabled application routing with an empty list disables Connect");
        Assert(viewModel.CanUsePrimaryAction, "primary dial remains actionable while application-policy validation is incomplete");
        viewModel.IncludeApps = "chrome.exe";
        Assert(viewModel.CanConnect, "valid allow-list restores Connect readiness");

        // Allow/exclude are mutually exclusive in the UI state as well as in
        // the compiler. Switching mode clears the now-inactive list.
        viewModel.AppPolicy = "exclude";
        Assert(string.IsNullOrEmpty(viewModel.IncludeApps), "exclude mode clears inactive allow-list text");
        Assert(!viewModel.CanConnect, "exclude mode waits for an exclude-list before Connect");
        viewModel.ExcludeApps = "telegram.exe";
        Assert(viewModel.CanConnect, "valid exclude-list restores Connect readiness");
        viewModel.AppPolicy = "allow";
        Assert(string.IsNullOrEmpty(viewModel.ExcludeApps), "allow mode clears inactive exclude-list text");

        // The dedicated settings button must call the real release updater,
        // not reuse config refresh or only change its label.
        viewModel.CheckProgramUpdateAsync().GetAwaiter().GetResult();
        Assert(coordinator.UpdateChecks == 1, "program-update button invokes release updater exactly once");
        Assert(viewModel.UpdateStatusMessage.Contains("42", StringComparison.Ordinal), "program-update result is surfaced through the settings UI binding");
        Assert(viewModel.UpdateStatusTitle == "已是最新版本" && viewModel.UpdateStatusKind == "current", "up-to-date result has an explicit successful terminal UI state");
        Assert(viewModel.UpdateProgress == 100 && !viewModel.IsUpdateChecking && viewModel.UpdateActionLabel == "检查软件更新", "program-update progress reaches 100 and restores the action after completion");

        // A protected connection freezes route/core/policy editing, while the
        // same primary control remains available as Disconnect even if the
        // mutable catalogue later becomes unavailable.
        viewModel.SetPresentation(UiPresentationState.TestProtected());
        Assert(!viewModel.CanEditConnectionSettings, "protected connection locks mutable connection controls");
        Assert(viewModel.CanConnect, "protected connection always keeps disconnect action enabled");
        Assert(viewModel.CanUsePrimaryAction, "protected connection keeps the primary disconnect action enabled");

        var directInitial = initial with { CandidateMode = "auto", CandidateLabel = "", Presentation = UiPresentationState.Idle() };
        var directCoordinator = new ProbeCoordinator();
        using var directVm = new UiShellViewModel(directCoordinator, new InMemoryUiShellPersistence(directInitial), directInitial);
        directVm.StartAsync().GetAwaiter().GetResult();
        Assert(directCoordinator.Probes.Count == 0, "direct-use startup stays free of an eager latency sweep");
        directVm.NavigateAsync("nodes").GetAwaiter().GetResult();
        WaitUntil(() => directCoordinator.Probes.Count == 1, "direct-use fixture did not start the source detail probe");
        directCoordinator.Complete(0, "A-01");
        WaitUntil(() => directVm.CandidateRoutes.Any(route => route.Code == "A-02" && route.CanUse), "second signed route never became directly usable");
        directVm.UseCandidateCommand.Execute("A-02");
        WaitUntil(() => directVm.IsProtected, "use-and-connect route action did not establish a protected session");
        Assert(directVm.CandidateMode == "manual" && directVm.CandidateLabel == "A-02", "use-and-connect persists the exact selected candidate");
    }

    private static void StartupEnrollmentResumeBehavior()
    {
        var initial = new UiShellState(Presentation: UiPresentationState.Idle(), IsEnrolled: false);

        // Cover both the current pending marker and an older interrupted
        // enrollment which retained its device key without that marker.
        foreach (var pendingEnrollment in new[] { true, false })
        {
            var coordinator = new ProbeCoordinator(
                enrolled: false,
                pendingEnrollment: pendingEnrollment,
                resumeOnRefresh: true);
            using var viewModel = new UiShellViewModel(coordinator, new InMemoryUiShellPersistence(initial), initial);

            viewModel.StartAsync().GetAwaiter().GetResult();
            WaitUntil(() => viewModel.IsEnrolled, "startup did not resume interrupted enrollment");

            Assert(coordinator.RefreshCalls == 1, "startup must make exactly one enrollment resume attempt");
            Assert(viewModel.DeviceRegistrationStatus == "已激活", "resumed startup must expose the fully activated state");
        }

        using var retryScheduler = new ManualStartupRetryScheduler();
        var transientCoordinator = new ProbeCoordinator(
            enrolled: false,
            pendingEnrollment: true,
            resumeOnRefresh: true,
            refreshFailuresBeforeSuccess: 1);
        using var transientViewModel = new UiShellViewModel(
            transientCoordinator,
            new InMemoryUiShellPersistence(initial),
            initial,
            probeLifecycle: null,
            dispatcher: null,
            startupRetryScheduler: retryScheduler);

        transientViewModel.StartAsync().GetAwaiter().GetResult();
        WaitUntil(() => transientCoordinator.RefreshCalls == 1, "startup did not make the initial enrollment resume attempt");
        Assert(!transientViewModel.IsEnrolled && retryScheduler.PendingCount == 1, "transient startup failure must schedule a retry without claiming activation");
        Assert(retryScheduler.LastDelay == TimeSpan.FromSeconds(2), "first activation resume retry uses the bounded backoff schedule");

        retryScheduler.ReleaseNext();
        WaitUntil(() => transientViewModel.IsEnrolled, "startup did not automatically retry interrupted enrollment after a transient failure");
        Assert(transientCoordinator.RefreshCalls == 2, "startup retries enrollment exactly once after the simulated network recovery");
        Assert(transientViewModel.DeviceRegistrationStatus == "已激活", "retry success must expose the fully activated state");

        using var rejectedScheduler = new ManualStartupRetryScheduler();
        var rejectedCoordinator = new ProbeCoordinator(enrolled: false, pendingEnrollment: true);
        using var rejectedViewModel = new UiShellViewModel(
            rejectedCoordinator,
            new InMemoryUiShellPersistence(initial),
            initial,
            probeLifecycle: null,
            dispatcher: null,
            startupRetryScheduler: rejectedScheduler);

        rejectedViewModel.StartAsync().GetAwaiter().GetResult();
        WaitUntil(() => rejectedCoordinator.RefreshCalls == 1, "startup did not check whether the retained identity was registered");
        Assert(rejectedScheduler.PendingCount == 0, "an explicit not-registered result must stop automatic activation retries");
        Assert(!rejectedViewModel.IsEnrolled, "an explicit not-registered result must keep activation required");
    }

    private static int ProgramUpdateLoopBehavior()
    {
        try
        {
            var initial = new UiShellState(Presentation: UiPresentationState.Idle(), IsEnrolled: true);
            var coordinator = new ProbeCoordinator(updateResult: new ReleaseCheckResult("up-to-date", 42, "TEST-ONLY current", null));
            var dispatcher = new PumpedUiDispatcher();
            var scheduler = new ManualProgramUpdateScheduler();
            using var viewModel = new UiShellViewModel(
                coordinator,
                new InMemoryUiShellPersistence(initial),
                initial,
                probeLifecycle: null,
                dispatcher: dispatcher,
                startupRetryScheduler: new SystemStartupRetryScheduler(),
                programUpdateScheduler: scheduler);

            var updateNotifications = 0;
            viewModel.PropertyChanged += (_, change) =>
            {
                if (change.PropertyName is not (nameof(UiShellViewModel.IsUpdateChecking) or nameof(UiShellViewModel.UpdateActionLabel))) return;
                Assert(dispatcher.CheckAccess, "automatic update completion notification left the UI dispatcher");
                updateNotifications++;
            };

            viewModel.StartAsync().GetAwaiter().GetResult();
            WaitUntil(() => scheduler.PendingCount == 1, "automatic update startup delay was not scheduled");
            scheduler.ReleaseNext();
            WaitUntil(() => coordinator.UpdateChecks == 1, "first automatic update check did not run");
            WaitUntil(() => scheduler.PendingCount == 1, "automatic update loop stopped after its first check");
            dispatcher.Drain();

            scheduler.ReleaseNext();
            WaitUntil(() => coordinator.UpdateChecks == 2, "second automatic update check did not run");
            WaitUntil(() => scheduler.PendingCount == 1, "automatic update loop did not schedule its next interval");
            dispatcher.Drain();

            // A successful automatic up-to-date result now clears any stale
            // foreground failure before the operation-complete notification,
            // so each check publishes the two status properties once from
            // SetUpdateFeedback and once from NotifyUpdateOperationChanged.
            Assert(updateNotifications == 8, "each automatic check clears stale status and publishes completion properties on the UI dispatcher");
            Assert(viewModel.UpdateStatusKind == "current" &&
                   viewModel.UpdateStatusMessage.Contains("发布序列 42", StringComparison.Ordinal),
                "automatic success must replace a stale update failure with the current signed release status");
            Assert(dispatcher.OffThreadExecutions == 0, "queued UI work executed outside the UI dispatcher");

            var stagedCoordinator = new ProbeCoordinator(updateResult: new ReleaseCheckResult("staged", 43, "TEST-ONLY staged", null));
            var stagedDispatcher = new PumpedUiDispatcher();
            var stagedScheduler = new ManualProgramUpdateScheduler();
            using var stagedViewModel = new UiShellViewModel(
                stagedCoordinator,
                new InMemoryUiShellPersistence(initial),
                initial,
                probeLifecycle: null,
                dispatcher: stagedDispatcher,
                startupRetryScheduler: new SystemStartupRetryScheduler(),
                programUpdateScheduler: stagedScheduler);
            long scheduledSequence = 0;
            long promptedSequence = 0;
            stagedViewModel.ProgramUpdateScheduled += sequence => scheduledSequence = sequence;
            stagedViewModel.ProgramUpdateAvailable += sequence => promptedSequence = sequence;
            stagedViewModel.StartAsync().GetAwaiter().GetResult();
            WaitUntil(() => stagedScheduler.PendingCount == 1, "staged automatic update startup delay was not scheduled");
            stagedScheduler.ReleaseNext();
            WaitUntil(() => stagedCoordinator.UpdateChecks == 1, "staged automatic update check did not run");
            WaitUntil(() => stagedScheduler.PendingCount == 1, "staged automatic update loop did not remain alive");
            stagedDispatcher.Drain();
            Assert(stagedCoordinator.UpdateApplies == 0, "automatic discovery must notify instead of silently applying a staged release");
            Assert(promptedSequence == 43, "verified discovery must produce a foreground notification");
            Assert(stagedViewModel.UpdateStatusKind == "available" &&
                   stagedViewModel.UpdateStatusTitle.Contains("及时更新", StringComparison.Ordinal) &&
                   stagedViewModel.UpdateActionLabel == "更新软件",
                "automatic staged release exposes a timely visible update reminder");

            stagedViewModel.CheckProgramUpdateAsync().GetAwaiter().GetResult();
            stagedDispatcher.Drain();
            Assert(stagedCoordinator.UpdateApplies == 1, "explicit update action applies the staged release exactly once");
            Assert(scheduledSequence == 43, "update restart monitor is correlated to the exact release sequence");
            Assert(stagedViewModel.UpdateStatusMessage.Contains("自动重启", StringComparison.Ordinal),
                "manual update reports that successful installation will restart automatically");

            Console.WriteLine("PROGRAM-UPDATE-LOOP PASS checks=2 ui_notifications=8 staged_reminder=true explicit_apply=true loop_alive=true");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"PROGRAM-UPDATE-LOOP FAIL {error}");
            return 1;
        }
    }

    private sealed class ManualProgramUpdateScheduler : IProgramUpdateScheduler
    {
        private readonly object _gate = new();
        private readonly Queue<TaskCompletionSource<object?>> _pending = new();
        public int PendingCount { get { lock (_gate) return _pending.Count; } }

        public Task DelayAsync(TimeSpan _, CancellationToken cancellationToken)
        {
            var completion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate) _pending.Enqueue(completion);
            cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
            return completion.Task;
        }

        public void ReleaseNext()
        {
            TaskCompletionSource<object?> completion;
            lock (_gate) completion = _pending.Dequeue();
            completion.TrySetResult(null);
        }
    }

    private sealed class PumpedUiDispatcher : IUiStateDispatcher
    {
        private readonly int _ownerThread = Environment.CurrentManagedThreadId;
        private readonly object _gate = new();
        private readonly Queue<Action> _pending = new();
        public bool CheckAccess => Environment.CurrentManagedThreadId == _ownerThread;
        public int OffThreadExecutions { get; private set; }

        public void Post(Action action)
        {
            if (CheckAccess)
            {
                action();
                return;
            }
            lock (_gate) _pending.Enqueue(action);
        }

        public void Drain()
        {
            Assert(CheckAccess, "test UI queue must be drained by its owner");
            while (true)
            {
                Action? action;
                lock (_gate) action = _pending.Count == 0 ? null : _pending.Dequeue();
                if (action is null) return;
                if (!CheckAccess) OffThreadExecutions++;
                action();
            }
        }
    }

    private sealed class ManualStartupRetryScheduler : IStartupRetryScheduler, IDisposable
    {
        private readonly Queue<TaskCompletionSource<object?>> _pending = new();
        public int PendingCount { get { lock (_pending) return _pending.Count; } }
        public TimeSpan LastDelay { get; private set; }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            LastDelay = delay;
            var completion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_pending) _pending.Enqueue(completion);
            cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
            return completion.Task;
        }

        public void ReleaseNext()
        {
            TaskCompletionSource<object?> completion;
            lock (_pending) completion = _pending.Dequeue();
            completion.TrySetResult(null);
        }

        public void Dispose()
        {
            TaskCompletionSource<object?>[] pending;
            lock (_pending) { pending = _pending.ToArray(); _pending.Clear(); }
            foreach (var completion in pending) completion.TrySetCanceled();
        }
    }

    private static void UiShellPersistenceFailureBehavior()
    {
        var initial = new UiShellState(Source: "A", Presentation: UiPresentationState.Idle(), IsEnrolled: true);
        using var loadVm = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), new ThrowingPersistence(throwOnLoad: true), initial: null);
        Assert(loadVm.UpdateText.Contains("安全存储不可用", StringComparison.Ordinal), "load failure uses safe Chinese default");

        var persistence = new ThrowingPersistence(state: initial, throwOnSave: true);
        using var saveVm = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), persistence, initial);
        saveVm.Theme = "dark";
        Assert(saveVm.Theme == "dark", "theme remains usable when best-effort persistence is unavailable");
        saveVm.DesignDirection = "c";
        Assert(saveVm.DesignDirection == "c", "visual direction remains usable when best-effort persistence is unavailable");
        saveVm.Source = "B";
        Assert(saveVm.Source == "A" && saveVm.UpdateText.Contains("安全存储", StringComparison.Ordinal), "security-relevant saved choices roll back on persistence failure");
    }

    private static void OriginConfigurationBehavior(bool expectedConfigured)
    {
        Assert(BifrostProductConfiguration.IsControlPlaneConfigured == expectedConfigured, "build-time control origin configuration");
        Assert(TrustedControlOrigin.TryParse("https://control.example.invalid", out var origin) && origin?.Value == "https://control.example.invalid", "reserved test origin accepted");
        foreach (var invalid in new[]
        {
            "http://control.example.invalid", "https://control.example.invalid:444", "https://control.example.invalid/path",
            "https://user:pass@control.example.invalid", "https://control.example.invalid/?q=1", "https://127.0.0.1", "https://[::1]",
            "https://localhost", "https://control.localhost", "https://nested.control.localhost",
            "https://CONTROL.example.invalid", "https://control。example.invalid", "not-an-origin"
        }) Assert(!TrustedControlOrigin.TryParse(invalid, out _), $"origin rejected: {invalid}");
        if (expectedConfigured) Assert(TrustedControlOrigin.Compiled?.Value == "https://control.example.invalid", "compiled origin is immutable");
        if (!expectedConfigured)
        {
            using var client = new BifrostControlClient();
            Assert(client.ConfigurationStatus == "BF-CONTROL-UNCONFIGURED" && !client.IsEnrolled, "unconfigured build is fail-closed before enrollment");
            try { client.EnrollAsync("TEST-ONLY").GetAwaiter().GetResult(); throw new InvalidOperationException("unconfigured enrollment unexpectedly proceeded"); }
            catch (InvalidOperationException error) { Assert(error.Message == "BF-CONTROL-UNCONFIGURED", "unconfigured enrollment uses stable redacted code"); }
        }
    }

    private static void WindowsAvailabilityClassifierBehavior()
    {
        Assert(BifrostWindowsAvailabilityClassifier.CanUseOffline(new HttpRequestException("TEST-ONLY transport")), "statusless transport failure is classified as unavailable");
        Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new InvalidOperationException("BF-CONTROL-HTTP")), "generic HTTP is not an offline proof");
        foreach (var code in new[] { "BF-CONTROL-401", "BF-CONTROL-403", "BF-CONTROL-410", "BF-CONTROL-JSON", "BF-CONFIG-SIGNATURE", "BF-AUTH-REVOKED" })
            Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new InvalidOperationException(code)), $"security error blocks offline fallback: {code}");
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Gone })
            Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new HttpRequestException("TEST-ONLY status", null, status)), $"HTTP {status} blocks offline fallback");
        foreach (var status in new[] { HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable, HttpStatusCode.GatewayTimeout })
        {
            Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new HttpRequestException("TEST-ONLY untyped status", null, status)), $"HTTP {status} requires the production typed status boundary");
            Assert(BifrostWindowsAvailabilityClassifier.CanUseOffline(new BifrostWindowsRetryableStatusException((int)status)), $"HTTP {status} permits only explicit offline policy");
        }
        Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new InvalidOperationException("BF-CONTROL-DEADLINE")), "untyped local deadline marker cannot authorize offline fallback");
        Assert(BifrostWindowsAvailabilityClassifier.CanUseOffline(new TaskCanceledException("TEST-ONLY deadline")), "internal deadline is unavailable");
        using (var caller = new CancellationTokenSource())
        {
            caller.Cancel();
            Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new TaskCanceledException("TEST-ONLY caller cancel"), caller.Token), "caller cancellation blocks offline fallback");
        }
        Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new AuthenticationException("TEST-ONLY TLS")), "TLS authentication failure blocks offline fallback");
        Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new CryptographicException("TEST-ONLY crypto")), "crypto failure blocks offline fallback");
        Assert(!BifrostWindowsAvailabilityClassifier.CanUseOffline(new HttpRequestException("TEST-ONLY wrapped", new InvalidDataException("BF-CONFIG-SIGNATURE"))), "wrapped security failure wins over transport allow");
    }

    private static void WindowsGatewayContentTypeOrderingBehavior()
    {
        var parser = typeof(BifrostControlClient).GetMethod("ParseStrictJsonObject", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        JsonObject Parse(string text, bool package = false, bool stored = false) =>
            (JsonObject)parser.Invoke(null, new object[] { Encoding.UTF8.GetBytes(text), package, stored })!;
        var large = new string('A', 128 * 1024);
        Assert(Parse("{\"config_package\":{\"ciphertext\":\"" + large + "\"}}", package: true)["config_package"]!["ciphertext"]!.GetValue<string>().Length == large.Length,
            "large encrypted node packages retain the decoded package budget");
        Assert(Parse("{\"ConfigJson\":\"" + large + "\"}", stored: true)["ConfigJson"]!.GetValue<string>().Length == large.Length,
            "stored configuration survives expansion beyond ordinary JSON strings");
        foreach (var text in new[] { "{\"message\":\"" + large + "\"}", "{\"ciphertext\":\"AA\",\"ciphertext\":\"BB\"}", "{\"ciphertext\":\"" + new string('A', 700000) + "\"}" })
        {
            try { Parse(text, package: true); throw new InvalidOperationException("fixture assertion failed: invalid package string accepted"); }
            catch (System.Reflection.TargetInvocationException error) when (error.InnerException is InvalidDataException inner && inner.Message == "BF-CONTROL-JSON") { }
        }
        foreach (var gatewayStatus in new[] { 502, 503, 504, 530 })
        using (var gateway = new HttpResponseMessage((HttpStatusCode)gatewayStatus)
        {
            Content = new StringContent("bad gateway", Encoding.UTF8, "text/plain")
        })
        {
            try
            {
                _ = BifrostControlClient.ReadJsonForHarnessAsync(gateway).GetAwaiter().GetResult();
                throw new InvalidOperationException("fixture assertion failed: gateway text/plain unexpectedly parsed");
            }
            catch (BifrostWindowsRetryableStatusException error)
            {
                Assert(error.Status == gatewayStatus, "unavailable gateway maps to its status before content-type validation");
                Assert(BifrostWindowsAvailabilityClassifier.CanUseOffline(error), "a previously verified offline configuration survives gateway outage");
            }
        }

        using (var healthyWrongType = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not json", Encoding.UTF8, "text/plain")
        })
        {
            try
            {
                _ = BifrostControlClient.ReadJsonForHarnessAsync(healthyWrongType).GetAwaiter().GetResult();
                throw new InvalidOperationException("fixture assertion failed: 200 text/plain unexpectedly parsed");
            }
            catch (InvalidDataException error)
            {
                Assert(error.Message == "BF-CONTROL-CONTENT-TYPE", "successful non-JSON response remains fail-closed");
            }
        }
    }

    private static void WindowsProductionRefreshBoundaryBehavior()
    {
        var root = Path.Combine(Path.GetTempPath(), $"bifrost-refresh-boundary-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var stateFile = Path.Combine(root, "state.bin");
        var config = new JsonObject
        {
            ["schema_version"] = "1.0",
            ["config_version"] = 1,
            ["anti_rollback"] = 1,
            ["account"] = new JsonObject { ["public_id"] = "BF-AB12-CD34", ["plan"] = "permanent", ["expires_at"] = null },
            ["sources"] = new JsonArray(new JsonObject
            {
                ["code"] = "A",
                ["display_name"] = "TEST-ONLY source A",
                ["server_name"] = "source-a.example.invalid",
                ["candidates"] = new JsonArray(new JsonObject { ["label"] = "A-01", ["dial_address"] = "192.0.2.10", ["port"] = 443 }),
                ["profiles"] = new JsonObject { ["direct"] = new JsonObject { ["profile_id"] = "TEST-ONLY-profile", ["uuid"] = "00000000-0000-4000-8000-000000000001" }, ["countries"] = new JsonObject() },
            }),
            ["countries"] = new JsonArray(),
            ["routing"] = new JsonObject { ["ruleset_version"] = "TEST-ONLY", ["smart_gate_remote_dns"] = true, ["kill_switch_default"] = "normal", ["dns_policy"] = new JsonObject { ["version"] = "dns-policy-v1", ["remote"] = "https://resolver.example.invalid/dns-query", ["direct"] = "https://direct.example.invalid/dns-query", ["smart_gate_remote"] = true, ["plaintext_fallback"] = false, ["ipv4"] = "proxy", ["ipv6"] = "proxy", ["failure"] = "block" }, ["ipv6_policy"] = "proxy_or_block", ["udp_policy"] = "capability" },
            ["core_policy"] = new JsonObject { ["allowed"] = new JsonArray("mihomo"), ["default"] = "mihomo" },
        }.ToJsonString();
        try
        {
            foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.Gone })
            {
                BifrostControlClient.SeedLifecycleRefreshStateForTest(stateFile, 1, config);
                using var client = BifrostControlClient.CreateLifecycleRefreshClient(stateFile, "http://127.0.0.1:18182", new StatusBodyTimeoutHandler(status));
                try
                {
                    client.RefreshAsync().GetAwaiter().GetResult();
                    throw new InvalidDataException("reachable rejection was accepted");
                }
                catch (BifrostWindowsReachableStatusException error)
                {
                    Assert(error.Status == (int)status && !error.Message.StartsWith("offline:", StringComparison.Ordinal), $"HTTP {status} body timeout remains blocked");
                }
            }

            foreach (var status in new[] { HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable, HttpStatusCode.GatewayTimeout })
            {
                BifrostControlClient.SeedLifecycleRefreshStateForTest(stateFile, 1, config);
                using var client = BifrostControlClient.CreateLifecycleRefreshClient(stateFile, "http://127.0.0.1:18182", new StatusBodyTimeoutHandler(status));
                var result = client.RefreshAsync().GetAwaiter().GetResult();
                Assert(result.Ok && result.Message.StartsWith("offline:", StringComparison.Ordinal) && result.ConfigVersion == 1, $"HTTP {status} uses typed retryable status and LKG gate");
            }

            BifrostControlClient.SeedLifecycleRefreshStateForTest(stateFile, 1, config);
            using (var client = BifrostControlClient.CreateLifecycleRefreshClient(
                stateFile,
                "http://127.0.0.1:18182",
                new StatusBodyTimeoutHandler(HttpStatusCode.ServiceUnavailable, () => BifrostControlClient.ReplaceLifecycleContentForTest(stateFile, config.Replace("TEST-ONLY source A", "TEST-ONLY source B", StringComparison.Ordinal)))))
            {
                try
                {
                    client.RefreshAsync().GetAwaiter().GetResult();
                    throw new InvalidDataException("mutated LKG was accepted");
                }
                catch (InvalidDataException error)
                {
                    Assert(error.Message == "BF-CONFIG-LKG", "content digest mutation blocks offline fallback");
                }
            }
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static void DynamicOptionPersistenceBehavior()
    {
        var validPersistence = new CountingPersistence(new UiShellState(Source: "B", Presentation: UiPresentationState.Idle(), IsEnrolled: true));
        using (var validVm = new UiShellViewModel(new ProbeCoordinator(), validPersistence, validPersistence.Load()))
        {
            validVm.RefreshAsync().GetAwaiter().GetResult();
            Assert(validVm.Source == "B" && validPersistence.Load().Source == "B", "refresh preserves a valid persisted source");
            Assert(validPersistence.SaveCalls == 0, "option repopulation does not perform a false save");
            validVm.Source = "A";
            Assert(validPersistence.SaveCalls == 1 && validPersistence.Load().Source == "A", "a real selection is saved exactly once");
            validVm.CandidateMode = "manual";
            validVm.CandidateLabel = "A-01";
            Assert(validPersistence.Load().CandidateMode == "manual" && validPersistence.Load().CandidateLabel == "A-01", "manual candidate is protected and source-scoped");
            validVm.CandidateMode = "auto";
            Assert(validPersistence.Load().CandidateLabel == "", "auto mode clears manual label");
        }

        var invalidPersistence = new CountingPersistence(new UiShellState(Source: "stale-choice", Presentation: UiPresentationState.Idle(), IsEnrolled: true));
        using (var invalidVm = new UiShellViewModel(new ProbeCoordinator(), invalidPersistence, invalidPersistence.Load()))
        {
            invalidVm.RefreshAsync().GetAwaiter().GetResult();
            Assert(invalidVm.Source == "A" && invalidPersistence.Load().Source == "A", "an invalid persisted choice falls back to the first signed source");
            Assert(invalidPersistence.SaveCalls == 1, "signed-source fallback is one atomic save");
        }

        var smartGatePersistence = new CountingPersistence(new UiShellState(Mode: ProtocolCodes.ModeSmartGate, ConnectionType: "smartgate", RouteMode: ProtocolCodes.ModeSmart, Source: "A", Presentation: UiPresentationState.Idle(), IsEnrolled: true));
        using (var smartGateVm = new UiShellViewModel(new ProbeCoordinator(), smartGatePersistence, smartGatePersistence.Load()))
        {
            smartGateVm.RefreshAsync().GetAwaiter().GetResult();
            Assert(smartGateVm.Mode == ProtocolCodes.ModeSmartGate && smartGateVm.ConnectionType == "smartgate", "zero country exits never downgrade SmartGate to ordinary smart routing");
            Assert(string.IsNullOrEmpty(smartGateVm.Country) && !smartGateVm.CanConnect && !smartGateVm.HasSelectedSmartGateNode, "SmartGate fails closed when no customer-selectable node is published");
        }

        var selectableSmartGatePersistence = new CountingPersistence(new UiShellState(Mode: ProtocolCodes.ModeSmartGate, ConnectionType: "smartgate", RouteMode: ProtocolCodes.ModeSmart, Source: "A", Country: "", Presentation: UiPresentationState.Idle(), IsEnrolled: true));
        using (var selectableSmartGateVm = new UiShellViewModel(new ProbeCoordinator(withCountry: true), selectableSmartGatePersistence, selectableSmartGatePersistence.Load()))
        {
            selectableSmartGateVm.RefreshAsync().GetAwaiter().GetResult();
            Assert(string.IsNullOrEmpty(selectableSmartGateVm.Country) && !selectableSmartGateVm.CanConnect, "publishing SmartGate nodes does not silently auto-select one for the customer");
            selectableSmartGateVm.Country = "SG-US";
            Assert(selectableSmartGateVm.HasSelectedSmartGateNode && selectableSmartGateVm.CanConnect && selectableSmartGateVm.CanUseSmartGateAction, "explicit customer SmartGate node selection enables the connection action");
        }
    }

    private static void CandidateSelectionContractBehavior()
    {
        var direct = ConnectionRouteSelection.FromPresentation(ProtocolCodes.ModeGlobal, false);
        Assert(direct.ConnectionTypeCode == "direct-vmess" && direct.RouteModeCode == ProtocolCodes.ModeGlobal, "direct VMess keeps independent global route mode");
        var smartGate = ConnectionRouteSelection.FromPresentation(ProtocolCodes.ModeSmartGate, false);
        Assert(smartGate.ConnectionTypeCode == "smartgate" && smartGate.RouteModeCode == ProtocolCodes.ModeSmart, "SmartGate never crosses as a route mode");
        try { ConnectionRouteSelection.Parse("smartgate", ProtocolCodes.ModeGlobal); throw new InvalidOperationException("ambiguous SmartGate route accepted"); }
        catch (InvalidDataException) { }
        var config = new JsonObject
        {
            ["sources"] = new JsonArray
            {
                new JsonObject
                {
                    ["code"] = "A", ["configured"] = true,
                    ["candidates"] = new JsonArray
                    {
                        new JsonObject { ["label"] = "A-01", ["display_name"] = "测试线路", ["dial_address"] = "127.0.0.1", ["uuid"] = "TEST-ONLY" },
                    },
                },
                new JsonObject { ["code"] = "B", ["configured"] = true, ["candidates"] = new JsonArray() },
            },
        };
        var options = CandidateSelectionContract.CandidateOptions(config, "A");
        Assert(options.Count == 1 && options[0].Label == "A-01" && options[0].DisplayName == "测试线路", "candidate options expose safe labels only");
        Assert(CandidateSelectionContract.ValidateManual(config, "A", CandidateMode.Auto, null) is null, "auto mode carries no label");
        Assert(CandidateSelectionContract.ValidateManual(config, "A", CandidateMode.Manual, "A-01") == "A-01", "manual mode accepts signed label");
        try { CandidateSelectionContract.ValidateManual(config, "B", CandidateMode.Manual, "A-01"); throw new InvalidOperationException("cross-source candidate accepted"); }
        catch (InvalidDataException) { }
    }

    private static void CandidateSelectionNoDuplicateBehavior()
    {
        var selectedSource = SelectionSource("A", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        var frontSource = SelectionSource("B", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        var calls = new List<string>();
        var selectedCandidate = SelectionCandidate("A-01", "192.0.2.10");
        var frontCandidate = SelectionCandidate("B-01", "192.0.2.11");
        var plan = CandidateSelectionPlan.SelectAsync(
            selectedSource,
            frontSource,
            null,
            (source, requested, _) =>
            {
                calls.Add($"{source["code"]!.GetValue<string>()}:{requested ?? "auto"}");
                return Task.FromResult(string.Equals(source["code"]?.GetValue<string>(), "A", StringComparison.Ordinal)
                    ? selectedCandidate
                    : frontCandidate);
            },
            CancellationToken.None).GetAwaiter().GetResult();
        Assert(calls.SequenceEqual(new[] { "A:auto", "B:auto" }), "selection plan makes one primary and one alternate-front selection");
        Assert(ReferenceEquals(plan.FrontCandidate, frontCandidate), "validated SmartGate front candidate is retained for LocalSystem Mihomo compilation");
    }

    private static JsonObject SelectionSource(string code, string uuid) => new()
    {
        ["code"] = code,
        ["server_name"] = $"{code.ToLowerInvariant()}.test-only.invalid",
        ["transport"] = new JsonObject { ["host"] = $"{code.ToLowerInvariant()}.test-only.invalid", ["sni"] = $"{code.ToLowerInvariant()}.test-only.invalid", ["network"] = "tcp", ["tls"] = true },
        ["profiles"] = new JsonObject { ["direct"] = new JsonObject { ["profile_id"] = $"profile-{code}", ["uuid"] = uuid } }
    };

    private static JsonObject SelectionCandidate(string label, string address) => new() { ["label"] = label, ["dial_address"] = address, ["port"] = 443 };

    private static void ProbeLifecycleBehavior()
    {
        var scheduler = new ManualProbeScheduler();
        var coordinator = new ProbeCoordinator();
        var outcomes = new List<ProbeLifecycleOutcome>();
        using var lifecycle = new WindowsProbeLifecycle(coordinator, outcomes.Add, scheduler);

        lifecycle.Start("", 1);
        Assert(coordinator.Probes.Count == 0, "no valid source means no startup probe");
        lifecycle.Start("A", 1);
        Assert(coordinator.Probes.Count == 1, "startup probes exactly once");
        lifecycle.Start("A", 1); lifecycle.TriggerManual();
        Assert(coordinator.Probes.Count == 1, "same source/config triggers coalesce");
        coordinator.Complete(0, "TEST-CANDIDATE");
        WaitUntil(() => outcomes.Count(outcome => !outcome.IsPartial) == 1);
        Assert(outcomes.Count(outcome => outcome.IsPartial) == 3, "each completed route publishes progressive latency feedback before the final outcome");
        var firstFinal = outcomes.Last(outcome => !outcome.IsPartial);
        Assert(firstFinal.Success && firstFinal.SelectedCandidateLabel == "TEST-CANDIDATE", "successful result publishes typed candidate outcome");

        lifecycle.SourceChanged("B", 1);
        Assert(coordinator.Probes.Count == 2, "source change probes once");
        lifecycle.SourceChanged("B", 1);
        Assert(coordinator.Probes.Count == 2, "duplicate source selection coalesces");
        coordinator.Complete(1, "B-CANDIDATE");
        WaitUntil(() => outcomes.Count(outcome => !outcome.IsPartial) == 2);

        lifecycle.NetworkInvalidated(1);
        Assert(coordinator.Probes.Count == 2, "network invalidation cancels without immediate probe");
        scheduler.Advance(TimeSpan.FromMilliseconds(1499));
        Assert(coordinator.Probes.Count == 2, "1499ms quiet period does not probe");
        scheduler.Advance(TimeSpan.FromMilliseconds(1));
        WaitUntil(() => coordinator.Probes.Count == 3);
        Assert(coordinator.Probes.Count == 3, "1500ms quiet period probes once");
        coordinator.Complete(2, null);
        WaitUntil(() => outcomes.Count(outcome => !outcome.IsPartial) == 3);
        Assert(!outcomes.Last(outcome => !outcome.IsPartial).Success, "failure is fail-closed and has no candidate text");

        scheduler.Advance(TimeSpan.FromHours(2));
        WaitUntil(() => coordinator.Probes.Count == 4);
        Assert(coordinator.Probes.Count == 4, "two-hour cadence remains active while open/minimized");
        lifecycle.SourceChanged("B", 2);
        lifecycle.SourceChanged("A", 3);
        Assert(coordinator.Probes.Count == 6, "config/source A-B-A creates generation-safe rounds");
        coordinator.Complete(3, "STALE-B");
        coordinator.Complete(4, "STALE-A");
        coordinator.Complete(5, "CURRENT-A");
        WaitUntil(() => outcomes.Count(outcome => !outcome.IsPartial) == 4);
        var currentFinal = outcomes.Last(outcome => !outcome.IsPartial);
        Assert(currentFinal.Success && currentFinal.SelectedCandidateLabel == "CURRENT-A", "late stale completions cannot publish");

        var sourceDuringDebounceScheduler = new ManualProbeScheduler();
        var sourceDuringDebounceCoordinator = new ProbeCoordinator();
        using (var sourceDuringDebounce = new WindowsProbeLifecycle(sourceDuringDebounceCoordinator, _ => { }, sourceDuringDebounceScheduler))
        {
            sourceDuringDebounce.Start("A", 1);
            sourceDuringDebounceCoordinator.Complete(0, "A");
            sourceDuringDebounce.NetworkInvalidated(1);
            sourceDuringDebounce.SourceChanged("B", 1);
            Assert(sourceDuringDebounceCoordinator.Probes.Count == 2, "source change during debounce probes immediately");
            sourceDuringDebounceScheduler.Advance(WindowsProbeLifecycle.NetworkQuietPeriod);
            Thread.Sleep(20);
            Assert(sourceDuringDebounceCoordinator.Probes.Count == 2, "source change resets the old debounce");
        }

        var disposedScheduler = new ManualProbeScheduler();
        var disposedCoordinator = new ProbeCoordinator();
        var disposedOutcomes = new List<ProbeLifecycleOutcome>();
        var disposed = new WindowsProbeLifecycle(disposedCoordinator, disposedOutcomes.Add, disposedScheduler);
        disposed.Start("A", 1);
        disposed.Dispose();
        disposedCoordinator.Complete(0, "LATE");
        Thread.Sleep(20);
        Assert(disposedOutcomes.Count == 0, "dispose prevents later publication");

        var manualCancelScheduler = new ManualProbeScheduler();
        var manualCancelCoordinator = new ProbeCoordinator(observeCancellation: true);
        var manualCancelOutcomes = new List<ProbeLifecycleOutcome>();
        using (var manualCancel = new WindowsProbeLifecycle(manualCancelCoordinator, manualCancelOutcomes.Add, manualCancelScheduler))
        {
            manualCancel.Start("A", 1);
            Assert(manualCancelCoordinator.Probes.Count == 1, "manual-cancel fixture starts one active round");
            manualCancel.CancelManual();
            WaitUntil(() => manualCancelCoordinator.CancellationObserved >= 1, "manual cancel did not reach the active probe token");
            Assert(manualCancelOutcomes.Count == 0, "manual cancellation cannot publish a false terminal measurement");
            manualCancel.TriggerManual();
            Assert(manualCancelCoordinator.Probes.Count == 2, "a stopped batch can be restarted immediately");
        }

        // Superseded rounds remain owned until they unwind. Cooperative fake
        // work observes cancellation; stubborn completions arrive after the
        // bounded join and still cannot publish or start new work.
        var supersededScheduler = new ManualProbeScheduler();
        var supersededCoordinator = new ProbeCoordinator(observeCancellation: true);
        var supersededOutcomes = new List<ProbeLifecycleOutcome>();
        var superseded = new WindowsProbeLifecycle(supersededCoordinator, supersededOutcomes.Add, supersededScheduler);
        superseded.Start("A", 1);
        superseded.SourceChanged("B", 1);
        superseded.SourceChanged("A", 2);
        Assert(supersededCoordinator.Probes.Count == 3, "all superseded rounds are represented before dispose");
        superseded.Dispose();
        Assert(supersededCoordinator.CancellationObserved >= 2, "superseded cooperative rounds observe cancellation");
        supersededCoordinator.Complete(0, "LATE-A");
        supersededCoordinator.Complete(1, "LATE-B");
        supersededCoordinator.Complete(2, "LATE-A2");
        superseded.Start("A", 3);
        superseded.SourceChanged("B", 3);
        superseded.NetworkInvalidated(3);
        superseded.TriggerManual();
        Thread.Sleep(20);
        Assert(supersededCoordinator.Probes.Count == 3 && supersededOutcomes.Count == 0, "disposed lifecycle rejects new work and stubborn late results");
        Console.WriteLine("PROBE-LIFECYCLE-FIXTURE PASS");
    }

    private static void ActivationProbeLifecycleBehavior()
    {
        // Activation remains lightweight on the home page. The same lifecycle
        // owner starts once the user opens Lines, then retains its cadence.
        var activationScheduler = new ManualProbeScheduler();
        var activationCoordinator = new ProbeCoordinator(enrolled: false, activateOnEnrollment: true);
        using (var lifecycle = new WindowsProbeLifecycle(activationCoordinator, _ => { }, activationScheduler))
        using (var vm = new UiShellViewModel(
            activationCoordinator,
            new CountingPersistence(new UiShellState(Source: "A", Presentation: UiPresentationState.Idle())),
            new UiShellState(Source: "A", Presentation: UiPresentationState.Idle()),
            lifecycle))
        {
            vm.EnrollAsync("TEST-INVITE").GetAwaiter().GetResult();
            Assert(activationCoordinator.Probes.Count == 0, "successful first enrollment does not launch a heavyweight latency sweep on the home page");
            vm.StartAsync().GetAwaiter().GetResult();
            Assert(activationCoordinator.Probes.Count == 0, "repeated successful Start remains lightweight before Lines is opened");
            vm.NavigateAsync("nodes").GetAwaiter().GetResult();
            Assert(activationCoordinator.Probes.Count == 1, "opening Lines after enrollment probes the persisted valid source once");
            activationCoordinator.Complete(0, "TEST-CANDIDATE");
            WaitUntil(() => activationCoordinator.CompletedProbeCount == 1);
            activationScheduler.Advance(TimeSpan.FromHours(2));
            WaitUntil(() => activationCoordinator.Probes.Count == 2);
            activationScheduler.Advance(TimeSpan.FromHours(2));
            Assert(activationCoordinator.Probes.Count == 2, "a second cadence tick cannot duplicate an unfinished round");
        }

        // Enrollment with no persisted source uses the first currently signed
        // source as the deterministic safe default without paying the latency
        // sweep cost until the Lines page actually needs those measurements.
        var emptyScheduler = new ManualProbeScheduler();
        var emptyCoordinator = new ProbeCoordinator(enrolled: false, activateOnEnrollment: true);
        using (var lifecycle = new WindowsProbeLifecycle(emptyCoordinator, _ => { }, emptyScheduler))
        using (var vm = new UiShellViewModel(
            emptyCoordinator,
            new CountingPersistence(new UiShellState(Presentation: UiPresentationState.Idle())),
            new UiShellState(Presentation: UiPresentationState.Idle()),
            lifecycle))
        {
            vm.EnrollAsync("TEST-INVITE").GetAwaiter().GetResult();
            Assert(vm.Source == "A", "activation with no persisted source selects the first signed source");
            Assert(emptyCoordinator.Probes.Count == 0, "activation with signed fallback source remains lightweight on the home page");
            vm.NavigateAsync("nodes").GetAwaiter().GetResult();
            Assert(emptyCoordinator.Probes.Count == 1, "opening Lines probes the signed fallback source exactly once");
            vm.Source = "A";
            Assert(emptyCoordinator.Probes.Count == 1, "reselecting the active signed source does not duplicate the probe");
        }

        var pairingScheduler = new ManualProbeScheduler();
        var pairingCoordinator = new ProbeCoordinator(enrolled: false, activateOnEnrollment: true);
        using (var lifecycle = new WindowsProbeLifecycle(pairingCoordinator, _ => { }, pairingScheduler))
        using (var vm = new UiShellViewModel(
            pairingCoordinator,
            new CountingPersistence(new UiShellState(Source: "A", Presentation: UiPresentationState.Idle())),
            new UiShellState(Source: "A", Presentation: UiPresentationState.Idle()),
            lifecycle))
        {
            vm.RedeemPairingAsync("TEST-PAIRING").GetAwaiter().GetResult();
            Assert(pairingCoordinator.Probes.Count == 0, "successful pairing redeem stays lightweight on the home page");
            vm.NavigateAsync("nodes").GetAwaiter().GetResult();
            Assert(pairingCoordinator.Probes.Count == 1, "opening Lines after pairing probes the valid source once");
        }

        var recoveryScheduler = new ManualProbeScheduler();
        var recoveryCoordinator = new ProbeCoordinator(enrolled: false, pendingRecovery: true);
        using (var lifecycle = new WindowsProbeLifecycle(recoveryCoordinator, _ => { }, recoveryScheduler))
        using (var vm = new UiShellViewModel(
            recoveryCoordinator,
            new CountingPersistence(new UiShellState(Source: "A", Presentation: UiPresentationState.Idle())),
            new UiShellState(Source: "A", Presentation: UiPresentationState.Idle()),
            lifecycle))
        {
            var result = vm.RecoverAsync("TEST-PUBLIC-ID", "TEST-RECOVERY").GetAwaiter().GetResult();
            Assert(result?.Ok == true && !recoveryCoordinator.IsEnrolled, "pending recovery does not claim enrollment");
            vm.Source = "A";
            Assert(recoveryCoordinator.Probes.Count == 0, "pending recovery does not start a probe lifecycle");
        }

        Console.WriteLine("ACTIVATION-PROBE-FIXTURE PASS");
    }

    private static void WaitUntil(Func<bool> condition, string failure = "deterministic async completion timed out")
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
        while (!condition() && DateTime.UtcNow < deadline) Thread.Sleep(5);
        Assert(condition(), failure);
    }

    private sealed class ManualProbeScheduler : IProbeLifecycleScheduler
    {
        private readonly object _gate = new();
        private readonly List<PendingDelay> _pending = new();
        private TimeSpan _now;
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            var completion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var pending = new PendingDelay(_now + delay, completion);
            lock (_gate) _pending.Add(pending);
            cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
            return completion.Task;
        }
        public void Advance(TimeSpan amount)
        {
            List<PendingDelay> due;
            lock (_gate)
            {
                _now += amount;
                due = _pending.Where(item => item.Due <= _now).ToList();
                foreach (var item in due) _pending.Remove(item);
            }
            foreach (var item in due) item.Completion.TrySetResult(null);
        }
        public void Dispose()
        {
            PendingDelay[] pending;
            lock (_gate) { pending = _pending.ToArray(); _pending.Clear(); }
            foreach (var item in pending) item.Completion.TrySetCanceled();
        }
        private sealed record PendingDelay(TimeSpan Due, TaskCompletionSource<object?> Completion);
    }

    private static int ConnectConflict()
    {
        var online = ServiceStatus.ConnectedState("mihomo", "smart", "cfg_existing", "A",
            new EnforcementSummary("smart", "none", 0, new string('a', 64), new string('b', 32), true));
        var coordinator = new ProbeCoordinator { ConnectConflictStatus = online };
        using var model = new UiShellViewModel(coordinator,
            new InMemoryUiShellPersistence(new UiShellState(Source: "A")));
        model.ConnectAsync().GetAwaiter().GetResult();
        Assert(coordinator.ConnectAttempts.Count == 1 && coordinator.DisconnectCalls == 0,
            "Rejected connect must not tear down a connection owned by another request");
        Assert(model.IsProtected && model.UpdateText.Contains("本次连接请求未执行"),
            "Conflict must display the verified existing session and explain that new settings were not applied");
        Console.WriteLine("UI-CONNECT-CONFLICT verified readback, rejected request and no foreign cleanup PASS");
        return 0;
    }

    private static int SmartGateRecovery()
    {
        try
        {
            var coordinator = new ProbeCoordinator(withCountry: true);
            using var model = new UiShellViewModel(coordinator, new InMemoryUiShellPersistence(new UiShellState(Source: "A")));
            model.Mode = ProtocolCodes.ModeSmartGate;
            model.Country = "SG-US";
            model.ApplyStatus(ServiceStatus.Blocked("BF-TRANSPORT-PROBE-PROXY"));
            var recover = typeof(UiShellViewModel).GetMethod("TryAutomaticCandidateFailoverAsync",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            ((Task)recover.Invoke(model, null)!).GetAwaiter().GetResult();
            Assert(model.IsProtected, $"SmartGate blocked runtime automatically reconnects: {model.StatusText}; mode={model.Mode}; country={model.Country}; ready={model.HasSelectedSmartGateNode}; disconnects={coordinator.DisconnectCalls}; connects={coordinator.ConnectAttempts.Count}");
            Assert(coordinator.DisconnectCalls == 1 && coordinator.ConnectAttempts.Count == 1,
                "SmartGate recovery completes teardown and reconnect exactly once");
            Assert(coordinator.LastPreparedState?.Country == "SG-US" && coordinator.LastPreparedState?.ConnectionType == "smartgate",
                "recovery preserves the customer-selected SmartGate exit and transport");
            ((Task)recover.Invoke(model, null)!).GetAwaiter().GetResult();
            Assert(model.IsProtected && coordinator.DisconnectCalls == 1, "late recovery never disconnects a healthy connection");
            Console.WriteLine("SMARTGATE-RECOVERY PASS teardown/reconnect/exit-preservation/healthy-no-op");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }

    private sealed class ProbeCoordinator : IUiShellCoordinator
    {
        private bool _enrolled;
        private long _configVersion;
        private readonly bool _activateOnEnrollment;
        private readonly bool _resumeOnRefresh;
        private int _refreshFailuresBeforeSuccess;
        private bool _pendingEnrollment;
        private bool _pendingRecovery;
        private readonly bool _observeCancellation;
        private readonly bool _withCountry;
        private readonly ReleaseCheckResult? _updateResult;
        private int _cancellationObserved;
        private int _updateChecks;
        private int _updateApplies;
        public ProbeCoordinator(bool enrolled = true, bool activateOnEnrollment = false, bool pendingRecovery = false, bool observeCancellation = false, ReleaseCheckResult? updateResult = null, bool withCountry = false, bool pendingEnrollment = false, bool resumeOnRefresh = false, int refreshFailuresBeforeSuccess = 0)
        {
            _enrolled = enrolled;
            _configVersion = enrolled ? 1 : 0;
            _activateOnEnrollment = activateOnEnrollment;
            _resumeOnRefresh = resumeOnRefresh;
            _refreshFailuresBeforeSuccess = refreshFailuresBeforeSuccess;
            _pendingEnrollment = pendingEnrollment;
            _pendingRecovery = pendingRecovery;
            _observeCancellation = observeCancellation;
            _updateResult = updateResult;
            _withCountry = withCountry;
        }
        public bool IsEnrolled => _enrolled;
        public bool HasPendingEnrollment => _pendingEnrollment;
        public bool HasPendingRecovery => _pendingRecovery;
        public bool IsLocalEvaluation => false;
        public string? ControlUrl => "https://control.example.invalid";
        public string CompiledOriginDisplay => "control.example.invalid";
        public string ControlOriginStatus => "此测试构建未配置控制面";
        public string? SessionToken => null;
        public string? RecoveryCode => null;
        public long LastConfigVersion => _configVersion;
        public List<string> Probes { get; } = new();
        public int CompletedProbeCount { get; private set; }
        public int CancellationObserved => Volatile.Read(ref _cancellationObserved);
        public int UpdateChecks => Volatile.Read(ref _updateChecks);
        public int UpdateApplies => Volatile.Read(ref _updateApplies);
        public int RefreshCalls { get; private set; }
        public UiShellState? LastPreparedState { get; private set; }
        public HashSet<string> FailingCandidates { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> ConnectAttempts { get; } = new();
        public int DisconnectCalls { get; private set; }
        public ServiceStatus? ConnectConflictStatus { get; init; }
        private readonly List<TaskCompletionSource<CandidateProbeSnapshot>> _completions = new();
        private readonly List<Action<CandidateProbeProgress>?> _probeProgress = new();
        public event Action? NetworkProbeInvalidated;
        public UiConfigOptions GetUiConfigOptions() => new(
            new[] { new UiOption("A", "线路 A"), new UiOption("B", "线路 B") },
            Array.Empty<UiOption>(),
            _withCountry ? new[] { new UiOption("SG-US", "美国 SmartGate") } : Array.Empty<UiOption>(),
            new Dictionary<string, IReadOnlyList<UiOption>>(StringComparer.OrdinalIgnoreCase)
            {
                ["A"] = new[] { new UiOption("A-01", "测试线路 A-01"), new UiOption("A-02", "测试线路 A-02"), new UiOption("A-03", "测试线路 A-03") },
                ["B"] = new[] { new UiOption("B-01", "测试线路 B-01"), new UiOption("B-02", "测试线路 B-02"), new UiOption("B-03", "测试线路 B-03") },
            });
        public Task<CandidateProbeSnapshot> ProbeCandidateStatusesAsync(string source, Action<CandidateProbeProgress>? progress, CancellationToken cancellationToken)
        {
            Probes.Add(source);
            var completion = new TaskCompletionSource<CandidateProbeSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
            _completions.Add(completion);
            _probeProgress.Add(progress);
            if (_observeCancellation)
            {
                cancellationToken.Register(() =>
                {
                    Interlocked.Increment(ref _cancellationObserved);
                    completion.TrySetCanceled(cancellationToken);
                });
            }
            return completion.Task;
        }
        public void Complete(int index, string? label)
        {
            var source = Probes[index];
            var candidates = GetUiConfigOptions().CandidatesBySource![source];
            var measuredAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var statuses = candidates.Select((candidate, candidateIndex) => new CandidateProbeStatus(
                candidate.Code,
                label is not null,
                label is null ? null : 28d + candidateIndex * 17d,
                label is null ? 100d : 0d,
                measuredAt)).ToArray();
            for (var candidateIndex = 0; candidateIndex < statuses.Length; candidateIndex++)
                _probeProgress[index]?.Invoke(new CandidateProbeProgress(source, candidateIndex + 1, statuses.Length, statuses[candidateIndex]));
            if (_completions[index].TrySetResult(new CandidateProbeSnapshot(source, label, statuses))) CompletedProbeCount++;
        }
        public void Fail(int index, string code) =>
            _completions[index].TrySetException(new ServiceException(code, "TEST-ONLY probe failure"));
        public void RaiseNetworkInvalidation() => NetworkProbeInvalidated?.Invoke();
        public Task<ControlResult> EnrollAsync(string _, CancellationToken __)
        {
            if (!_activateOnEnrollment) return Task.FromResult(new ControlResult(false, "TEST", null, null, 0));
            _enrolled = true; _configVersion = 1;
            return Task.FromResult(new ControlResult(true, "TEST-ENROLLED", null, null, _configVersion));
        }
        public Task<ControlResult> RecoverAsync(string _, string __, CancellationToken ___) =>
            Task.FromResult(_pendingRecovery
                ? new ControlResult(true, "TEST-RECOVERY-PENDING", "BF-RECOVERY-PENDING", null, 0)
                : new ControlResult(false, "TEST", "BF-RECOVERY", null, 0));
        public Task<ControlResult> RetrieveRecoveryDeliveryAsync(CancellationToken _)
        {
            if (!_pendingRecovery) return Task.FromResult(new ControlResult(false, "TEST-NOT-PENDING", null, null, 0));
            return Task.FromResult(new ControlResult(false, "TEST-RECOVERY-PENDING", "BF-RECOVERY-PENDING", null, 0));
        }
        public Task<ControlResult> RotateRecoveryCodeAsync(CancellationToken _) =>
            Task.FromResult(new ControlResult(true, "TEST-ROTATED", "BF-RECOVERY", "BFR-TEST-ONLY-ROTATED", _configVersion));
        public Task<ControlResult> CreatePairingAsync(string _, CancellationToken __) => Task.FromResult(new ControlResult(false, "TEST", null, null, 0));
        public Task<ControlResult> RedeemPairingAsync(string _, CancellationToken __)
        {
            if (!_activateOnEnrollment) return Task.FromResult(new ControlResult(false, "TEST", null, null, 0));
            _enrolled = true; _configVersion = 1;
            return Task.FromResult(new ControlResult(true, "TEST-PAIRED", null, null, _configVersion));
        }
        public Task<ControlResult> RefreshAsync(CancellationToken _)
        {
            RefreshCalls++;
            if (_refreshFailuresBeforeSuccess > 0)
            {
                _refreshFailuresBeforeSuccess--;
                return Task.FromException<ControlResult>(new HttpRequestException("TEST-ONLY transient startup network failure"));
            }
            if (!_enrolled && _resumeOnRefresh)
            {
                _enrolled = true;
                _pendingEnrollment = false;
                _configVersion = 1;
            }
            return Task.FromResult(new ControlResult(_enrolled, "TEST", null, null, _configVersion));
        }
        public Task LogoutAsync(CancellationToken _) => Task.CompletedTask;
        public Task<SignedClientPackageRequest> PrepareSignedPackageAsync(UiShellState state, ApplicationPolicySnapshot snapshot, CancellationToken _)
        {
            LastPreparedState = state;
            return Task.FromResult(new SignedClientPackageRequest(state.RouteMode, state.Core, state.Source, state.Country, snapshot.PolicyMode, snapshot, state.ConnectionType));
        }
        public Task<ServiceStatus> StageConfigAsync(SignedClientPackageRequest package, CancellationToken _) =>
            Task.FromResult(ServiceStatus.Staged("cfg_probe", ProtocolCodes.CoreMihomo, package.Mode));
        public Task<ServiceStatus> ConnectAsync(UiShellState state, ApplicationPolicySnapshot snapshot, string configId, string stagedCore, CancellationToken _)
        {
            ConnectAttempts.Add(state.CandidateLabel);
            if (ConnectConflictStatus is not null)
                return Task.FromException<ServiceStatus>(new ServiceException("BF-CONNECTION-RESET-REQUIRED", "TEST-ONLY concurrent connection"));
            return FailingCandidates.Contains(state.CandidateLabel)
                ? Task.FromException<ServiceStatus>(new ServiceException("BF-TRANSPORT-PROBE-TLS-HANDSHAKE", "TEST-ONLY candidate failure"))
                : Task.FromResult(ServiceStatus.ConnectedState(stagedCore, state.RouteMode, configId, state.Source, new EnforcementSummary(state.RouteMode, snapshot.PolicyMode, snapshot.Identities.Count, snapshot.Digest, new string('a', 32), true)));
        }
        public Task<ServiceStatus> DisconnectAsync(CancellationToken _)
        {
            DisconnectCalls++;
            return Task.FromResult(ServiceStatus.Disconnected());
        }
        public Task<ServiceStatus> GetStatusAsync(CancellationToken _) => Task.FromResult(ConnectConflictStatus ?? ServiceStatus.Disconnected());
        public Task<ReleaseCheckResult?> CheckProgramUpdateAsync(IProgress<ReleaseUpdateProgress>? progress, CancellationToken _)
        {
            Interlocked.Increment(ref _updateChecks);
            progress?.Report(new ReleaseUpdateProgress(8, "checking", "TEST-ONLY checking"));
            progress?.Report(new ReleaseUpdateProgress(100, _updateResult?.State == "up-to-date" ? "current" : "staged", "TEST-ONLY complete"));
            return Task.FromResult(_updateResult);
        }
        public Task<ServiceStatus> ApplyProgramUpdateAsync(CancellationToken _)
        {
            Interlocked.Increment(ref _updateApplies);
            return Task.FromResult(ServiceStatus.UpdateScheduled());
        }
        public void Dispose() { }
    }

    private sealed class StatusBodyTimeoutHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly Action? _onSend;
        public StatusBodyTimeoutHandler(HttpStatusCode status, Action? onSend = null) { _status = status; _onSend = onSend; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onSend?.Invoke();
            var response = new HttpResponseMessage(_status)
            {
                RequestMessage = request,
                Content = new TimeoutHttpContent(),
            };
            response.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");
            return Task.FromResult(response);
        }
    }

    private sealed class EnrollmentReplacementHandler : HttpMessageHandler
    {
        private readonly string _challengeCode;
        public EnrollmentReplacementHandler(string challengeCode) => _challengeCode = challengeCode;
        public List<string> ChallengeDeviceIds { get; } = new();
        public int RedeemRequests { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (path == "/v1/device/challenge")
            {
                var text = request.Content is null ? "{}" : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                var body = JsonNode.Parse(text)?.AsObject() ?? new JsonObject();
                ChallengeDeviceIds.Add(body["device_id"]?.GetValue<string>() ?? string.Empty);
                var code = ChallengeDeviceIds.Count == 1 ? _challengeCode : "BF-DEVICE-404";
                return Error(request,
                    code == "BF-DEVICE-404" ? HttpStatusCode.NotFound : HttpStatusCode.Unauthorized,
                    code,
                    code == "BF-DEVICE-404" ? "error.bf.device.404" : "error.bf.auth.003");
            }
            if (path == "/v1/enrollment/redeem")
            {
                RedeemRequests++;
                return Error(request, HttpStatusCode.BadRequest, "BF-ENROLL-001", "error.bf.enroll.001");
            }
            throw new InvalidOperationException($"unexpected replacement enrollment request: {path}");
        }

        private static HttpResponseMessage Error(HttpRequestMessage request, HttpStatusCode status, string code, string messageKey)
        {
            var json = JsonSerializer.Serialize(new
            {
                error = new
                {
                    code,
                    message_key = messageKey,
                    request_id = "req_TESTONLY1234"
                }
            });
            return new HttpResponseMessage(status)
            {
                RequestMessage = request,
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class EnrollmentIdentityHandler : HttpMessageHandler
    {
        public int SessionRequests { get; private set; }
        public bool IdentityOptInSeen { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.AbsolutePath == "/v1/device/session")
            {
                SessionRequests++;
                IdentityOptInSeen = request.Headers.TryGetValues("X-Bifrost-Session-Identity", out var values) &&
                    values.SequenceEqual(new[] { "public-id-v1" });
            }
            var body = request.RequestUri?.AbsolutePath switch
            {
                "/v1/device/challenge" => "{\"challenge\":\"TEST-ONLY-challenge-0001\",\"expires_in\":120}",
                "/v1/device/session" => "{\"session_token\":\"TEST-ONLY-session-token-0000000000000001\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"public_id\":\"BF-TEST-LOST-RESPONSE\"}",
                _ => throw new InvalidOperationException("unexpected enrollment identity request")
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class TimeoutHttpContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            Task.FromException(new TaskCanceledException("TEST-ONLY response body timeout"));
        protected override bool TryComputeLength(out long length) { length = 1; return true; }
        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromException<Stream>(new TaskCanceledException("TEST-ONLY response body timeout"));
    }

    private sealed class ThrowingPersistence : IUiShellPersistence
    {
        private readonly bool _throwOnLoad;
        private readonly bool _throwOnSave;
        private UiShellState _state;
        public ThrowingPersistence(bool throwOnLoad = false, UiShellState? state = null, bool throwOnSave = false)
        {
            _throwOnLoad = throwOnLoad;
            _throwOnSave = throwOnSave;
            _state = state ?? new UiShellState(Presentation: UiPresentationState.Idle());
        }
        public UiShellState Load() { if (_throwOnLoad) throw new IOException("TEST-ONLY storage failure"); return _state; }
        public void Save(UiShellState state) { if (_throwOnSave) throw new IOException("TEST-ONLY storage failure"); _state = state; }
    }

    private sealed class CountingPersistence : IUiShellPersistence
    {
        private UiShellState _state;
        public int SaveCalls { get; private set; }
        public CountingPersistence(UiShellState state) => _state = state;
        public UiShellState Load() => _state;
        public void Save(UiShellState state) { SaveCalls++; _state = state; }
    }

    private sealed class FakeSensitiveClipboard : ISensitiveClipboard
    {
        public string? Value { get; set; }
        public bool WriteSucceeds { get; set; } = true;
        public bool ReadSucceeds { get; set; } = true;
        public bool ClearSucceeds { get; set; } = true;
        public SensitiveClipboardReadResult TryReadText() =>
            ReadSucceeds ? new SensitiveClipboardReadResult(true, Value) : new SensitiveClipboardReadResult(false, null);
        public bool WriteText(string value)
        {
            if (!WriteSucceeds) return false;
            Value = value;
            return true;
        }
        public bool ClearIfMatches(string expected)
        {
            if (!ClearSucceeds) return false;
            if (Value != expected) return false;
            Value = null;
            return true;
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
