using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Bifrost.Release;

internal static class UpdateResumeFixture
{
    private const int ChunkBytes = 4 * 1024 * 1024;

    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-update-resume-" + Guid.NewGuid().ToString("N"));
        var installRoot = Path.Combine(root, "install");
        var updateRoot = Path.Combine(root, "updates");
        var destination = Path.Combine(root, "stage", "Bifrost.bin");
        var resumePath = Path.Combine(updateRoot, "download-cache", "artifact.part");
        var previousInstall = Environment.GetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT");
        var previousUpdate = Environment.GetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT");
        var payload = new byte[ChunkBytes * 2 + 733_117];
        for (var index = 0; index < payload.Length; index++) payload[index] = (byte)(index % 251);
        var digest = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        try
        {
            Directory.CreateDirectory(installRoot);
            Directory.CreateDirectory(updateRoot);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            Environment.SetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT", installRoot);
            Environment.SetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT", updateRoot);
            using var handler = new RangeFixtureHandler(payload);
            using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var manager = new ReleaseUpdateManager(http);
            var uri = new Uri("https://updates.test/v1/releases/artifacts/Bifrost.bin");

            var interrupted = false;
            try
            {
                manager.DownloadArtifactForHarnessAsync(uri, destination, resumePath, payload.LongLength, digest)
                    .GetAwaiter().GetResult();
            }
            catch (IOException error) when (string.Equals(error.Message, "BF-RELEASE-CHUNK-RETRY", StringComparison.Ordinal))
            {
                interrupted = true;
            }
            Require(interrupted, "first transfer must stop after bounded retries");
            Require(File.Exists(resumePath), "partial cache must survive an interrupted transfer");
            Require(new FileInfo(resumePath).Length == ChunkBytes * 2L, "partial cache must end at the last complete range");
            Require(!File.Exists(destination), "an interrupted transfer must not expose a staged artifact");

            var secondRunStart = handler.RequestStarts.Count;
            handler.AllowTail = true;
            manager.DownloadArtifactForHarnessAsync(uri, destination, resumePath, payload.LongLength, digest)
                .GetAwaiter().GetResult();
            var resumedRequests = handler.RequestStarts.Skip(secondRunStart).ToArray();
            Require(resumedRequests.Length == 1 && resumedRequests[0] == ChunkBytes * 2L,
                "resume must request only the missing tail instead of restarting at byte zero");
            Require(File.Exists(destination), "verified artifact must be staged");
            Require(File.ReadAllBytes(destination).AsSpan().SequenceEqual(payload), "resumed artifact bytes must match exactly");
            var blobDestination = Path.Combine(root, "stage", "Bifrost-cdn.bin");
            var blobResume = Path.Combine(updateRoot, "download-cache", "artifact-cdn.part");
            using var blobHandler = new ParallelBlobFixtureHandler(payload);
            using var blobHttp = new HttpClient(blobHandler) { Timeout = Timeout.InfiniteTimeSpan };
            using var blobManager = new ReleaseUpdateManager(blobHttp);
            var blobUri = new Uri($"https://updates.test/v1/releases/blobs/{digest}/Bifrost.bin.bin");
            blobManager.DownloadArtifactForHarnessAsync(blobUri, blobDestination, blobResume, payload.LongLength, digest)
                .GetAwaiter().GetResult();
            Require(blobHandler.FullRequests == 1 && blobHandler.RangeRequests == 0,
                "a fresh content-addressed blob must prefer one CDN-cacheable full-object request");
            Require(!blobHandler.SawAuthorization, "public immutable blobs must not shard the CDN cache by device authorization");
            Require(File.ReadAllBytes(blobDestination).AsSpan().SequenceEqual(payload), "cold blob bytes must match exactly");

            var resumedBlobDestination = Path.Combine(root, "stage", "Bifrost-cdn-resumed.bin");
            using (var resume = new FileStream(blobResume, FileMode.Open, FileAccess.Write, FileShare.None))
                resume.SetLength(ChunkBytes);
            blobManager.DownloadArtifactForHarnessAsync(blobUri, resumedBlobDestination, blobResume, payload.LongLength, digest)
                .GetAwaiter().GetResult();
            Require(blobHandler.FullRequests == 1 && blobHandler.RangeRequests == 2,
                "an existing blob prefix must resume only the missing ranges instead of restarting the full object");
            Require(blobHandler.MaxConcurrentRequests >= 2,
                "resumed blob ranges must retain bounded parallelism");
            Require(File.ReadAllBytes(resumedBlobDestination).AsSpan().SequenceEqual(payload),
                "resumed CDN blob bytes must match exactly");

            var fallbackDestination = Path.Combine(root, "stage", "Bifrost-fallback.bin");
            var fallbackResume = Path.Combine(updateRoot, "download-cache", "artifact-fallback.part");
            using var fallbackHandler = new MirrorFallbackFixtureHandler(payload);
            using var fallbackHttp = new HttpClient(fallbackHandler) { Timeout = Timeout.InfiniteTimeSpan };
            using var fallbackManager = new ReleaseUpdateManager(fallbackHttp);
            var preferredUri = new Uri($"https://mirror.test/v1/releases/blobs/{digest}/Bifrost.bin.bin");
            var fallbackUri = new Uri($"https://control.test/v1/releases/blobs/{digest}/Bifrost.bin.bin");
            long fallbackProgress = 0;
            fallbackManager.DownloadArtifactWithFallbackForHarnessAsync(preferredUri, fallbackUri,
                    fallbackDestination, fallbackResume, payload.LongLength, digest, delta => fallbackProgress += delta)
                .GetAwaiter().GetResult();
            Require(fallbackHandler.PreferredRequests > 0, "the preferred mirror must be attempted before fallback");
            Require(fallbackHandler.FallbackRequests == 4,
                "the control fallback must reject its full-object redirect locally, then complete through three independent ranges");
            Require(!fallbackHandler.SawAuthorization, "public preferred and fallback blobs must not carry device authorization");
            Require(fallbackProgress == payload.LongLength, "fallback progress must count verified bytes exactly once");
            Require(File.ReadAllBytes(fallbackDestination).AsSpan().SequenceEqual(payload), "fallback bytes must match exactly");

            var redirectDestination = Path.Combine(root, "stage", "Bifrost-redirect-fallback.bin");
            var redirectResume = Path.Combine(updateRoot, "download-cache", "artifact-redirect-fallback.part");
            using var redirectHandler = new TrustedRedirectFallbackFixtureHandler(payload);
            using var redirectHttp = new HttpClient(redirectHandler) { Timeout = Timeout.InfiniteTimeSpan };
            using var redirectManager = new ReleaseUpdateManager(redirectHttp);
            var productionMirrorUri = new Uri($"https://bifrostlog.com/v1/releases/blobs/{digest}/Bifrost.bin.bin");
            var productionEdgeUri = new Uri($"https://edge.bifrostlog.com/v1/releases/blobs/{digest}/Bifrost.bin.bin");
            redirectManager.DownloadArtifactWithFallbackForHarnessAsync(preferredUri, productionEdgeUri,
                    redirectDestination, redirectResume, payload.LongLength, digest)
                .GetAwaiter().GetResult();
            Require(redirectHandler.EdgeRedirects == 1, "the control edge fallback must return one redirect");
            Require(redirectHandler.MirrorRequests == 1, "the trusted redirect must be followed exactly once to the public mirror");
            Require(!redirectHandler.SawAuthorization, "trusted public-blob redirect must not carry device authorization");
            Require(File.ReadAllBytes(redirectDestination).AsSpan().SequenceEqual(payload),
                "trusted public-blob redirect must stage the verified payload");

            var transientDestination = Path.Combine(root, "stage", "Bifrost-transient.bin");
            var transientResume = Path.Combine(updateRoot, "download-cache", "artifact-transient.part");
            using var transientHandler = new TransientStatusFixtureHandler(payload);
            using var transientHttp = new HttpClient(transientHandler) { Timeout = Timeout.InfiniteTimeSpan };
            using var transientManager = new ReleaseUpdateManager(transientHttp);
            transientManager.DownloadArtifactForHarnessAsync(uri, transientDestination, transientResume,
                    payload.LongLength, digest)
                .GetAwaiter().GetResult();
            Require(transientHandler.AttemptsFor(0) == 2, "HTTP 429 must retry the same first range once");
            Require(transientHandler.AttemptsFor(ChunkBytes) == 2, "HTTP 503 must retry the same second range once");
            Require(transientHandler.AttemptsFor(ChunkBytes * 2L) == 1, "a successful range must not be retried");
            Require(File.ReadAllBytes(transientDestination).AsSpan().SequenceEqual(payload),
                "transient HTTP retries must preserve exact artifact bytes");

            var corruptDestination = Path.Combine(root, "stage", "Bifrost-corrupt-fallback.bin");
            var corruptResume = Path.Combine(updateRoot, "download-cache", "artifact-corrupt-fallback.part");
            using var corruptHandler = new CorruptMirrorFallbackFixtureHandler(payload);
            using var corruptHttp = new HttpClient(corruptHandler) { Timeout = Timeout.InfiniteTimeSpan };
            using var corruptManager = new ReleaseUpdateManager(corruptHttp);
            long corruptFallbackProgress = 0;
            corruptManager.DownloadArtifactWithFallbackForHarnessAsync(preferredUri, fallbackUri,
                    corruptDestination, corruptResume, payload.LongLength, digest,
                    delta => corruptFallbackProgress += delta)
                .GetAwaiter().GetResult();
            Require(corruptHandler.PreferredRequests == 1,
                "the corrupt preferred mirror must return one full object before digest rejection");
            Require(corruptHandler.FallbackRequests == 1,
                "the fallback must replace the rejected full object exactly once");
            Require(corruptFallbackProgress == payload.LongLength,
                "digest-failure fallback progress must not count rejected mirror bytes twice");
            Require(File.ReadAllBytes(corruptDestination).AsSpan().SequenceEqual(payload),
                "digest-failure fallback must stage only the verified payload");
            Console.WriteLine($"UPDATE-RESUME PASS partial={ChunkBytes * 2L} total={payload.LongLength} resumed_requests={resumedRequests.Length} cdn_full=1 resumed_blob_ranges={blobHandler.RangeRequests} max_parallel={blobHandler.MaxConcurrentRequests} mirror_fallback=1 trusted_redirect=1 transient_retries=2 corrupt_mirror_fallback=1");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"UPDATE-RESUME FAIL {error.GetType().Name}: {error.Message}");
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            Environment.SetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT", previousInstall);
            Environment.SetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT", previousUpdate);
            try { if (Directory.Exists(root)) Directory.Delete(root, true); } catch { }
        }
    }

    internal static int RunRenewedSessionFlow()
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-update-session-" + Guid.NewGuid().ToString("N"));
        var installRoot = Path.Combine(root, "install");
        var updateRoot = Path.Combine(root, "updates");
        var previousInstall = Environment.GetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT");
        var previousUpdate = Environment.GetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT");
        var fixturePath = Environment.GetEnvironmentVariable("BIFROST_RELEASE_SESSION_FIXTURE")
            ?? throw new InvalidOperationException("missing BIFROST_RELEASE_SESSION_FIXTURE");
        try
        {
            Directory.CreateDirectory(installRoot);
            Directory.CreateDirectory(updateRoot);
            Environment.SetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT", installRoot);
            Environment.SetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT", updateRoot);

            using var fixture = JsonDocument.Parse(File.ReadAllBytes(fixturePath));
            var fixtureRoot = fixture.RootElement;
            var envelope = Encoding.UTF8.GetBytes(fixtureRoot.GetProperty("envelope").GetRawText());
            var payloads = fixtureRoot.GetProperty("artifacts").EnumerateArray().ToDictionary(
                item => item.GetProperty("id").GetString()!,
                item => Convert.FromBase64String(item.GetProperty("payload_base64").GetString()!),
                StringComparer.Ordinal);
            var previousState = JsonSerializer.Deserialize<ReleaseStateAuthority.State>(
                fixtureRoot.GetProperty("previous_state").GetRawText())
                ?? throw new InvalidDataException("missing previous release state");
            previousState = previousState with { Checksum = ReleaseStateAuthority.ComputeChecksum(previousState) };
            var statePath = Path.Combine(installRoot, ".bifrost-state", "update-state.json");
            Directory.CreateDirectory(Path.GetDirectoryName(statePath)!);
            File.WriteAllText(statePath, JsonSerializer.Serialize(previousState), new UTF8Encoding(false));

            var authorityBefore = File.ReadAllBytes(statePath);
            using (var discoveryHandler = new RenewedSessionFixtureHandler(envelope, payloads))
            using (var discoveryHttp = new HttpClient(discoveryHandler))
            using (var discovery = new ReleaseUpdateManager(discoveryHttp,
                (baseUri, artifactId) => new Uri(baseUri, "/v1/releases/artifacts/" + Uri.EscapeDataString(artifactId)),
                completeAfterVerifiedDownloads: true))
            {
                var available = discovery.CheckAndStageWithSessionAsync("https://updates.test/",
                    RenewedSessionFixtureHandler.OldToken, CancellationToken.None, CreateProof,
                    (_, _) => Task.FromResult(RenewedSessionFixtureHandler.NewToken), null, stageArtifacts: false)
                    .GetAwaiter().GetResult();
                Require(available.State == "available", "startup discovery must advertise the verified release");
                Require(discoveryHandler.ProtectedArtifactRequests == 0, "discovery must not download artifacts before consent");
                Require(!Directory.EnumerateFileSystemEntries(updateRoot).Any(), "discovery must not create staged files");
                Require(authorityBefore.SequenceEqual(File.ReadAllBytes(statePath)), "discovery must not advance installed authority");
                Console.WriteLine("UPDATE-DISCOVERY PASS verified_manifest=1 artifact_requests=0 authority_unchanged=1");
            }

            using var handler = new RenewedSessionFixtureHandler(envelope, payloads);
            using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var manager = new ReleaseUpdateManager(
                http,
                (baseUri, artifactId) => new Uri(baseUri, "/v1/releases/artifacts/" + Uri.EscapeDataString(artifactId)),
                completeAfterVerifiedDownloads: true);
            var renewalCalls = 0;
            var result = manager.CheckAndStageWithSessionAsync(
                "https://updates.test/",
                RenewedSessionFixtureHandler.OldToken,
                CancellationToken.None,
                CreateProof,
                (rejectedToken, _) =>
                {
                    Require(rejectedToken == RenewedSessionFixtureHandler.OldToken, "renewal must receive the rejected old token");
                    renewalCalls += 1;
                    return Task.FromResult(RenewedSessionFixtureHandler.NewToken);
                }).GetAwaiter().GetResult();

            Require(result.State == "staged", "the formal update entry point must stage the signed release");
            Require(renewalCalls == 1, "a rejected manifest session must renew exactly once");
            Require(handler.ManifestRequests == 2, "manifest must be retried exactly once");
            Require(handler.ProtectedArtifactRequests == payloads.Count, "every signed Windows artifact must be downloaded once");
            Require(handler.RequestedArtifactIds.SetEquals(payloads.Keys), "the formal signed download plan must request every artifact");
            Console.WriteLine($"UPDATE-SESSION-RENEWAL PASS formal_entry=1 manifest_requests=2 renewal_calls=1 protected_requests={payloads.Count}");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"UPDATE-SESSION-RENEWAL FAIL {error}");
            return 1;
        }
        finally
        {
            Environment.SetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT", previousInstall);
            Environment.SetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT", previousUpdate);
            try { if (Directory.Exists(root)) Directory.Delete(root, true); } catch { }
        }
    }

    private static IReadOnlyDictionary<string, string> CreateProof(string token, HttpMethod method, Uri uri, byte[]? body)
    {
        Require(body is null, "GET proof must not include a body");
        var proofBytes = Encoding.UTF8.GetBytes($"{token}\n{method.Method}\n{uri.AbsoluteUri}");
        try
        {
            return new Dictionary<string, string>
            {
                ["X-Bifrost-Proof-Signature"] = Convert.ToHexString(SHA256.HashData(proofBytes)).ToLowerInvariant()
            };
        }
        finally { CryptographicOperations.ZeroMemory(proofBytes); }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class RangeFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        internal RangeFixtureHandler(byte[] payload) => _payload = payload;
        internal bool AllowTail { get; set; }
        internal ConcurrentQueue<long> RequestStarts { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var range = request.Headers.Range?.Ranges.SingleOrDefault() ?? throw new InvalidDataException("missing Range header");
            var start = range.From ?? throw new InvalidDataException("missing range start");
            var end = range.To ?? throw new InvalidDataException("missing range end");
            RequestStarts.Enqueue(start);
            if (!AllowTail && start >= ChunkBytes * 2L) throw new HttpRequestException("TEST-ONLY interrupted tail");
            if (start < 0 || end < start || end >= _payload.LongLength) throw new InvalidDataException("bad test range");
            var length = checked((int)(end - start + 1));
            var bytes = new byte[length];
            Buffer.BlockCopy(_payload, checked((int)start), bytes, 0, length);
            var content = new ByteArrayContent(bytes);
            content.Headers.ContentRange = new ContentRangeHeaderValue(start, end, _payload.LongLength);
            content.Headers.ContentLength = length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content });
        }
    }

    private sealed class ParallelBlobFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        private int _activeRequests;
        private int _fullRequests;
        private int _rangeRequests;
        private int _maxConcurrentRequests;
        private int _sawAuthorization;
        internal ParallelBlobFixtureHandler(byte[] payload) => _payload = payload;
        internal int FullRequests => Volatile.Read(ref _fullRequests);
        internal int RangeRequests => Volatile.Read(ref _rangeRequests);
        internal int MaxConcurrentRequests => Volatile.Read(ref _maxConcurrentRequests);
        internal bool SawAuthorization => Volatile.Read(ref _sawAuthorization) != 0;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization is not null) Interlocked.Exchange(ref _sawAuthorization, 1);
            var active = Interlocked.Increment(ref _activeRequests);
            UpdateMaximum(ref _maxConcurrentRequests, active);
            try
            {
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                var range = request.Headers.Range?.Ranges.SingleOrDefault();
                if (range is null)
                {
                    Interlocked.Increment(ref _fullRequests);
                    var fullContent = new ByteArrayContent(_payload.ToArray());
                    fullContent.Headers.ContentLength = _payload.LongLength;
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = fullContent };
                }

                Interlocked.Increment(ref _rangeRequests);
                var start = range.From ?? throw new InvalidDataException("missing range start");
                var end = range.To ?? throw new InvalidDataException("missing range end");
                var length = checked((int)(end - start + 1));
                var bytes = new byte[length];
                Buffer.BlockCopy(_payload, checked((int)start), bytes, 0, length);
                var content = new ByteArrayContent(bytes);
                content.Headers.ContentRange = new ContentRangeHeaderValue(start, end, _payload.LongLength);
                content.Headers.ContentLength = length;
                return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
            }
            finally { Interlocked.Decrement(ref _activeRequests); }
        }

        private static void UpdateMaximum(ref int target, int candidate)
        {
            int observed;
            while (candidate > (observed = Volatile.Read(ref target)) &&
                   Interlocked.CompareExchange(ref target, candidate, observed) != observed) { }
        }
    }

    private sealed class MirrorFallbackFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        internal MirrorFallbackFixtureHandler(byte[] payload) => _payload = payload;
        private int _preferredRequests;
        private int _fallbackRequests;
        internal int PreferredRequests => Volatile.Read(ref _preferredRequests);
        internal int FallbackRequests => Volatile.Read(ref _fallbackRequests);
        internal bool SawAuthorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SawAuthorization |= request.Headers.Authorization is not null;
            if (string.Equals(request.RequestUri?.Host, "mirror.test", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref _preferredRequests);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }
            Require(string.Equals(request.RequestUri?.Host, "control.test", StringComparison.OrdinalIgnoreCase),
                "fallback request must use the control origin");
            Interlocked.Increment(ref _fallbackRequests);
            var range = request.Headers.Range?.Ranges.SingleOrDefault();
            if (range is null)
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
                redirect.Headers.Location = new Uri("https://mirror.test/v1/releases/blobs/redirected/Bifrost.bin.bin");
                return Task.FromResult(redirect);
            }
            var start = range.From ?? throw new InvalidDataException("missing fallback range start");
            var end = range.To ?? throw new InvalidDataException("missing fallback range end");
            var length = checked((int)(end - start + 1));
            var bytes = new byte[length];
            Buffer.BlockCopy(_payload, checked((int)start), bytes, 0, length);
            var content = new ByteArrayContent(bytes);
            content.Headers.ContentRange = new ContentRangeHeaderValue(start, end, _payload.LongLength);
            content.Headers.ContentLength = length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content });
        }
    }

    private sealed class TransientStatusFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        private readonly ConcurrentDictionary<long, int> _attempts = new();

        internal TransientStatusFixtureHandler(byte[] payload) => _payload = payload;
        internal int AttemptsFor(long start) => _attempts.TryGetValue(start, out var attempts) ? attempts : 0;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var range = request.Headers.Range?.Ranges.SingleOrDefault() ?? throw new InvalidDataException("missing transient Range header");
            var start = range.From ?? throw new InvalidDataException("missing transient range start");
            var end = range.To ?? throw new InvalidDataException("missing transient range end");
            var attempt = _attempts.AddOrUpdate(start, 1, static (_, current) => current + 1);
            if (attempt == 1 && start == 0)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.TooManyRequests));
            if (attempt == 1 && start == ChunkBytes)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            return Task.FromResult(RangeResponse(_payload, start, end));
        }
    }

    private sealed class TrustedRedirectFallbackFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        private int _edgeRedirects;
        private int _mirrorRequests;

        internal TrustedRedirectFallbackFixtureHandler(byte[] payload) => _payload = payload;
        internal int EdgeRedirects => Volatile.Read(ref _edgeRedirects);
        internal int MirrorRequests => Volatile.Read(ref _mirrorRequests);
        internal bool SawAuthorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SawAuthorization |= request.Headers.Authorization is not null;
            var host = request.RequestUri?.Host ?? throw new InvalidDataException("missing redirect host");
            if (string.Equals(host, "mirror.test", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            if (string.Equals(host, "edge.bifrostlog.com", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref _edgeRedirects);
                var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
                response.Headers.Location = new Uri("https://bifrostlog.com" + request.RequestUri!.AbsolutePath);
                return Task.FromResult(response);
            }
            Require(string.Equals(host, "bifrostlog.com", StringComparison.OrdinalIgnoreCase),
                "trusted redirect must terminate at the compiled public mirror");
            Interlocked.Increment(ref _mirrorRequests);
            var range = request.Headers.Range?.Ranges.SingleOrDefault();
            if (range is null)
            {
                var content = new ByteArrayContent(_payload.ToArray());
                content.Headers.ContentLength = _payload.LongLength;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
            }
            var start = range.From ?? throw new InvalidDataException("missing trusted redirect range start");
            var end = range.To ?? throw new InvalidDataException("missing trusted redirect range end");
            return Task.FromResult(RangeResponse(_payload, start, end));
        }
    }

    private sealed class CorruptMirrorFallbackFixtureHandler : HttpMessageHandler
    {
        private readonly byte[] _payload;
        private int _preferredRequests;
        private int _fallbackRequests;

        internal CorruptMirrorFallbackFixtureHandler(byte[] payload) => _payload = payload;
        internal int PreferredRequests => Volatile.Read(ref _preferredRequests);
        internal int FallbackRequests => Volatile.Read(ref _fallbackRequests);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var range = request.Headers.Range?.Ranges.SingleOrDefault();
            if (range is null)
            {
                var full = _payload.ToArray();
                if (string.Equals(request.RequestUri?.Host, "mirror.test", StringComparison.OrdinalIgnoreCase))
                {
                    Interlocked.Increment(ref _preferredRequests);
                    full[0] ^= 0xff;
                }
                else
                {
                    Require(string.Equals(request.RequestUri?.Host, "control.test", StringComparison.OrdinalIgnoreCase),
                        "corrupt-fallback request must use the control origin");
                    Interlocked.Increment(ref _fallbackRequests);
                }
                var fullContent = new ByteArrayContent(full);
                fullContent.Headers.ContentLength = _payload.LongLength;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = fullContent });
            }
            var start = range.From ?? throw new InvalidDataException("missing corrupt-fallback range start");
            var end = range.To ?? throw new InvalidDataException("missing corrupt-fallback range end");
            var response = RangeResponse(_payload, start, end);
            if (string.Equals(request.RequestUri?.Host, "mirror.test", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref _preferredRequests);
                var corrupt = response.Content.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
                corrupt[0] ^= 0xff;
                response.Content.Dispose();
                var corruptContent = new ByteArrayContent(corrupt);
                corruptContent.Headers.ContentRange = new ContentRangeHeaderValue(start, end, _payload.LongLength);
                corruptContent.Headers.ContentLength = corrupt.LongLength;
                response.Content = corruptContent;
                return Task.FromResult(response);
            }
            Require(string.Equals(request.RequestUri?.Host, "control.test", StringComparison.OrdinalIgnoreCase),
                "corrupt-fallback request must use the control origin");
            Interlocked.Increment(ref _fallbackRequests);
            return Task.FromResult(response);
        }
    }

    private static HttpResponseMessage RangeResponse(byte[] payload, long start, long end)
    {
        if (start < 0 || end < start || end >= payload.LongLength) throw new InvalidDataException("bad fixture range");
        var length = checked((int)(end - start + 1));
        var bytes = new byte[length];
        Buffer.BlockCopy(payload, checked((int)start), bytes, 0, length);
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentRange = new ContentRangeHeaderValue(start, end, payload.LongLength);
        content.Headers.ContentLength = length;
        return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
    }

    private sealed class RenewedSessionFixtureHandler : HttpMessageHandler
    {
        internal const string OldToken = "old-token";
        internal const string NewToken = "new-token";
        private readonly byte[] _envelope;
        private readonly IReadOnlyDictionary<string, byte[]> _payloads;
        private readonly object _requestGate = new();

        internal RenewedSessionFixtureHandler(byte[] envelope, IReadOnlyDictionary<string, byte[]> payloads)
        {
            _envelope = envelope;
            _payloads = payloads;
        }
        internal int ManifestRequests { get; private set; }
        internal int ProtectedArtifactRequests { get; private set; }
        internal HashSet<string> RequestedArtifactIds { get; } = new(StringComparer.Ordinal);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var token = request.Headers.Authorization?.Parameter ?? throw new InvalidDataException("missing bearer token");
            var suppliedProof = request.Headers.TryGetValues("X-Bifrost-Proof-Signature", out var values)
                ? values.Single()
                : throw new InvalidDataException("missing proof signature");
            var expectedProof = CreateProof(token, request.Method, request.RequestUri!, null)["X-Bifrost-Proof-Signature"];
            Require(suppliedProof == expectedProof, "proof signature must be bound to the bearer token on the same request");

            if (request.RequestUri!.AbsolutePath == "/v1/releases/manifest")
            {
                ManifestRequests += 1;
                if (ManifestRequests == 1)
                {
                    Require(token == OldToken, "first manifest request must use old-token");
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
                }
                Require(ManifestRequests == 2, "manifest must not be requested more than twice");
                Require(token == NewToken, "retried manifest request must use new-token");
                var content = new ByteArrayContent(_envelope);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
            }

            Require(request.RequestUri.AbsolutePath.StartsWith("/v1/releases/artifacts/", StringComparison.Ordinal), "unexpected request path");
            Require(token == NewToken, "protected artifact must use the renewed token");
            var artifactId = Uri.UnescapeDataString(request.RequestUri.AbsolutePath["/v1/releases/artifacts/".Length..]);
            if (!_payloads.TryGetValue(artifactId, out var payload))
                throw new InvalidDataException("requested artifact must come from the signed plan");
            var range = request.Headers.Range?.Ranges.SingleOrDefault() ?? throw new InvalidDataException("missing artifact range");
            var start = range.From ?? throw new InvalidDataException("missing range start");
            var end = range.To ?? throw new InvalidDataException("missing range end");
            Require(start == 0 && end == payload.LongLength - 1, "protected artifact range must cover the payload");
            lock (_requestGate)
            {
                Require(RequestedArtifactIds.Add(artifactId), "each protected artifact must be requested exactly once");
                ProtectedArtifactRequests += 1;
            }
            var artifactContent = new ByteArrayContent(payload.ToArray());
            artifactContent.Headers.ContentRange = new ContentRangeHeaderValue(start, end, payload.LongLength);
            artifactContent.Headers.ContentLength = payload.LongLength;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = artifactContent });
        }
    }
}
