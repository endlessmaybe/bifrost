using System.IO;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Bifrost.ClientService;

namespace Bifrost.Release;

/// <summary>
/// Native Windows release verifier/stager. It verifies signed raw manifest
/// bytes, streams artifacts to a same-volume staging tree, and only writes a
/// pending marker. The external updater promotes the tree and advances the
/// installed sequence after service restart and health checks.
/// </summary>
public sealed class ReleaseUpdateManager : IDisposable
{
    private const string Format = "BIFROST-RELEASE-MANIFEST-2";
    private const long MaxArtifactBytes = 512L * 1024 * 1024;
    private const int MaxManifestBytes = 1 * 1024 * 1024;
    // The Windows client may sit behind an existing local full-tunnel/proxy.
    // Four-megabyte authenticated ranges amortize TLS/proxy overhead without
    // making a retry throw away a large response. Four artifacts and two
    // ordered ranges per artifact may be in flight, which lets a remote client
    // fill a faster link without buffering more than roughly 32 MiB of payload.
    private const int ArtifactChunkBytes = 4 * 1024 * 1024;
    // Release artifacts are independently hashed and resumable. Use more of
    // the host/network on higher-core machines without allowing unbounded
    // parallel downloads on very large systems.
    private static readonly int MaxParallelArtifactDownloads = Math.Clamp(Environment.ProcessorCount, 4, 12);
    private const int MaxParallelChunksPerArtifact = 2;
    private const int ArtifactChunkAttempts = 5;
    private static readonly TimeSpan ArtifactResponseHeaderTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ArtifactReadIdleTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ManifestCheckTimeout = TimeSpan.FromSeconds(30);
    private const string CurrentClientVersion = "2.2.63";
    // The authenticated manifest remains on the control origin. Immutable
    // content-addressed blobs are served from the operator's release mirror so
    // large client/service/core updates do not depend on the workstation's
    // upload path through Cloudflare Tunnel. Every byte is still size- and
    // SHA-256-bound by the signed manifest before it can be staged.
    private static readonly Uri ReleaseBlobBaseUri = RequireCanonicalOrigin(new Uri("https://bifrostlog.com"));
    private interface IReleaseTrustRoot
    {
        string KeyId { get; }
        string? Pem { get; }
        string? Fingerprint { get; }
        bool Provisioned { get; }
    }

    private sealed class CompiledReleaseTrustRoot : IReleaseTrustRoot
    {
        public string KeyId => ReleaseContract.TrustRootKeyId;
        public string? Pem => ReleaseContract.TrustRootPem;
        public string? Fingerprint => ReleaseContract.TrustRootFingerprint;
        public bool Provisioned => ReleaseContract.TrustRootProvisioned;
    }

    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly string _token;
    private readonly string _statePath;
    private readonly string _updateRoot;
    private readonly string _installRoot;
    private readonly bool _installedLayout;
#if BIFROST_TEST_HARNESS
    private Func<Uri, string, Uri>? _harnessArtifactUriResolver;
    private bool _harnessCompleteAfterVerifiedDownloads;
#endif

    public ReleaseUpdateManager(HttpClient? http = null)
    {
        // Every release request owns an explicit bounded deadline below. A
        // shorter HttpClient-wide timeout used to cancel healthy large Range
        // responses before the updater's retry/idle policy could decide.
        _http = http ?? new HttpClient(new BifrostControlRelayHandler(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseDefaultCredentials = false,
            // Release transport must follow the same OS proxy policy as the
            // control plane.  The update remains fail-closed because TLS,
            // root/delegation signatures, manifest identity and every
            // artifact SHA-256 are verified independently of the proxy.
            UseProxy = true,
            DefaultProxyCredentials = null
        }))
        {
            Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower
        };
        _baseUrl = (Environment.GetEnvironmentVariable("BIFROST_CONTROL_BASE_URL") ?? string.Empty).TrimEnd('/');
        _token = Environment.GetEnvironmentVariable("BIFROST_DEVICE_TOKEN") ?? string.Empty;
        // Promotion state is installation-owned. A mutable environment value
        // must not redirect release staging into a user-controlled tree.
        _updateRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "updates");
#if BIFROST_TEST_HARNESS
        // Native updater E2E tests need production cryptographic semantics
        // without mutating Program Files/ProgramData on the developer machine.
        // These overrides do not exist in shipping builds and are restricted
        // to the OS temporary directory.
        var testUpdateRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT");
        var testInstallRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT");
        if (!string.IsNullOrWhiteSpace(testUpdateRoot) || !string.IsNullOrWhiteSpace(testInstallRoot))
        {
            if (string.IsNullOrWhiteSpace(testUpdateRoot) || string.IsNullOrWhiteSpace(testInstallRoot)) throw new InvalidOperationException("BF-RELEASE-TEST-ROOT");
            _updateRoot = RequireTemporaryHarnessRoot(testUpdateRoot);
            _installRoot = RequireTemporaryHarnessRoot(testInstallRoot);
            _installedLayout = true;
        }
        else
        {
            _installRoot = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory);
            _installedLayout = true;
        }
#else
        // Shipping update authority follows the generation that is actually
        // running. This keeps custom E:/D:/... installs coherent and prevents
        // a valid client installed outside Program Files from staging state
        // against an unrelated C:\Program Files\Bifrost tree.
        //
        // A release payload can also be inspected or launched before the
        // installer moves it into .bifrost-generations\g-*.  That is not an
        // update-authority layout, but it must not make the whole WPF process
        // die during MainWindow construction.  Keep the UI usable while
        // disabling release staging; the actual updater/service boundary still
        // requires the strict installed-generation layout below.
        try
        {
            _installRoot = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory);
            _installedLayout = true;
        }
        catch (InvalidDataException ex) when (string.Equals(ex.Message, "BF-INSTALL-LAYOUT", StringComparison.Ordinal))
        {
            _installRoot = string.Empty;
            _installedLayout = false;
        }
#endif
        _statePath = _installedLayout ? Path.Combine(_installRoot, ".bifrost-state", "update-state.json") : string.Empty;
    }

#if BIFROST_TEST_HARNESS
    internal ReleaseUpdateManager(
        HttpClient http,
        Func<Uri, string, Uri> artifactUriResolver,
        bool completeAfterVerifiedDownloads) : this(http)
    {
        _harnessArtifactUriResolver = artifactUriResolver ?? throw new ArgumentNullException(nameof(artifactUriResolver));
        _harnessCompleteAfterVerifiedDownloads = completeAfterVerifiedDownloads;
    }
#endif

#if BIFROST_TEST_HARNESS
    private static string RequireTemporaryHarnessRoot(string value)
    {
        var full = Path.GetFullPath(value);
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) || string.Equals(full.TrimEnd(Path.DirectorySeparatorChar), temp.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("BF-RELEASE-TEST-ROOT");
        return full;
    }
#endif

    public static ReleaseUpdateManager FromEnvironment() => new();

    public Task<ReleaseCheckResult> CheckAndStageAsync(CancellationToken cancellationToken = default) =>
        CheckAndStageCoreAsync(_baseUrl, _token, cancellationToken, progress: null);

    /// <summary>
    /// Use the authenticated control-plane session held by the native client.
    /// Environment variables remain a headless/service fallback, but the WPF
    /// application never needs a second manually provisioned token.
    /// </summary>
    public Task<ReleaseCheckResult> CheckAndStageWithSessionAsync(
        string baseUrl,
        string token,
        CancellationToken cancellationToken = default,
        IProgress<ReleaseUpdateProgress>? progress = null) =>
        CheckAndStageCoreAsync(baseUrl, token, cancellationToken, progress);

    public Task<ReleaseCheckResult> CheckAndStageWithSessionAsync(
        string baseUrl,
        string token,
        CancellationToken cancellationToken,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>> proofFactory,
        IProgress<ReleaseUpdateProgress>? progress = null) =>
        CheckAndStageCoreAsync(baseUrl, token, cancellationToken, progress,
            (_, method, uri, body) => proofFactory(method, uri, body));

    /// <summary>
    /// Checks with a native device session and, for the replay-safe manifest GET
    /// only, renews a session rejected by the control plane before retrying once.
    /// </summary>
    public Task<ReleaseCheckResult> CheckAndStageWithSessionAsync(
        string baseUrl,
        string token,
        CancellationToken cancellationToken,
        Func<string, HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>> proofFactory,
        Func<string, CancellationToken, Task<string>> renewSession,
        IProgress<ReleaseUpdateProgress>? progress = null,
        bool stageArtifacts = true) =>
        CheckAndStageCoreAsync(baseUrl, token, cancellationToken, progress, proofFactory, renewSession, stageArtifacts);

    private async Task<ReleaseCheckResult> CheckAndStageCoreAsync(
        string? baseUrlText,
        string? tokenText,
        CancellationToken cancellationToken,
        IProgress<ReleaseUpdateProgress>? progress,
        Func<string, HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory = null,
        Func<string, CancellationToken, Task<string>>? renewSession = null,
        bool stageArtifacts = true)
    {
        // A loose payload may run for inspection and can still use the normal
        // control/service UI, but it has no installation-owned update state.
        // Never derive or invent an install root for it.
        if (!_installedLayout)
            return ReleaseCheckResult.Disabled("BF-INSTALL-LAYOUT");

        // Discovery is a network wait, not measurable download work. Keep it
        // indeterminate in the UI instead of presenting a fake 4% that can
        // appear frozen while the manifest endpoint is unreachable.
        progress?.Report(new ReleaseUpdateProgress(0, "checking", "正在检查可用版本"));
#if false
        if (!Uri.TryCreate((baseUrlText ?? string.Empty).TrimEnd('/'), UriKind.Absolute, out var baseUri) || string.IsNullOrEmpty(tokenText))
            return ReleaseCheckResult.Disabled("BIFROST_CONTROL_BASE_URL/BIFROST_DEVICE_TOKEN 未配置");
        #endif
        if (!Uri.TryCreate((baseUrlText ?? string.Empty).TrimEnd('/'), UriKind.Absolute, out var baseUri) || string.IsNullOrEmpty(tokenText))
            return ReleaseCheckResult.Disabled("BF-RELEASE-CONTROL-NOT-CONFIGURED");
        baseUri = RequireCanonicalOrigin(baseUri);
        var activeSessionToken = tokenText;

        var manifestFetch = await FetchManifestWithSessionRenewalAsync(
            baseUri, activeSessionToken, proofFactory, renewSession, cancellationToken).ConfigureAwait(false);
        activeSessionToken = manifestFetch.ActiveSessionToken;
        if (manifestFetch.NotFound)
        {
            progress?.Report(new ReleaseUpdateProgress(100, "unavailable", "当前没有可用的新版本"));
            return ReleaseCheckResult.NoRelease("签名发布尚未提供");
        }
        progress?.Report(new ReleaseUpdateProgress(10, "verifying", "正在验证发布清单"));
        var envelopeBytes = manifestFetch.EnvelopeBytes;
        var previousAuthority = ReadAuthorityState(_statePath);
        var envelope = VerifyEnvelopeCore(envelopeBytes, new CompiledReleaseTrustRoot(), expectedChannel: null, currentClientVersion: CurrentClientVersion, currentConfigVersion: 1, previousAuthority: previousAuthority);
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-RELEASE-PLAN");
        progress?.Report(new ReleaseUpdateProgress(18, "verified", "发布签名验证完成"));
        var classification = ReleaseStateAuthority.Classify(previousAuthority?.Sequence, previousAuthority?.ManifestDigest, envelope.Sequence, plan.ManifestDigest, plan.Floor);
        if (classification == "idempotent")
        {
            progress?.Report(new ReleaseUpdateProgress(100, "current", "已经是最新版本"));
            return ReleaseCheckResult.UpToDate(envelope.Sequence);
        }
        if (classification is "rollback" or "equivocation") throw new InvalidDataException(classification == "equivocation" ? "BF-RELEASE-EQUIVOCATION" : "BF-RELEASE-ROLLBACK");
        if (previousAuthority is not null)
        {
            if (plan.AuthorityGeneration < previousAuthority.AuthorityGeneration) throw new InvalidDataException("BF-RELEASE-AUTHORITY-ROLLBACK");
            if (plan.AuthorityGeneration == previousAuthority.AuthorityGeneration && !string.Equals(plan.AuthorityDigest, previousAuthority.AuthorityDigest, StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-AUTHORITY-EQUIVOCATION");
            if (plan.AuthorityGeneration > previousAuthority.AuthorityGeneration && !string.Equals(plan.SigningKeyFingerprint, previousAuthority.SigningKeyFingerprint, StringComparison.Ordinal) && !plan.HasTransition) throw new InvalidDataException("BF-RELEASE-TRANSITION");
            if (plan.HasTransition)
            {
                using var transitionDocument = ParseStrictJson(envelopeBytes, 32);
                var transition = transitionDocument.RootElement.GetProperty("transition_signature");
                if (!string.Equals(FingerprintPem(transition.GetProperty("old_public_key_pem").GetString()!), previousAuthority.SigningKeyFingerprint, StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-TRANSITION");
            }
        }
        /* legacy disabled-environment branch intentionally removed
            return ReleaseCheckResult.Verified(envelope.Sequence, "发布已验签；等待外部更新器配置");

        */
        // Discovery has already verified signature, compatibility and all
        // anti-rollback authority checks. Do not download or change the local
        // release floor until the user accepts this available release.
        if (!stageArtifacts)
            return new ReleaseCheckResult("available", envelope.Sequence, "发现已验证的新版本", null);
        var root = Path.GetFullPath(_updateRoot);
        Directory.CreateDirectory(root);
        var stage = Path.Combine(root, $".update-staging-{envelope.Sequence}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stage);
        try
        {
            var selected = (plan?.Artifacts ?? throw new InvalidDataException("BF-RELEASE-PLAN"))
                .Where(a => a.Platform == "windows" && a.Arch == "x64" && (a.Kind == "exe" || a.Kind == "service-exe" || a.Kind == "installer" || a.Kind == "core" || a.Kind == "core-manifest" || a.Kind == "metadata"))
                .ToArray();
            var unsupportedWindows = plan.Artifacts.Where(a => a.Platform == "windows" && a.Arch == "x64" && a.Kind != "source" && a.Kind != "notice" && a.Kind != "exe" && a.Kind != "service-exe" && a.Kind != "installer" && a.Kind != "core" && a.Kind != "core-manifest" && a.Kind != "metadata").ToArray();
            if (unsupportedWindows.Length != 0) throw new InvalidDataException("BF-RELEASE-WINDOWS-SET");
            var windowsIds = selected.Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
            if (!ReleaseArtifactPolicy.IsWindowsX64Stable(windowsIds))
                throw new InvalidDataException("BF-RELEASE-WINDOWS-SET");
            var selectedKinds = selected.GroupBy(a => a.Kind, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count());
            if (selected.Length != 8 || selectedKinds.GetValueOrDefault("exe") != 1 || selectedKinds.GetValueOrDefault("service-exe") != 1 || selectedKinds.GetValueOrDefault("installer") != 1 || selectedKinds.GetValueOrDefault("core-manifest") != 1 || selectedKinds.GetValueOrDefault("metadata") != 1 || selectedKinds.GetValueOrDefault("core") != 3)
                throw new InvalidDataException("BF-RELEASE-WINDOWS-SET");
#if false
            if (selected.Length == 0) throw new InvalidDataException("发布缺少 Windows x64 客户端构件");
            #endif
            if (selected.Length == 0) throw new InvalidDataException("BF-RELEASE-WINDOWS-EMPTY");
            var totalArtifactBytes = selected.Sum(artifact => artifact.Bytes);
            long downloadedArtifactBytes = 0;
            var completedArtifacts = 0;
            progress?.Report(new ReleaseUpdateProgress(20, "downloading", $"发现新版本，准备下载 {selected.Length} 个组件"));
            var stageRoot = Path.GetFullPath(stage).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var cacheRoot = Path.Combine(root, "download-cache", $"v{envelope.Sequence}-{plan.ManifestDigest[..16]}");
            Directory.CreateDirectory(cacheRoot);
            var downloads = selected.Select((artifact, index) =>
            {
                var relative = SafeRelative(artifact.Path);
                if (!relative.StartsWith("windows-app/", StringComparison.Ordinal) && !relative.StartsWith("windows-service/", StringComparison.Ordinal) && !relative.StartsWith("windows-installer/", StringComparison.Ordinal) &&
                    !(artifact.Kind == "metadata" && string.Equals(relative, "install-metadata.json", StringComparison.Ordinal)) &&
                    !(artifact.Kind == "installer" && string.Equals(relative, "BifrostSetup.exe", StringComparison.Ordinal)))
                    throw new InvalidDataException($"Windows artifact path is outside the client payload: {relative}");
                // Content-addressed blobs are immutable and cacheable at the
                // edge. The authenticated signed manifest remains the only
                // authority for the path, size and SHA-256; the .bin suffix
                // makes every artifact eligible under the CDN's static-file
                // policy regardless of its original .json/.dat extension.
                var blobPath = "/v1/releases/blobs/" + artifact.Sha256 + "/" +
                    Uri.EscapeDataString(Path.GetFileName(relative) + ".bin");
                var artifactUri = new Uri(ReleaseBlobBaseUri, blobPath);
                var fallbackUri = new Uri(baseUri, blobPath);
#if BIFROST_TEST_HARNESS
                if (_harnessArtifactUriResolver is not null)
                {
                    artifactUri = _harnessArtifactUriResolver(baseUri, artifact.Id);
                    fallbackUri = artifactUri;
                }
#endif
                var installRelative = SafeRelative(artifact.InstallPath ?? relative);
                var destination = Path.Combine(stage, installRelative.Replace('/', Path.DirectorySeparatorChar));
                if (!Path.GetFullPath(destination).StartsWith(stageRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("release install path escapes staging tree");
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                var resumePath = Path.Combine(cacheRoot, $"{index:D2}-{artifact.Sha256}-{artifact.Bytes}.part");
                return (Artifact: artifact, Uri: artifactUri, FallbackUri: fallbackUri, Destination: destination, ResumePath: resumePath);
            }).ToArray();
            using (var downloadSlots = new SemaphoreSlim(MaxParallelArtifactDownloads, MaxParallelArtifactDownloads))
            {
                var tasks = downloads.Select(async download =>
                {
                    await downloadSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        await DownloadAndVerifyArtifactWithFallbackAsync(download.Uri, download.FallbackUri, activeSessionToken!,
                            proofFactory is null ? null : (method, uri, body) => proofFactory(activeSessionToken!, method, uri, body),
                            download.Destination,
                            download.ResumePath, download.Artifact, cancellationToken, delta =>
                            {
                                var currentBytes = Interlocked.Add(ref downloadedArtifactBytes, delta);
                                var fraction = totalArtifactBytes <= 0 ? 1d : Math.Clamp((double)currentBytes / totalArtifactBytes, 0d, 1d);
                                var percent = 20 + (int)Math.Round(fraction * 72d, MidpointRounding.AwayFromZero);
                                progress?.Report(new ReleaseUpdateProgress(percent, "downloading",
                                    $"正在下载更新 · {Volatile.Read(ref completedArtifacts)}/{selected.Length} 个组件完成"));
                            }).ConfigureAwait(false);
                        Interlocked.Increment(ref completedArtifacts);
                    }
                    finally { downloadSlots.Release(); }
                }).ToArray();
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            if (!Directory.EnumerateFiles(stage, "*", SearchOption.AllDirectories).Any()) throw new InvalidDataException("发布不包含 Windows 构件");
            progress?.Report(new ReleaseUpdateProgress(94, "finalizing", "下载完成，正在校验并准备安装"));
#if BIFROST_TEST_HARNESS
            // This test-only stop occurs after the public production entry
            // point has verified the signed plan and traversed the real
            // concurrent download loop. Installer ownership and DPAPI
            // promotion are covered by the dedicated installer tests.
            if (_harnessCompleteAfterVerifiedDownloads)
                return ReleaseCheckResult.Staged(envelope.Sequence, stage);
#endif
            var stageIdentity = ComputeStageIdentity(selected, stage);
            var expectedInstallId = ReadInstallIdForPendingOperation();
            var expectedPointerDigest = DigestFileForPendingOperation(Path.Combine(_installRoot, ".bifrost-state", "current.json"));
            var authority = previousAuthority ?? throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
            // Keep the marker minimal and untrusted. Sequence, artifacts and
            // durable state are recovered from the signed manifest by the
            // trusted promoter, never from marker fields.
            var operationId = $"rel-{Guid.NewGuid():N}";
            var operation = new PendingOperationRecord(
                operationId,
                envelope.Plan?.EnvelopeDigest ?? throw new InvalidDataException("BF-RELEASE-PLAN"),
                envelope.Plan.ManifestDigest,
                envelope.Plan.AllowlistDigest,
                envelope.Sequence,
                envelope.Plan.Floor,
                envelope.Plan.AuthorityGeneration,
                envelope.Plan.AuthorityDigest ?? throw new InvalidDataException("BF-RELEASE-AUTHORITY"),
                 string.Join("\n", selected.Select(artifact => artifact.Id).OrderBy(id => id, StringComparer.Ordinal)),
                stage,
                Path.GetFullPath(_updateRoot),
                 Path.GetFullPath(_installRoot),
                 authority.Sequence,
                 stageIdentity,
                 ReadCurrentGenerationForPendingOperation(),
                 authority.EnvelopeDigest,
                 authority.ManifestDigest,
                 authority.AuthorityGeneration,
                 authority.AuthorityDigest,
                 expectedPointerDigest,
                 expectedInstallId);
            var protectedOperation = ProtectPendingOperation(operation);
            var pending = new
            {
                operation_id = operationId,
                manifest_text = envelope.ManifestText,
                signature = envelope.SignatureText,
                envelope_bytes_b64 = Convert.ToBase64String(envelopeBytes),
                envelope_digest = envelope.Plan?.EnvelopeDigest,
                manifest_digest = envelope.Plan?.ManifestDigest,
                allowlist_digest = envelope.Plan?.AllowlistDigest,
                root_key_id = envelope.Plan?.RootKeyId,
                root_fingerprint = envelope.Plan?.RootFingerprint,
                authority_digest = envelope.Plan?.AuthorityDigest,
                authority_generation = envelope.Plan?.AuthorityGeneration,
                delegation_generation = envelope.Plan?.DelegationGeneration,
                signing_key_id = envelope.Plan?.SigningKeyId,
                channel = envelope.Plan?.Channel,
                rollback_floor = envelope.Plan?.Floor,
                plan = envelope.Plan,
                stage_directory = stage,
                protected_operation = Convert.ToBase64String(protectedOperation)
            };
            try { WriteAtomic(Path.Combine(root, "update-pending.json"), JsonSerializer.Serialize(pending)); }
            finally { CryptographicOperations.ZeroMemory(protectedOperation); }
            // A fully verified staging tree is now authoritative. Partial
            // cache files are retained only across failed/interrupted checks.
            try { if (Directory.Exists(cacheRoot)) Directory.Delete(cacheRoot, true); } catch { }
            progress?.Report(new ReleaseUpdateProgress(100, "staged", "更新已下载并验证，等待安全安装"));
            return ReleaseCheckResult.Staged(envelope.Sequence, stage);
        }
        catch
        {
            if (Directory.Exists(stage)) Directory.Delete(stage, true);
            throw;
        }
    }

    private async Task<ManifestFetchResult> FetchManifestWithSessionRenewalAsync(
        Uri baseUri,
        string initialSessionToken,
        Func<string, HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        Func<string, CancellationToken, Task<string>>? renewSession,
        CancellationToken cancellationToken)
    {
        var activeSessionToken = initialSessionToken;
        using var manifestDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        manifestDeadline.CancelAfter(ManifestCheckTimeout);
        try
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var response = await SendAuthenticatedManifestRequestAsync(
                    baseUri, activeSessionToken, proofFactory, manifestDeadline.Token).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.Unauthorized && attempt == 0 && renewSession is not null)
                {
                    activeSessionToken = await renewSession(activeSessionToken, manifestDeadline.Token).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(activeSessionToken)) throw new InvalidOperationException("BF-AUTH-SESSION");
                    continue;
                }
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return new ManifestFetchResult(Array.Empty<byte>(), activeSessionToken, NotFound: true);
                EnsureSuccessfulResponse(response, requireJson: true);
                var envelopeBytes = await ReadLimitedAsync(response.Content, MaxManifestBytes, manifestDeadline.Token).ConfigureAwait(false);
                return new ManifestFetchResult(envelopeBytes, activeSessionToken, NotFound: false);
            }
            throw new InvalidOperationException("BF-AUTH-SESSION");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && manifestDeadline.IsCancellationRequested)
        {
            throw new TimeoutException("BF-RELEASE-CHECK-TIMEOUT");
        }
    }

    private async Task<HttpResponseMessage> SendAuthenticatedManifestRequestAsync(
        Uri baseUri,
        string sessionToken,
        Func<string, HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, "/v1/releases/manifest"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sessionToken);
        // Version routing is advisory only; the signed envelope remains the
        // authority.  Reporting the real client version lets Control keep a
        // compatibility lane for old activated devices without guessing from
        // a fixed User-Agent string.
        request.Headers.TryAddWithoutValidation("X-Bifrost-Client-Version", CurrentClientVersion);
        // The proof hashes the exact bearer token on this request. It must not
        // read mutable shared session state after Authorization is selected.
        AddProofHeaders(request, proofFactory?.Invoke(sessionToken, HttpMethod.Get, request.RequestUri!, null));
        return await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private sealed record ManifestFetchResult(byte[] EnvelopeBytes, string ActiveSessionToken, bool NotFound);

    private static void AddProofHeaders(HttpRequestMessage request, IReadOnlyDictionary<string, string>? proof)
    {
        if (proof is null) return;
        foreach (var pair in proof) request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
    }

    public static VerifiedEnvelope VerifyEnvelope(byte[] envelopeBytes) => VerifyEnvelopeCore(envelopeBytes, new CompiledReleaseTrustRoot(), expectedChannel: null, currentClientVersion: CurrentClientVersion, currentConfigVersion: 1, previousAuthority: null);

    // Installer/apply path: the previous authority is read from its
    // protected installation state before this entry point is called.  This
    // keeps the verifier/state transition identical to the client updater
    // instead of validating a new envelope in isolation.
    internal static VerifiedEnvelope VerifyEnvelopeForInstaller(byte[] envelopeBytes, ReleaseStateAuthority.State previousAuthority, string? expectedChannel = null, long? currentConfigVersion = 1) =>
        VerifyEnvelopeCore(envelopeBytes, new CompiledReleaseTrustRoot(), expectedChannel, CurrentClientVersion, currentConfigVersion, previousAuthority);

    // Clients released before the protected-operation transaction shipped the
    // already verified manifest/signature pair, but not the public delegation
    // and key-state records. The current installer embeds those public ceremony
    // records and reconstructs the same full envelope before using the normal
    // production verifier. No raw-key or signature-only authority is accepted.
    internal static VerifiedEnvelope VerifyLegacyBridgeForInstaller(
        string manifestText,
        string signatureText,
        string delegationText,
        string keyStateText,
        ReleaseStateAuthority.State previousAuthority) =>
        VerifyEnvelopeCore(
            BuildLegacyBridgeEnvelope(manifestText, signatureText, delegationText, keyStateText),
            new CompiledReleaseTrustRoot(),
            expectedChannel: null,
            currentClientVersion: CurrentClientVersion,
            currentConfigVersion: 1,
            previousAuthority);

    private static byte[] BuildLegacyBridgeEnvelope(string manifestText, string signatureText, string delegationText, string keyStateText)
    {
        if (string.IsNullOrEmpty(manifestText) || manifestText.Length > MaxManifestBytes || signatureText.Length != 86)
            throw new InvalidDataException("BF-RELEASE-ENVELOPE-SHAPE");
        using var delegationDocument = ParseStrictJson(Encoding.UTF8.GetBytes(delegationText), 16);
        using var keyStateDocument = ParseStrictJson(Encoding.UTF8.GetBytes(keyStateText), 16);
        var delegation = delegationDocument.RootElement;
        var keyState = keyStateDocument.RootElement;
        RequireExactFields(delegation,
            new[] { "activation_sequence", "algorithm", "channel", "generation", "key_id", "public_key_fingerprint", "public_key_pem", "purpose", "retirement_sequence", "root_key_id", "root_signature" },
            new[] { "activation_sequence", "algorithm", "channel", "generation", "key_id", "public_key_fingerprint", "public_key_pem", "purpose", "retirement_sequence", "root_key_id", "root_signature" });
        RequireExactFields(keyState,
            new[] { "active_key_ids", "channel", "generation", "revoked_key_ids", "root_key_id", "signature" },
            new[] { "active_key_ids", "channel", "generation", "revoked_key_ids", "root_key_id", "signature" });
        var delegationFields = delegation.EnumerateObject()
            .Where(property => property.Name != "root_signature")
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            manifest_text = manifestText,
            signature = signatureText,
            delegation = delegationFields,
            root_signature = delegation.GetProperty("root_signature").GetString(),
            key_state = keyState.Clone()
        });
    }

    // Narrow contract seams used by the isolated cross-language corpus. They
    // delegate to the same strict parser/path policy as the shipping updater;
    // no trust material or alternate envelope authority is exposed.
    internal static void ValidateStrictJsonForContract(byte[] bytes) { using var _ = ParseStrictJson(bytes, 32); }
    internal static void ValidateCanonicalJsonForContract(byte[] bytes)
    {
        using var _ = ParseStrictJson(bytes, 32);
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 32 });
        while (reader.Read())
        {
            if (reader.TokenType != JsonTokenType.Number) continue;
            if (!reader.TryGetInt64(out var integer) || !Regex.IsMatch(Encoding.UTF8.GetString(reader.ValueSpan), "^(?:0|-?[1-9][0-9]*)$", RegexOptions.CultureInvariant) || integer > int.MaxValue || integer < int.MinValue)
                throw new InvalidDataException("BF-RELEASE-FIELDS");
        }
    }
    internal static string ValidateReleasePathForContract(string value) => SafeRelative(value);
    internal static void ValidateDownloadStatusForContract(int status)
    {
        if (status is >= 300 and < 400) throw new InvalidDataException("BF-RELEASE-REDIRECT");
        if (status is not (200 or 204 or 206)) throw new InvalidDataException("BF-RELEASE-HTTP");
    }

#if BIFROST_TEST_HARNESS
    // Isolated installer test-harness compatibility for the pre-ceremony
    // compact manifest fixture.  This source is compiled only into the
    // explicitly requested test harness; no shipping app/service/installer
    // assembly contains a raw-key or compact-envelope verifier.
    internal static VerifiedEnvelope VerifyEnvelopeForHarness(byte[] envelopeBytes, string fixtureRootPem)
    {
        if (string.IsNullOrWhiteSpace(fixtureRootPem)) throw new InvalidDataException("BF-RELEASE-TRUST-ROOT");
        using var document = ParseStrictJson(envelopeBytes, 32); var root = document.RootElement;
        RequireExactFields(root, new[] { "manifest_text", "signature" }, new[] { "manifest_text", "signature" });
        var manifestText = root.GetProperty("manifest_text").GetString() ?? throw new InvalidDataException("BF-RELEASE-MANIFEST-MISSING");
        var signatureText = root.GetProperty("signature").GetString() ?? string.Empty;
        var payload = new UTF8Encoding(false, true).GetBytes(manifestText); var signature = FromBase64Url(signatureText); var rawKey = ExtractRawPublicKey(fixtureRootPem);
        try
        {
            if (signature.Length != 64 || !Ed25519.Verify(signature, payload, rawKey)) throw new CryptographicException("BF-RELEASE-SIGNATURE");
            using var manifest = ParseStrictJson(payload, 32); var m = manifest.RootElement; var build = RequireObject(m, "build"); var artifactArray = build.GetProperty("artifacts");
            var artifacts = new List<Artifact>(); foreach (var item in artifactArray.EnumerateArray()) artifacts.Add(new Artifact(ReadRequiredString(item, "path"), item.TryGetProperty("install_path", out var install) ? install.GetString() : null, ReadRequiredString(item, "platform"), ReadRequiredString(item, "arch"), ReadRequiredString(item, "kind"), ReadRequiredPositiveInt64(item, "bytes"), ReadRequiredString(item, "sha256"), item.TryGetProperty("source_bundle", out var sourceBundle) ? sourceBundle.GetString() : null, item.TryGetProperty("notice", out var notice) ? notice.GetString() : null, item.TryGetProperty("dependencies", out var deps) && deps.ValueKind == JsonValueKind.Array ? deps.EnumerateArray().Select(value => value.GetString() ?? string.Empty).ToArray() : Array.Empty<string>(), item.TryGetProperty("id", out var itemId) && itemId.ValueKind == JsonValueKind.String ? itemId.GetString() : null));
            var manifestDigest = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(); var envelopeDigest = Convert.ToHexString(SHA256.HashData(envelopeBytes)).ToLowerInvariant(); var allowlistDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson(artifactArray)))).ToLowerInvariant();
            var sequence = ReadRequiredPositiveInt64(m, "release_sequence"); var plan = new VerifiedReleasePlan(envelopeDigest, manifestDigest, allowlistDigest, sequence, m.TryGetProperty("channel", out var channel) ? channel.GetString() : "test", m.TryGetProperty("rollback_floor", out var floor) && floor.TryGetInt64(out var floorValue) ? floorValue : 1, null, null, null, 0, 1, m.TryGetProperty("signing_key_id", out var key) ? key.GetString() : null, null, false, artifacts.ToArray());
            return new VerifiedEnvelope(sequence, manifestText, signatureText, artifacts, plan);
        }
        finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(signature); CryptographicOperations.ZeroMemory(rawKey); }
    }

    private sealed class TestReleaseTrustRoot : IReleaseTrustRoot
    {
        private readonly string _pem;
        public TestReleaseTrustRoot(string pem) => _pem = string.IsNullOrWhiteSpace(pem) ? throw new InvalidDataException("BF-RELEASE-TRUST-ROOT") : pem;
        public string KeyId => "bifrost-root-v1";
        public string? Pem => _pem;
        public string? Fingerprint => FingerprintPem(_pem);
        public bool Provisioned => true;
    }

    internal static VerifiedEnvelope VerifyEnvelopeForCorpus(byte[] envelopeBytes, string fixtureRootPem, string? expectedChannel = null, string? currentClientVersion = "0.1.0", long? currentConfigVersion = 0, long previousSequence = 0, string? previousManifestDigest = null, long previousAuthorityGeneration = 0, string? previousAuthorityDigest = null, string? previousSigningKeyId = null, string? previousSigningKeyFingerprint = null)
    {
        ReleaseStateAuthority.State? previous = null;
        if (previousSequence > 0 || previousAuthorityGeneration > 0)
        {
            var candidate = new ReleaseStateAuthority.State(previousSequence, previousManifestDigest ?? throw new InvalidDataException("BF-RELEASE-STATE"), new string('0', 64), previousAuthorityDigest ?? throw new InvalidDataException("BF-RELEASE-STATE"), previousAuthorityGeneration, "bifrost-root-v1", new string('0', 64), 1, previousSigningKeyId ?? "bifrost-release-v1", previousSigningKeyFingerprint ?? new string('0', 64), expectedChannel ?? "test", 1, 1, "a", string.Empty, "2026-01-01T00:00:00.000Z");
            previous = candidate with { Checksum = ReleaseStateAuthority.ComputeChecksum(candidate) };
        }
        return VerifyEnvelopeCore(envelopeBytes, new TestReleaseTrustRoot(fixtureRootPem), expectedChannel, currentClientVersion, currentConfigVersion, previous, allowTestOnlyShape: true);
    }

    // Test-only compiled-binding fixture. It reaches the same production
    // parser, authority checks and plan builder; only the trust provider is
    // replaced by the isolated TEST binding at compile time.
    internal static VerifiedEnvelope VerifyEnvelopeForInstallerTest(byte[] envelopeBytes, string fixtureRootPem, ReleaseStateAuthority.State previousAuthority) =>
        VerifyEnvelopeCore(envelopeBytes, new TestReleaseTrustRoot(fixtureRootPem), expectedChannel: null, currentClientVersion: CurrentClientVersion, currentConfigVersion: 1, previousAuthority, allowTestOnlyShape: true);

    internal static VerifiedEnvelope VerifyEnvelopeForInstallerTestInitial(byte[] envelopeBytes, string fixtureRootPem) =>
        VerifyEnvelopeCore(envelopeBytes, new TestReleaseTrustRoot(fixtureRootPem), expectedChannel: null, currentClientVersion: CurrentClientVersion, currentConfigVersion: 1, previousAuthority: null, allowTestOnlyShape: true);

    internal Task DownloadArtifactForHarnessAsync(Uri artifactUri, string destination, string resumePath,
        long bytes, string sha256, CancellationToken cancellationToken = default) =>
        DownloadAndVerifyArtifactAsync(artifactUri, "TEST-ONLY", null, destination, resumePath,
            new Artifact("windows-app/TEST-ONLY.bin", "TEST-ONLY.bin", "windows", "x64", "exe", bytes, sha256, id: "TEST-ONLY"),
            cancellationToken);

    internal Task DownloadArtifactWithFallbackForHarnessAsync(Uri preferredUri, Uri fallbackUri,
        string destination, string resumePath, long bytes, string sha256, Action<long>? onBytesCopied = null,
        CancellationToken cancellationToken = default) =>
        DownloadAndVerifyArtifactWithFallbackAsync(preferredUri, fallbackUri, "TEST-ONLY", null,
            destination, resumePath,
            new Artifact("windows-app/TEST-ONLY.bin", "TEST-ONLY.bin", "windows", "x64", "exe", bytes, sha256, id: "TEST-ONLY"),
            cancellationToken, onBytesCopied);

#endif

    private static VerifiedEnvelope VerifyEnvelopeCore(byte[] envelopeBytes, IReleaseTrustRoot trustRoot, string? expectedChannel, string? currentClientVersion, long? currentConfigVersion, ReleaseStateAuthority.State? previousAuthority, bool allowTestOnlyShape = false)
    {
        var rootKeyPem = trustRoot.Pem;
        if (!trustRoot.Provisioned || string.IsNullOrWhiteSpace(rootKeyPem) || string.IsNullOrWhiteSpace(trustRoot.KeyId) || string.IsNullOrWhiteSpace(trustRoot.Fingerprint))
            throw new InvalidDataException("BF-RELEASE-TRUST-ROOT");
        if (!string.Equals(FingerprintPem(rootKeyPem), trustRoot.Fingerprint, StringComparison.Ordinal))
            throw new InvalidDataException("BF-RELEASE-TRUST-ROOT");
        if (envelopeBytes.Length == 0 || envelopeBytes.Length > MaxManifestBytes) throw new InvalidDataException("BF-RELEASE-ENVELOPE-SIZE");
        using var document = ParseStrictJson(envelopeBytes, 32);
        var root = document.RootElement;
        RequireExactFields(root, new[] { "manifest_text", "signature", "delegation", "root_signature", "key_state", "transition_signature" }, new[] { "manifest_text", "signature", "delegation", "root_signature", "key_state" });
        if (root.GetProperty("manifest_text").ValueKind != JsonValueKind.String || root.GetProperty("signature").ValueKind != JsonValueKind.String)
            throw new InvalidDataException("BF-RELEASE-ENVELOPE-SHAPE");
        var manifestText = root.GetProperty("manifest_text").GetString() ?? throw new InvalidDataException("BF-RELEASE-MANIFEST-MISSING");
        var signatureText = root.GetProperty("signature").GetString() ?? string.Empty;
        var payload = new UTF8Encoding(false, true).GetBytes(manifestText);
        byte[]? signature = null;
        byte[]? rawKey = null;
        try
        {
            signature = FromBase64Url(signatureText);
            if (signature.Length != 64) throw new CryptographicException("BF-RELEASE-SIGNATURE");
            using var manifest = ParseStrictJson(payload, 32);
            var m = manifest.RootElement;
            string? authorityDigest = null;
            long authorityGeneration = 0;
            {
                var delegation = root.GetProperty("delegation");
                var rootSignatureText = root.GetProperty("root_signature").GetString() ?? throw new InvalidDataException("BF-RELEASE-KEY");
                 ValidateDelegation(delegation, m, sequenceHint: null, expectedRootKeyId: trustRoot.KeyId);
                var delegationBytes = Encoding.UTF8.GetBytes(CanonicalDelegation(delegation));
                var rootSignature = FromBase64Url(rootSignatureText);
                var rootKey = ExtractRawPublicKey(rootKeyPem);
                try
                {
                    if (rootSignature.Length != 64 || !Ed25519.Verify(rootSignature, delegationBytes, rootKey)) throw new CryptographicException("BF-RELEASE-KEY");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(rootSignature);
                    CryptographicOperations.ZeroMemory(rootKey);
                    CryptographicOperations.ZeroMemory(delegationBytes);
                }
                if (!root.TryGetProperty("key_state", out var keyState)) throw new InvalidDataException("BF-RELEASE-KEY-STATE");
                 ValidateKeyState(keyState, trustRoot, signingKeyId: delegation.GetProperty("key_id").GetString());
                authorityGeneration = keyState.GetProperty("generation").GetInt64();
                authorityDigest = KeyStateDigest(keyState);
                var hasTransition = root.TryGetProperty("transition_signature", out var transition);
                if (hasTransition)
                    ValidateTransition(transition, m.GetProperty("channel").GetString() ?? string.Empty, authorityGeneration, delegation.GetProperty("key_id").GetString() ?? string.Empty, delegation.GetProperty("public_key_pem").GetString()!, previousAuthority?.SigningKeyId, previousAuthority?.SigningKeyFingerprint, ReadRequiredPositiveInt64(m, "release_sequence"));
                rawKey = ExtractRawPublicKey(delegation.GetProperty("public_key_pem").GetString() ?? throw new InvalidDataException("BF-RELEASE-KEY"));
            }
            RequireExactFields(m,
                 new[] { "format", "generated_at", "release_sequence", "minimum_client_version", "build", "sbom_sha256", "licenses_sha256", "source_bundle_id", "notice_artifact_id", "signing_algorithm", "rollback_policy", "channel", "minimum_config_version", "rollback_floor", "signing_key_id", "trust_root_key_id", "source_manifest_sha256", "build_plan_sha256", "source_policy_sha256", "core_provenance_sha256", "build_inputs_sha256", "toolchain_sha256", "dependency_license_manifest_sha256" },
                new[] { "format", "generated_at", "release_sequence", "minimum_client_version", "build", "sbom_sha256", "licenses_sha256", "source_bundle_id", "notice_artifact_id", "signing_algorithm", "rollback_policy", "channel", "minimum_config_version", "rollback_floor", "signing_key_id", "trust_root_key_id" });
            if (ReadRequiredString(m, "format") != Format || ReadRequiredString(m, "signing_algorithm") != "Ed25519") throw new InvalidDataException("BF-RELEASE-FORMAT");
            var sequence = ReadRequiredPositiveInt64(m, "release_sequence");
            var rollbackFloor = ReadRequiredPositiveInt64(m, "rollback_floor");
            if (rollbackFloor > sequence) throw new InvalidDataException("BF-RELEASE-METADATA");
             if (m.TryGetProperty("trust_root_key_id", out var rootId) && rootId.GetString() != trustRoot.KeyId) throw new InvalidDataException("BF-RELEASE-KEY");
            if (m.TryGetProperty("signing_key_id", out var signerId) && !System.Text.RegularExpressions.Regex.IsMatch(signerId.GetString() ?? string.Empty, "^bifrost-release-v[0-9]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) throw new InvalidDataException("BF-RELEASE-KEY");
            if (m.TryGetProperty("revoked_key_ids", out var revoked) && revoked.ValueKind == JsonValueKind.Array && m.TryGetProperty("signing_key_id", out var currentSigner) && revoked.EnumerateArray().Any(item => item.ValueKind == JsonValueKind.String && item.GetString() == currentSigner.GetString())) throw new InvalidDataException("BF-RELEASE-KEY");
             if (m.TryGetProperty("channel", out var channel) && channel.GetString() is not ("stable" or "beta" or "test")) throw new InvalidDataException("BF-RELEASE-METADATA");
             if (!allowTestOnlyShape && m.TryGetProperty("channel", out var stableChannel) && stableChannel.GetString() == "stable")
             {
                 foreach (var field in new[] { "source_manifest_sha256", "build_plan_sha256", "source_policy_sha256", "core_provenance_sha256", "build_inputs_sha256", "toolchain_sha256", "dependency_license_manifest_sha256" })
                     if (!m.TryGetProperty(field, out var digestField) || !IsDigest(digestField.GetString())) throw new InvalidDataException("BF-RELEASE-METADATA");
             }
             if (expectedChannel is not null && (!m.TryGetProperty("channel", out var actualChannel) || actualChannel.GetString() != expectedChannel)) throw new InvalidDataException("BF-RELEASE-METADATA");
             if (!m.TryGetProperty("minimum_config_version", out var minimumConfig) || !minimumConfig.TryGetInt64(out var configVersion) || configVersion < 0 || configVersion > 1 || (currentConfigVersion is not null && configVersion > currentConfigVersion.Value))
                throw new InvalidDataException("BF-RELEASE-MIN-CONFIG-VERSION");
            if (m.TryGetProperty("minimum_client_version", out var minimumVersion))
            {
                if (minimumVersion.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("BF-RELEASE-MIN-VERSION");
                var minimum = minimumVersion.GetString();
                 if (string.IsNullOrWhiteSpace(minimum) || (currentClientVersion is not null && CompareReleaseVersions(currentClientVersion, minimum) < 0))
                    throw new InvalidDataException("BF-RELEASE-MIN-VERSION");
            }
            var build = RequireObject(m, "build");
            RequireExactFields(build,
                new[] { "format", "generated_at", "configuration", "android_signing_scope", "android_signing_key_alias", "artifact_root", "artifacts" },
                new[] { "artifact_root", "artifacts" });
            if (ReadRequiredString(build, "artifact_root") != "releases") throw new InvalidDataException("BF-RELEASE-ROOT");
            var artifactArray = build.GetProperty("artifacts");
            if (artifactArray.ValueKind != JsonValueKind.Array || artifactArray.GetArrayLength() is < 1 or > 64) throw new InvalidDataException("BF-RELEASE-ARTIFACTS");
            var artifacts = new List<Artifact>(artifactArray.GetArrayLength());
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var installPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var artifactIds = new HashSet<string>(StringComparer.Ordinal);
            var dependencyGraph = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            long totalBytes = 0;
            foreach (var item in artifactArray.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-RELEASE-ARTIFACT-SHAPE");
                RequireExactFields(item, new[] { "id", "path", "install_path", "platform", "arch", "kind", "bytes", "sha256", "source_bundle", "notice", "dependencies" }, new[] { "id", "path", "install_path", "platform", "arch", "kind", "bytes", "sha256", "source_bundle", "notice", "dependencies" });
                var relative = SafeRelative(ReadRequiredString(item, "path"));
                var installPath = SafeRelative(ReadRequiredString(item, "install_path"));
                if (!paths.Add(relative) || !installPaths.Add(installPath)) throw new InvalidDataException("BF-RELEASE-PATH-COLLISION");
                var platform = ReadRequiredString(item, "platform");
                var arch = ReadRequiredString(item, "arch");
                var kind = ReadRequiredString(item, "kind");
                var id = ReadRequiredString(item, "id");
                if (!artifactIds.Add(id)) throw new InvalidDataException("BF-RELEASE-ARTIFACT");
                if (platform is not ("android" or "windows" or "linux") || string.IsNullOrWhiteSpace(arch) || !arch.All(ch => char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-') || kind is not ("apk" or "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata" or "notice" or "source" or "node-agent")) throw new InvalidDataException("BF-RELEASE-TARGET");
                var bytes = ReadRequiredPositiveInt64(item, "bytes");
                if (bytes > MaxArtifactBytes || checked(totalBytes + bytes) > 1024L * 1024 * 1024) throw new InvalidDataException("BF-RELEASE-SIZE");
                totalBytes += bytes;
                var sha = ReadRequiredString(item, "sha256");
                if (sha.Length != 64 || !sha.All(Uri.IsHexDigit) || sha != sha.ToLowerInvariant()) throw new InvalidDataException("BF-RELEASE-DIGEST");
                _ = ReadRequiredString(item, "source_bundle");
                _ = ReadRequiredString(item, "notice");
                var dependencies = item.GetProperty("dependencies");
                if (dependencies.ValueKind != JsonValueKind.Array || dependencies.GetArrayLength() > 32) throw new InvalidDataException("BF-RELEASE-METADATA");
                dependencyGraph[id] = dependencies.EnumerateArray().Select(value => value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new InvalidDataException("BF-RELEASE-METADATA")).ToList();
                artifacts.Add(new Artifact(relative, installPath, platform, arch, kind, bytes, sha, item.GetProperty("source_bundle").GetString(), item.GetProperty("notice").GetString(), Array.AsReadOnly(dependencyGraph[id].ToArray()), id));
            }
            {
                foreach (var item in artifactArray.EnumerateArray())
                {
                    var id = item.GetProperty("id").GetString()!;
                    if (!artifactIds.Contains(item.GetProperty("source_bundle").GetString()!) || !artifactIds.Contains(item.GetProperty("notice").GetString()!) || dependencyGraph[id].Any(dep => !artifactIds.Contains(dep) || dep == id)) throw new InvalidDataException("BF-RELEASE-METADATA");
                    var sourceArtifact = artifactArray.EnumerateArray().First(candidate => candidate.GetProperty("id").GetString() == item.GetProperty("source_bundle").GetString());
                    var noticeArtifact = artifactArray.EnumerateArray().First(candidate => candidate.GetProperty("id").GetString() == item.GetProperty("notice").GetString());
                    if (sourceArtifact.GetProperty("kind").GetString() != "source" || noticeArtifact.GetProperty("kind").GetString() != "notice") throw new InvalidDataException("BF-RELEASE-METADATA");
                    foreach (var dependencyId in dependencyGraph[id])
                    {
                        var dependency = artifactArray.EnumerateArray().First(candidate => candidate.GetProperty("id").GetString() == dependencyId);
                        if (dependency.GetProperty("kind").GetString() is not ("source" or "notice") && (dependency.GetProperty("platform").GetString() != item.GetProperty("platform").GetString() || dependency.GetProperty("arch").GetString() != item.GetProperty("arch").GetString())) throw new InvalidDataException("BF-RELEASE-METADATA");
                    }
                }
                var visiting = new HashSet<string>(StringComparer.Ordinal); var visited = new HashSet<string>(StringComparer.Ordinal);
                void Visit(string id) { if (visiting.Contains(id)) throw new InvalidDataException("BF-RELEASE-METADATA"); if (!visited.Add(id)) return; visiting.Add(id); foreach (var dep in dependencyGraph[id]) Visit(dep); visiting.Remove(id); }
                foreach (var id in artifactIds) Visit(id);
                if (!artifactIds.Contains(m.GetProperty("source_bundle_id").GetString()!) || !artifactIds.Contains(m.GetProperty("notice_artifact_id").GetString()!)) throw new InvalidDataException("BF-RELEASE-METADATA");
            }
            if (m.GetProperty("channel").GetString() == "stable")
            {
                var windows = artifactArray.EnumerateArray().Where(item => item.GetProperty("platform").GetString() == "windows" && item.GetProperty("arch").GetString() == "x64").ToArray();
                var payloadWindows = windows.Where(item => item.GetProperty("kind").GetString() is not ("source" or "notice")).ToArray();
                var payloadIds = payloadWindows.Select(item => item.GetProperty("id").GetString() ?? string.Empty).ToHashSet(StringComparer.Ordinal);
                var androidPayload = artifactArray.EnumerateArray().Where(item => item.GetProperty("platform").GetString() == "android" && item.GetProperty("kind").GetString() != "source" && item.GetProperty("kind").GetString() != "notice").Select(item => item.GetProperty("id").GetString() ?? string.Empty).ToHashSet(StringComparer.Ordinal);
                if (payloadWindows.Length > 0 && (payloadWindows.Length != payloadIds.Count || !ReleaseArtifactPolicy.IsWindowsX64Stable(payloadIds))) throw new InvalidDataException("BF-RELEASE-WINDOWS-SET");
                if (androidPayload.Count > 0 && !androidPayload.SetEquals(ReleaseArtifactPolicy.AndroidStable)) throw new InvalidDataException("BF-RELEASE-ANDROID-SET");
                if (androidPayload.Count > 0) foreach (var androidId in ReleaseArtifactPolicy.AndroidStable)
                {
                    var androidArtifact = artifactArray.EnumerateArray().SingleOrDefault(item => item.GetProperty("id").GetString() == androidId);
                    if (androidArtifact.ValueKind != JsonValueKind.Object || androidArtifact.GetProperty("platform").GetString() != "android" || androidArtifact.GetProperty("kind").GetString() != "apk" || androidId != $"android-{androidArtifact.GetProperty("arch").GetString()}-apk") throw new InvalidDataException("BF-RELEASE-ANDROID-SET");
                }
                if (payloadWindows.Length == 0 && androidPayload.Count == 0) throw new InvalidDataException("BF-RELEASE-REQUIRED-SET");
            }
            var verifiedDelegation = root.GetProperty("delegation");
            if (verifiedDelegation.GetProperty("key_id").GetString() != m.GetProperty("signing_key_id").GetString() || verifiedDelegation.GetProperty("root_key_id").GetString() != m.GetProperty("trust_root_key_id").GetString() || verifiedDelegation.GetProperty("channel").GetString() != m.GetProperty("channel").GetString()) throw new InvalidDataException("BF-RELEASE-KEY");
            if (!Ed25519.Verify(signature, payload, rawKey)) throw new CryptographicException("BF-RELEASE-SIGNATURE");
            var manifestDigest = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
            var envelopeDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson(root)))).ToLowerInvariant();
            var allowlistDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson(build.GetProperty("artifacts"))))).ToLowerInvariant();
            var rootKeyId = m.TryGetProperty("trust_root_key_id", out var rootKeyElement) ? rootKeyElement.GetString() : null;
            var channelName = m.TryGetProperty("channel", out var channelElement) ? channelElement.GetString() : null;
            var floor = m.TryGetProperty("rollback_floor", out var floorElement) && floorElement.TryGetInt64(out var floorValue) ? floorValue : 0;
            var signingKey = m.TryGetProperty("signing_key_id", out var signingElement) ? signingElement.GetString() : null;
            var delegationGeneration = root.GetProperty("delegation").GetProperty("generation").GetInt64();
            var signingKeyFingerprint = FingerprintPem(root.GetProperty("delegation").GetProperty("public_key_pem").GetString()!);
            if (previousAuthority is not null)
            {
                var sequenceClass = ReleaseStateAuthority.Classify(previousAuthority.Sequence, previousAuthority.ManifestDigest, sequence, manifestDigest, previousAuthority.Floor);
                if (sequenceClass is "rollback" or "equivocation") throw new InvalidDataException(sequenceClass == "equivocation" ? "BF-RELEASE-EQUIVOCATION" : "BF-RELEASE-ROLLBACK");
                var authorityClass = ReleaseStateAuthority.ClassifyAuthority(previousAuthority, authorityGeneration, authorityDigest ?? throw new InvalidDataException("BF-RELEASE-AUTHORITY"), signingKeyFingerprint);
                if (authorityClass is "rollback" or "equivocation") throw new InvalidDataException(authorityClass == "equivocation" ? "BF-RELEASE-AUTHORITY-EQUIVOCATION" : "BF-RELEASE-AUTHORITY-ROLLBACK");
                if (authorityClass == "advance" && !string.Equals(previousAuthority.SigningKeyFingerprint, signingKeyFingerprint, StringComparison.Ordinal) && !root.TryGetProperty("transition_signature", out _)) throw new InvalidDataException("BF-RELEASE-TRANSITION");
            }
             var plan = new VerifiedReleasePlan(envelopeDigest, manifestDigest, allowlistDigest, sequence, channelName, floor, rootKeyId, trustRoot.Fingerprint, authorityDigest, authorityGeneration, delegationGeneration, signingKey, signingKeyFingerprint, root.TryGetProperty("transition_signature", out _), Array.AsReadOnly(artifacts.ToArray()));
            return new VerifiedEnvelope(sequence, manifestText, signatureText, artifacts, plan);
        }
        finally
        {
            if (rawKey is not null) CryptographicOperations.ZeroMemory(rawKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(payload);
      }
    }

    private static void ValidateDelegation(JsonElement delegation, JsonElement manifest, long? sequenceHint, string expectedRootKeyId)
    {
        RequireExactFields(delegation,
            new[] { "root_key_id", "key_id", "purpose", "algorithm", "public_key_pem", "public_key_fingerprint", "channel", "activation_sequence", "retirement_sequence", "generation" },
            new[] { "root_key_id", "key_id", "purpose", "algorithm", "public_key_pem", "public_key_fingerprint", "channel", "activation_sequence", "retirement_sequence", "generation" });
        if (delegation.GetProperty("root_key_id").GetString() != expectedRootKeyId || delegation.GetProperty("purpose").GetString() != "release-signing" || delegation.GetProperty("algorithm").GetString() != "Ed25519") throw new InvalidDataException("BF-RELEASE-KEY");
        var keyId = delegation.GetProperty("key_id").GetString() ?? string.Empty;
        if (!System.Text.RegularExpressions.Regex.IsMatch(keyId, "^bifrost-release-v[0-9]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) throw new InvalidDataException("BF-RELEASE-KEY");
        var channel = delegation.GetProperty("channel").GetString() ?? string.Empty;
        if (channel is not ("stable" or "beta" or "test")) throw new InvalidDataException("BF-RELEASE-METADATA");
        var activation = ReadRequiredPositiveInt64(delegation, "activation_sequence");
        var retirement = ReadRequiredPositiveInt64(delegation, "retirement_sequence");
        if (retirement <= activation || (sequenceHint.HasValue && sequenceHint.Value < activation) || (sequenceHint.HasValue && sequenceHint.Value >= retirement)) throw new InvalidDataException("BF-RELEASE-KEY");
        if (delegation.GetProperty("generation").ValueKind != JsonValueKind.Number || !delegation.GetProperty("generation").TryGetInt64(out var generationNumber) || generationNumber < 1) throw new InvalidDataException("BF-RELEASE-KEY");
        var pem = delegation.GetProperty("public_key_pem").GetString() ?? throw new InvalidDataException("BF-RELEASE-KEY");
        var der = ExportPublicDer(pem);
        try
        {
            var fingerprint = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
            if (!string.Equals(fingerprint, delegation.GetProperty("public_key_fingerprint").GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-KEY");
        }
        finally { CryptographicOperations.ZeroMemory(der); }
        if (manifest.ValueKind == JsonValueKind.Object)
        {
            if (manifest.TryGetProperty("signing_key_id", out var signer) && signer.GetString() != keyId) throw new InvalidDataException("BF-RELEASE-KEY");
            if (manifest.TryGetProperty("trust_root_key_id", out var root) && root.GetString() != expectedRootKeyId) throw new InvalidDataException("BF-RELEASE-KEY");
            if (manifest.TryGetProperty("channel", out var manifestChannel) && manifestChannel.GetString() != channel) throw new InvalidDataException("BF-RELEASE-KEY");
            if (manifest.TryGetProperty("release_sequence", out var releaseSequence) && releaseSequence.TryGetInt64(out var sequence) && (sequence < activation || sequence >= retirement)) throw new InvalidDataException("BF-RELEASE-KEY");
        }
    }

    private static void ValidateKeyState(JsonElement value, IReleaseTrustRoot trustRoot, string? signingKeyId)
    {
        RequireExactFields(value, new[] { "root_key_id", "generation", "channel", "active_key_ids", "revoked_key_ids", "signature" }, new[] { "root_key_id", "generation", "channel", "active_key_ids", "revoked_key_ids", "signature" });
        if (value.GetProperty("root_key_id").GetString() != trustRoot.KeyId || !value.GetProperty("generation").TryGetInt64(out var generation) || generation < 1 || value.GetProperty("channel").GetString() is not ("stable" or "beta" or "test")) throw new InvalidDataException("BF-RELEASE-KEY-STATE");
        if (value.GetProperty("active_key_ids").ValueKind != JsonValueKind.Array || value.GetProperty("revoked_key_ids").ValueKind != JsonValueKind.Array) throw new InvalidDataException("BF-RELEASE-KEY-STATE");
        var active = value.GetProperty("active_key_ids").EnumerateArray().Select(x => x.GetString() ?? throw new InvalidDataException("BF-RELEASE-KEY-STATE")).ToHashSet(StringComparer.Ordinal);
        var revoked = value.GetProperty("revoked_key_ids").EnumerateArray().Select(x => x.GetString() ?? throw new InvalidDataException("BF-RELEASE-KEY-STATE")).ToHashSet(StringComparer.Ordinal);
        var activeList = value.GetProperty("active_key_ids").EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray();
        var revokedList = value.GetProperty("revoked_key_ids").EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray();
        if (activeList.Any(string.IsNullOrWhiteSpace) || revokedList.Any(string.IsNullOrWhiteSpace) || !activeList.SequenceEqual(activeList.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal) || !revokedList.SequenceEqual(revokedList.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal) || activeList.Distinct(StringComparer.Ordinal).Count() != activeList.Length || revokedList.Distinct(StringComparer.Ordinal).Count() != revokedList.Length || active.Overlaps(revoked) || (signingKeyId is not null && (!active.Contains(signingKeyId) || revoked.Contains(signingKeyId)))) throw new InvalidDataException("BF-RELEASE-KEY-STATE");
        var activeJson = "[" + string.Join(',', active.OrderBy(x => x).Select(item => JsonSerializer.Serialize(item))) + "]";
        var revokedJson = "[" + string.Join(',', revoked.OrderBy(x => x).Select(item => JsonSerializer.Serialize(item))) + "]";
        var channelJson = JsonSerializer.Serialize(value.GetProperty("channel").GetString());
        var rootIdJson = JsonSerializer.Serialize(value.GetProperty("root_key_id").GetString());
        var bytes = Encoding.UTF8.GetBytes($"{{\"active_key_ids\":{activeJson},\"channel\":{channelJson},\"generation\":{generation.ToString(CultureInfo.InvariantCulture)},\"revoked_key_ids\":{revokedJson},\"root_key_id\":{rootIdJson}}}");
        var signature = FromBase64Url(value.GetProperty("signature").GetString() ?? string.Empty);
        try { if (signature.Length != 64 || trustRoot.Pem is null || !Ed25519.Verify(signature, bytes, ExtractRawPublicKey(trustRoot.Pem))) throw new InvalidDataException("BF-RELEASE-KEY-STATE"); }
        finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(signature); }
    }

    private static string KeyStateDigest(JsonElement value)
    {
        var signed = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["active_key_ids"] = value.GetProperty("active_key_ids").EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray(),
            ["channel"] = value.GetProperty("channel").GetString(),
            ["generation"] = value.GetProperty("generation").GetInt64(),
            ["revoked_key_ids"] = value.GetProperty("revoked_key_ids").EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray(),
            ["root_key_id"] = value.GetProperty("root_key_id").GetString()
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(signed, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateTransition(JsonElement value, string channel, long keyStateGeneration, string signingKeyId, string signingKeyPem, string? previousSigningKeyId, string? previousSigningKeyFingerprint, long releaseSequence)
    {
        RequireExactFields(value,
            new[] { "old_key_id", "new_key_id", "purpose", "algorithm", "channel", "from_generation", "to_generation", "activation_sequence", "retirement_sequence", "old_public_key_pem", "new_public_key_pem", "old_signature", "new_signature" },
            new[] { "old_key_id", "new_key_id", "purpose", "algorithm", "channel", "from_generation", "to_generation", "activation_sequence", "retirement_sequence", "old_public_key_pem", "new_public_key_pem", "old_signature", "new_signature" });
        var oldId = ReadRequiredString(value, "old_key_id"); var newId = ReadRequiredString(value, "new_key_id");
        var purpose = ReadRequiredString(value, "purpose"); var algorithm = ReadRequiredString(value, "algorithm"); var transitionChannel = ReadRequiredString(value, "channel");
        var from = ReadRequiredPositiveInt64(value, "from_generation"); var to = ReadRequiredPositiveInt64(value, "to_generation");
        var activation = ReadRequiredPositiveInt64(value, "activation_sequence"); var retirement = ReadRequiredPositiveInt64(value, "retirement_sequence");
        if (!System.Text.RegularExpressions.Regex.IsMatch(oldId, "^[A-Za-z0-9._-]{1,64}$") || !System.Text.RegularExpressions.Regex.IsMatch(newId, "^[A-Za-z0-9._-]{1,64}$") || oldId == newId || newId != signingKeyId || (previousSigningKeyId is not null && oldId != previousSigningKeyId) || purpose != "release-signing" || algorithm != "Ed25519" || transitionChannel != channel || from + 1 != to || to != keyStateGeneration || retirement <= activation || releaseSequence < activation || releaseSequence >= retirement) throw new InvalidDataException("BF-RELEASE-TRANSITION");
        var oldPem = ReadRequiredString(value, "old_public_key_pem"); var newPem = ReadRequiredString(value, "new_public_key_pem");
        if (!string.Equals(FingerprintPem(newPem), FingerprintPem(signingKeyPem), StringComparison.Ordinal) || (previousSigningKeyFingerprint is not null && !string.Equals(FingerprintPem(oldPem), previousSigningKeyFingerprint, StringComparison.Ordinal))) throw new InvalidDataException("BF-RELEASE-TRANSITION");
        var oldSignature = FromBase64Url(ReadRequiredString(value, "old_signature")); var newSignature = FromBase64Url(ReadRequiredString(value, "new_signature"));
        var oldKey = ExtractRawPublicKey(oldPem); var newKey = ExtractRawPublicKey(newPem);
        var jsonOptions = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        var unsigned = $"{{\"activation_sequence\":{activation},\"algorithm\":\"Ed25519\",\"channel\":{JsonSerializer.Serialize(channel, jsonOptions)},\"from_generation\":{from},\"new_key_id\":{JsonSerializer.Serialize(newId, jsonOptions)},\"new_public_key_pem\":{JsonSerializer.Serialize(newPem, jsonOptions)},\"old_key_id\":{JsonSerializer.Serialize(oldId, jsonOptions)},\"old_public_key_pem\":{JsonSerializer.Serialize(oldPem, jsonOptions)},\"purpose\":\"release-signing\",\"retirement_sequence\":{retirement},\"to_generation\":{to}}}";
        var bytes = Encoding.UTF8.GetBytes(unsigned);
        try
        {
            if (oldSignature.Length != 64 || newSignature.Length != 64 || !Ed25519.Verify(oldSignature, bytes, oldKey) || !Ed25519.Verify(newSignature, bytes, newKey)) throw new InvalidDataException("BF-RELEASE-TRANSITION");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(oldSignature); CryptographicOperations.ZeroMemory(newSignature); CryptographicOperations.ZeroMemory(oldKey); CryptographicOperations.ZeroMemory(newKey); }
    }

    private static string CanonicalDelegation(JsonElement delegation)
    {
        var options = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        var keys = new[] { "activation_sequence", "algorithm", "channel", "generation", "key_id", "public_key_fingerprint", "public_key_pem", "purpose", "retirement_sequence", "root_key_id" };
        var parts = new List<string>(keys.Length);
        foreach (var key in keys)
        {
            var value = delegation.GetProperty(key);
            var encoded = value.ValueKind switch
            {
                JsonValueKind.String => JsonSerializer.Serialize(value.GetString(), options),
                JsonValueKind.Number when value.TryGetInt64(out var number) => number.ToString(CultureInfo.InvariantCulture),
                _ => throw new InvalidDataException("BF-RELEASE-KEY")
            };
            parts.Add(JsonSerializer.Serialize(key, options) + ":" + encoded);
        }
        return "{" + string.Join(',', parts) + "}";
    }

    private static string CanonicalJson(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Name) + ":" + CanonicalJson(p.Value))) + "}",
            JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
            JsonValueKind.String => JsonSerializer.Serialize(value.GetString(), new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }),
            JsonValueKind.Number when value.TryGetInt64(out var n) => n.ToString(CultureInfo.InvariantCulture),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => throw new InvalidDataException("BF-RELEASE-FIELDS")
        };
    }

    private static byte[] ExportPublicDer(string pem)
    {
        if (!PemEncoding.TryFind(pem.AsSpan(), out var fields)) throw new CryptographicException("BF-RELEASE-KEY");
        var der = Convert.FromBase64String(pem[fields.Base64Data].ToString());
        var prefix = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
        if (der.Length != prefix.Length + 32 || !der.AsSpan(0, prefix.Length).SequenceEqual(prefix)) throw new CryptographicException("BF-RELEASE-KEY");
        return der;
    }

    public static void VerifyArtifact(byte[] bytes, Artifact metadata)
    {
        if (bytes.LongLength != metadata.Bytes) throw new InvalidDataException($"artifact size mismatch: {metadata.Path}");
        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(metadata.Sha256))) throw new CryptographicException($"artifact digest mismatch: {metadata.Path}");
    }

    private static string ComputeStageIdentity(IEnumerable<Artifact> artifacts, string stage)
    {
        var lines = new List<string>();
        foreach (var artifact in artifacts.OrderBy(value => value.Id, StringComparer.Ordinal))
        {
            var relative = SafeRelative(artifact.InstallPath ?? artifact.Path);
            var path = Path.Combine(stage, relative.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path)) throw new InvalidDataException("BF-RELEASE-STAGE");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[64 * 1024]; long bytes = 0; int read;
            try
            {
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) { bytes += read; hash.AppendData(buffer, 0, read); }
                var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                if (bytes != artifact.Bytes || !string.Equals(digest, artifact.Sha256, StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-STAGE");
                lines.Add($"{artifact.Id}\n{relative}\n{bytes}\n{digest}");
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines)))).ToLowerInvariant();
    }

    private static async Task CopyAndVerifyAsync(
        HttpContent content,
        string destination,
        Artifact metadata,
        CancellationToken cancellationToken,
        Action<int>? onBytesCopied = null)
    {
        if (metadata.Bytes > MaxArtifactBytes) throw new InvalidDataException("release artifact exceeds size limit");
        var temporary = destination + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        long count = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var buffer = new byte[1024 * 1024];
            try
            {
                await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    int read;
                    while ((read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
                    {
                        count += read;
                        if (count > MaxArtifactBytes || count > metadata.Bytes) throw new InvalidDataException($"artifact size mismatch: {metadata.Path}");
                        hash.AppendData(buffer, 0, read);
                        await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        onBytesCopied?.Invoke(read);
                    }
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
            if (count != metadata.Bytes || !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(metadata.Sha256))) throw new CryptographicException($"artifact digest mismatch: {metadata.Path}");
            // The temporary file must be closed before Move on Windows.
            // FileShare.None intentionally prevents any observer from seeing a
            // partially written artifact, but that same exclusive handle also
            // blocks renaming while it is still open.
            File.Move(temporary, destination, true);
        }
        catch { if (File.Exists(temporary)) File.Delete(temporary); throw; }
    }

    private async Task DownloadAndVerifyArtifactAsync(
        Uri artifactUri,
        string token,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        string destination,
        string resumePath,
        Artifact metadata,
        CancellationToken cancellationToken,
        Action<long>? onBytesCopied = null)
    {
        if (metadata.Bytes is < 1 or > MaxArtifactBytes) throw new InvalidDataException("BF-RELEASE-ARTIFACT-SIZE");
        var destinationTemporary = destination + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        Directory.CreateDirectory(Path.GetDirectoryName(resumePath)!);
        if (File.Exists(resumePath) && File.GetAttributes(resumePath).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException("BF-RELEASE-CACHE");
        if (File.Exists(resumePath) && new FileInfo(resumePath).Length > metadata.Bytes)
            File.Delete(resumePath);
        long total = 0;
        var discardResume = false;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            // Keep the resumable cache handle exclusive from prefix hashing
            // through the final verified copy. A failed network attempt leaves
            // a complete chunk boundary on disk; a digest failure discards it.
            await using (var output = new FileStream(resumePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                1024 * 1024, FileOptions.Asynchronous))
            {
                var prefixBuffer = new byte[1024 * 1024];
                try
                {
                    output.Position = 0;
                    int read;
                    while ((read = await output.ReadAsync(prefixBuffer, cancellationToken).ConfigureAwait(false)) != 0)
                    {
                        total += read;
                        if (total > metadata.Bytes) throw new InvalidDataException("BF-RELEASE-CACHE");
                        hash.AppendData(prefixBuffer, 0, read);
                    }
                    if (total > 0) onBytesCopied?.Invoke(total);
                }
                finally { CryptographicOperations.ZeroMemory(prefixBuffer); }

                output.Position = total;
                if (total == 0 && artifactUri.AbsolutePath.StartsWith("/v1/releases/blobs/", StringComparison.Ordinal))
                {
                    try
                    {
                        total = await DownloadFullArtifactAsync(artifactUri, token, proofFactory, metadata,
                            output, hash, cancellationToken, onBytesCopied).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                    catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException or OperationCanceledException or
                                                       InvalidOperationException or InvalidDataException)
                    {
                        // Whole immutable objects are what the CDN caches most
                        // efficiently.  If that fast path is interrupted by a
                        // local proxy/cold edge fill, or a mirror responds with
                        // an unusable redirect/HTTP shape, keep the exact
                        // received prefix and continue below with bounded Range
                        // requests instead of aborting the origin immediately.
                        total = output.Position;
                    }
                }
                total = await DownloadRemainingChunksAsync(artifactUri, token, proofFactory, metadata,
                    output, hash, total, cancellationToken, onBytesCopied).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                if (total != metadata.Bytes || !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(metadata.Sha256)))
                {
                    discardResume = true;
                    throw new CryptographicException("BF-RELEASE-ARTIFACT-HASH");
                }

                output.Position = 0;
                await using (var staged = new FileStream(destinationTemporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    1024 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    await output.CopyToAsync(staged, 1024 * 1024, cancellationToken).ConfigureAwait(false);
                    await staged.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            File.Move(destinationTemporary, destination, true);
        }
        catch
        {
            if (File.Exists(destinationTemporary)) File.Delete(destinationTemporary);
            if (discardResume && File.Exists(resumePath)) File.Delete(resumePath);
            throw;
        }
    }

    private async Task DownloadAndVerifyArtifactWithFallbackAsync(
        Uri preferredUri,
        Uri fallbackUri,
        string token,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        string destination,
        string resumePath,
        Artifact metadata,
        CancellationToken cancellationToken,
        Action<long>? onBytesCopied = null)
    {
        long reportedByPreferred = 0;
        Action<long>? preferredProgress = onBytesCopied is null ? null : delta =>
        {
            reportedByPreferred += delta;
            onBytesCopied(delta);
        };
        try
        {
            await DownloadAndVerifyArtifactAsync(preferredUri, token, proofFactory, destination, resumePath,
                metadata, cancellationToken, preferredProgress).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (!Uri.Compare(preferredUri, fallbackUri, UriComponents.AbsoluteUri,
                   UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase).Equals(0) &&
               error is HttpRequestException or IOException or TimeoutException or OperationCanceledException or
                   InvalidOperationException or InvalidDataException or CryptographicException)
        {
            // Progress is a UI accounting value, not a property of the cache
            // file. A digest failure deliberately deletes that file, but the
            // bytes already reported by the rejected mirror still need to be
            // suppressed while the trusted fallback replaces them.
            var alreadyReported = reportedByPreferred;
            Action<long>? fallbackProgress = onBytesCopied is null ? null : delta =>
            {
                var duplicate = Math.Min(alreadyReported, delta);
                alreadyReported -= duplicate;
                var fresh = delta - duplicate;
                if (fresh > 0) onBytesCopied(fresh);
            };
            await DownloadAndVerifyArtifactAsync(fallbackUri, token, proofFactory, destination, resumePath,
                metadata, cancellationToken, fallbackProgress).ConfigureAwait(false);
        }
    }

    private async Task<long> DownloadFullArtifactAsync(
        Uri artifactUri,
        string token,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        Artifact metadata,
        FileStream output,
        IncrementalHash hash,
        CancellationToken cancellationToken,
        Action<long>? onBytesCopied)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, artifactUri);
        var publicBlob = artifactUri.AbsolutePath.StartsWith("/v1/releases/blobs/", StringComparison.Ordinal);
        if (!publicBlob)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            AddProofHeaders(request, proofFactory?.Invoke(HttpMethod.Get, artifactUri, null));
        }
        using var response = await SendArtifactRequestAsync(request, cancellationToken).ConfigureAwait(false);
        EnsureSuccessfulArtifactResponse(response);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength != metadata.Bytes)
            throw new InvalidDataException("BF-RELEASE-FULL");
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffer = new byte[1024 * 1024];
        try
        {
            long total = 0;
            while (total < metadata.Bytes)
            {
                var remaining = checked((int)Math.Min(buffer.Length, metadata.Bytes - total));
                var read = await ReadArtifactBytesAsync(input, buffer.AsMemory(0, remaining), cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                total += read;
                onBytesCopied?.Invoke(read);
            }
            if (total != metadata.Bytes) throw new IOException("BF-RELEASE-FULL-TRUNCATED");
            var extra = await ReadArtifactBytesAsync(input, buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (extra != 0) throw new InvalidDataException("BF-RELEASE-FULL-OVERFLOW");
            return total;
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private async Task<byte[]> DownloadArtifactChunkAsync(
        Uri artifactUri,
        string token,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        Artifact metadata,
        long start,
        long end,
        CancellationToken cancellationToken)
    {
        var expectedChunkLong = end - start + 1;
        if (expectedChunkLong is < 1 or > ArtifactChunkBytes) throw new InvalidDataException("BF-RELEASE-RANGE");
        var expectedChunk = checked((int)expectedChunkLong);
        Exception? lastTransient = null;

        for (var attempt = 1; attempt <= ArtifactChunkAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, artifactUri);
                var publicBlob = artifactUri.AbsolutePath.StartsWith("/v1/releases/blobs/", StringComparison.Ordinal);
                if (!publicBlob) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Headers.Range = new RangeHeaderValue(start, end);
                if (!publicBlob) AddProofHeaders(request, proofFactory?.Invoke(HttpMethod.Get, artifactUri, null));

                using var response = await SendArtifactRequestAsync(request, cancellationToken).ConfigureAwait(false);
                EnsureSuccessfulArtifactResponse(response);
                var range = response.Content.Headers.ContentRange;
                if (response.StatusCode != HttpStatusCode.PartialContent || range is null ||
                    !string.Equals(range.Unit, "bytes", StringComparison.OrdinalIgnoreCase) ||
                    range.From != start || range.To != end || range.Length != metadata.Bytes)
                    throw new InvalidDataException("BF-RELEASE-RANGE");
                if (response.Content.Headers.ContentLength is long contentLength && contentLength != expectedChunkLong)
                    throw new InvalidDataException("BF-RELEASE-RANGE");

                await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                using var chunk = new MemoryStream(expectedChunk);
                var buffer = new byte[256 * 1024];
                try
                {
                    while (chunk.Length < expectedChunk)
                    {
                        var remaining = expectedChunk - checked((int)chunk.Length);
                        var read = await ReadArtifactBytesAsync(
                            input, buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken).ConfigureAwait(false);
                        if (read == 0) break;
                        chunk.Write(buffer, 0, read);
                    }
                    if (chunk.Length != expectedChunk) throw new IOException("BF-RELEASE-CHUNK-TRUNCATED");
                    // A bounded extra read proves the server did not send more
                    // bytes than the signed Content-Range before we commit the
                    // chunk into the artifact hash/output stream.
                    var extra = await ReadArtifactBytesAsync(input, buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                    if (extra != 0) throw new InvalidDataException("BF-RELEASE-RANGE");
                    return chunk.ToArray();
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            catch (InvalidDataException) { throw; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException or OperationCanceledException)
            {
                lastTransient = error;
                if (attempt == ArtifactChunkAttempts) break;
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken).ConfigureAwait(false);
            }
        }

        throw new IOException("BF-RELEASE-CHUNK-RETRY", lastTransient);
    }

    private async Task<long> DownloadRemainingChunksAsync(
        Uri artifactUri,
        string token,
        Func<HttpMethod, Uri, byte[]?, IReadOnlyDictionary<string, string>>? proofFactory,
        Artifact metadata,
        FileStream output,
        IncrementalHash hash,
        long committedBytes,
        CancellationToken cancellationToken,
        Action<long>? onBytesCopied)
    {
        using var pipelineCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = new Queue<(long Start, Task<byte[]> Download)>();
        var nextStart = committedBytes;
        try
        {
            while (committedBytes < metadata.Bytes)
            {
                while (pending.Count < MaxParallelChunksPerArtifact && nextStart < metadata.Bytes)
                {
                    var start = nextStart;
                    var end = Math.Min(metadata.Bytes - 1, start + ArtifactChunkBytes - 1L);
                    pending.Enqueue((start, DownloadArtifactChunkAsync(
                        artifactUri, token, proofFactory, metadata, start, end, pipelineCancellation.Token)));
                    nextStart = end + 1;
                }

                var pendingChunk = pending.Dequeue();
                if (pendingChunk.Start != committedBytes) throw new InvalidDataException("BF-RELEASE-RANGE-ORDER");
                var chunkBytes = await pendingChunk.Download.ConfigureAwait(false);
                try
                {
                    hash.AppendData(chunkBytes);
                    await output.WriteAsync(chunkBytes, cancellationToken).ConfigureAwait(false);
                    committedBytes += chunkBytes.Length;
                    if (committedBytes > metadata.Bytes) throw new InvalidDataException("BF-RELEASE-RANGE");
                    onBytesCopied?.Invoke(chunkBytes.Length);
                }
                finally { CryptographicOperations.ZeroMemory(chunkBytes); }
            }
            return committedBytes;
        }
        catch
        {
            pipelineCancellation.Cancel();
            while (pending.TryDequeue(out var abandonedChunk))
            {
                try
                {
                    var abandonedBytes = await abandonedChunk.Download.ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(abandonedBytes);
                }
                catch { }
            }
            throw;
        }
    }

    private async Task<HttpResponseMessage> SendArtifactRequestAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        using var headerDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        headerDeadline.CancelAfter(ArtifactResponseHeaderTimeout);
        try
        {
            var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, headerDeadline.Token).ConfigureAwait(false);
            if (!TryResolveTrustedBlobRedirect(request, response, out var redirectUri)) return response;

            // edge.bifrostlog.com intentionally redirects immutable release
            // blobs to the public release mirror.  HttpClient auto-redirects
            // stay disabled globally so manifest/device requests can never
            // leak bearer/proof headers to another origin.  For a public,
            // content-addressed blob only, follow exactly one redirect to the
            // compiled mirror, preserving only the GET Range header.  The
            // signed manifest's size/SHA-256 checks remain authoritative.
            response.Dispose();
            using var redirected = new HttpRequestMessage(HttpMethod.Get, redirectUri)
            {
                Version = request.Version,
                VersionPolicy = request.VersionPolicy,
            };
            if (request.Headers.Range is not null)
                redirected.Headers.TryAddWithoutValidation("Range", request.Headers.Range.ToString());
            return await _http.SendAsync(redirected, HttpCompletionOption.ResponseHeadersRead, headerDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested && headerDeadline.IsCancellationRequested)
        {
            throw new TimeoutException("BF-RELEASE-RESPONSE-HEADER-TIMEOUT", error);
        }
    }

    private static bool TryResolveTrustedBlobRedirect(
        HttpRequestMessage request,
        HttpResponseMessage response,
        out Uri redirectUri)
    {
        redirectUri = null!;
        if ((int)response.StatusCode is not (301 or 302 or 307 or 308)) return false;
        var source = request.RequestUri;
        var location = response.Headers.Location;
        if (source is null || location is null ||
            !source.AbsolutePath.StartsWith("/v1/releases/blobs/", StringComparison.Ordinal) ||
            request.Headers.Authorization is not null ||
            request.Headers.Any(header => header.Key.StartsWith("X-Bifrost-Proof-", StringComparison.OrdinalIgnoreCase)))
            return false;

        Uri target;
        try { target = location.IsAbsoluteUri ? location : new Uri(source, location); }
        catch (UriFormatException) { return false; }
        if (!target.IsAbsoluteUri ||
            !string.Equals(target.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(target.Host, ReleaseBlobBaseUri.Host, StringComparison.OrdinalIgnoreCase) ||
            target.Port != 443 ||
            !string.IsNullOrEmpty(target.UserInfo) ||
            !string.IsNullOrEmpty(target.Query) ||
            !string.IsNullOrEmpty(target.Fragment) ||
            !string.Equals(target.AbsolutePath, source.AbsolutePath, StringComparison.Ordinal))
            return false;

        redirectUri = target;
        return true;
    }

    private static async Task<int> ReadArtifactBytesAsync(
        Stream input,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        using var idleDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idleDeadline.CancelAfter(ArtifactReadIdleTimeout);
        try
        {
            return await input.ReadAsync(buffer, idleDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested && idleDeadline.IsCancellationRequested)
        {
            throw new TimeoutException("BF-RELEASE-READ-IDLE", error);
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var result = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (result.Length + read > limit) throw new InvalidDataException("response exceeds size limit");
            result.Write(buffer, 0, read);
        }
        return result.ToArray();
    }

    private static Uri RequireCanonicalOrigin(Uri value)
    {
        if (!value.IsAbsoluteUri || !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(value.Host) || !string.IsNullOrEmpty(value.UserInfo) || !string.IsNullOrEmpty(value.Query) || !string.IsNullOrEmpty(value.Fragment) ||
            (value.AbsolutePath is not ("" or "/")) || value.Port != 443)
            throw new InvalidOperationException("BF-RELEASE-ORIGIN");
        return new UriBuilder(Uri.UriSchemeHttps, value.Host, 443).Uri;
    }

    private static void EnsureSuccessfulResponse(HttpResponseMessage response, bool requireJson)
    {
        if ((int)response.StatusCode is >= 300 and < 400) throw new InvalidDataException("BF-RELEASE-REDIRECT");
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException("BF-RELEASE-HTTP");
        if (requireJson)
        {
            var type = response.Content.Headers.ContentType;
            if (type is null || !string.Equals(type.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
                (type.CharSet is not null && !string.Equals(type.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("BF-RELEASE-CONTENT-TYPE");
        }
    }

    private static void EnsureSuccessfulArtifactResponse(HttpResponseMessage response)
    {
        // Retry only statuses that represent temporary server pressure or an
        // interrupted upstream. Redirects and permanent 4xx responses remain
        // hard failures and can move directly to the configured fallback.
        if (response.StatusCode is HttpStatusCode.RequestTimeout or
            HttpStatusCode.TooManyRequests or
            HttpStatusCode.InternalServerError or
            HttpStatusCode.BadGateway or
            HttpStatusCode.ServiceUnavailable or
            HttpStatusCode.GatewayTimeout)
            throw new HttpRequestException("BF-RELEASE-HTTP-TRANSIENT", null, response.StatusCode);
        EnsureSuccessfulResponse(response, requireJson: false);
    }

    private static JsonDocument ParseStrictJson(ReadOnlySpan<byte> bytes, int maxDepth)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = maxDepth });
        var objects = new Stack<HashSet<string>>();
        var sawToken = false;
        while (reader.Read())
        {
            sawToken = true;
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    objects.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.PropertyName:
                    if (objects.Count == 0 || !objects.Peek().Add(reader.GetString() ?? string.Empty)) throw new InvalidDataException("BF-RELEASE-DUPLICATE-KEY");
                    break;
                case JsonTokenType.EndObject:
                    if (objects.Count == 0) throw new InvalidDataException("BF-RELEASE-JSON");
                    objects.Pop();
                    break;
            }
        }
        if (!sawToken || objects.Count != 0 || reader.BytesConsumed != bytes.Length) throw new InvalidDataException("BF-RELEASE-JSON");
        // The locked toolchain does not expose the ReadOnlySpan overload of
        // JsonDocument.Parse; materialize one bounded copy after the reader
        // has already validated the exact byte range.
        var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = maxDepth });
        if (document.RootElement.ValueKind != JsonValueKind.Object) { document.Dispose(); throw new InvalidDataException("BF-RELEASE-JSON-ROOT"); }
        return document;
    }

    private static void RequireExactFields(JsonElement objectElement, IReadOnlyCollection<string> allowed, IReadOnlyCollection<string> required)
    {
        if (objectElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-RELEASE-OBJECT");
        var actual = objectElement.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (actual.Any(name => !allowed.Contains(name, StringComparer.Ordinal)) || required.Any(name => !actual.Contains(name))) throw new InvalidDataException("BF-RELEASE-FIELDS");
    }

    private static JsonElement RequireObject(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-RELEASE-OBJECT");
        return value;
    }

    private static string ReadRequiredString(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString())) throw new InvalidDataException("BF-RELEASE-FIELDS");
        return value.GetString()!;
    }

    private static long ReadRequiredPositiveInt64(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        if (value.ValueKind != JsonValueKind.Number) throw new InvalidDataException("BF-RELEASE-SEQUENCE");
        if (!Regex.IsMatch(value.GetRawText(), "^(?:0|-?[1-9][0-9]*)$", RegexOptions.CultureInvariant)) throw new InvalidDataException("BF-RELEASE-FIELDS");
        if (!value.TryGetInt64(out var result) || result < 1) throw new InvalidDataException("BF-RELEASE-SEQUENCE");
        return result;
    }

    private static byte[] ExtractRawPublicKey(string pem)
    {
        var der = PemEncoding.TryFind(pem.AsSpan(), out var fields) ? Convert.FromBase64String(pem[fields.Base64Data].ToString()) : throw new CryptographicException("BF-RELEASE-KEY");
        try
        {
            var prefix = Convert.FromHexString("302a300506032b6570032100");
            if (der.Length != prefix.Length + 32 || !der.AsSpan(0, prefix.Length).SequenceEqual(prefix)) throw new CryptographicException("BF-RELEASE-KEY");
            return der.AsSpan(prefix.Length, 32).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    private static byte[] FromBase64Url(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(ch => ch is < '!' or > '~' || ch is not ('-' or '_' or >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9')))
            throw new CryptographicException("BF-RELEASE-BASE64");
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        var bytes = Convert.FromBase64String(normalized);
        if (!Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_').Equals(value, StringComparison.Ordinal)) throw new CryptographicException("BF-RELEASE-BASE64");
        return bytes;
    }

    private static string SafeRelative(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 240 || Path.IsPathRooted(value) || value.Contains('\0') || value.Contains(':')) throw new InvalidDataException("BF-RELEASE-PATH");
        var normalized = value.Replace('\\', '/');
        var parts = normalized.Split('/');
        if (normalized.Normalize(NormalizationForm.FormC) != normalized || parts.Any(part => part.Length == 0 || part == "." || part == ".." || part.EndsWith(' ') || part.EndsWith('.') || part.Any(char.IsControl) || IsDeviceName(part)) || normalized.StartsWith('/') || normalized.Any(char.IsControl)) throw new InvalidDataException("BF-RELEASE-PATH");
        return normalized;
    }

    private static bool IsDeviceName(string part)
    {
        var stem = part.Split('.', 2)[0].ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" || (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && stem[3] is >= '1' and <= '9');
    }

    private static ReleaseStateAuthority.State? ReadAuthorityState(string path)
    {
        FileStream stream;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        }
        catch (FileNotFoundException)
        {
            // Initial state is written only by the protected installer
            // transaction. The ordinary updater never trusts a path-local
            // marker or a caller-shaped bootstrap object.
            throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
        }
        try
        {
            using (stream)
            {
                if (stream.Length <= 0 || stream.Length > 16 * 1024) throw new InvalidDataException();
                var bytes = new byte[checked((int)stream.Length)];
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var read = stream.Read(bytes, offset, bytes.Length - offset);
                    if (read <= 0) throw new EndOfStreamException();
                    offset += read;
                }
                if (stream.ReadByte() != -1) throw new InvalidDataException();
                try
                {
                    using var json = ParseStrictJson(bytes, 8);
                    var root = json.RootElement;
                    var state = JsonSerializer.Deserialize<ReleaseStateAuthority.State>(bytes) ?? throw new InvalidDataException();
                    ReleaseStateAuthority.Validate(state);
                    return state;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }
        catch { throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT"); }
    }

    private static int CompareReleaseVersions(string left, string right)
    {
        static (int Major, int Minor, int Patch, string[] Pre) Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 128)
                throw new InvalidDataException("BF-RELEASE-VERSION");
            var pieces = value.Split('-', 2, StringSplitOptions.None);
            var core = pieces[0].Split('.', StringSplitOptions.None);
            if (core.Length != 3 || core.Any(part => part.Length == 0 || (part.Length > 1 && part[0] == '0') || !part.All(char.IsDigit)))
                throw new InvalidDataException("BF-RELEASE-VERSION");
            if (!int.TryParse(core[0], out var major) || !int.TryParse(core[1], out var minor) || !int.TryParse(core[2], out var patch) || major < 0 || minor < 0 || patch < 0)
                throw new InvalidDataException("BF-RELEASE-VERSION");
            var pre = pieces.Length == 1 ? Array.Empty<string>() : pieces[1].Split('.', StringSplitOptions.None);
            if (pieces.Length == 2 && (pre.Length == 0 || pre.Any(part => part.Length == 0 || !part.All(ch => char.IsLetterOrDigit(ch) || ch == '-') || (part.Length > 1 && part[0] == '0' && part.All(char.IsDigit)))))
                throw new InvalidDataException("BF-RELEASE-VERSION");
            return (major, minor, patch, pre);
        }

        var a = Parse(left);
        var b = Parse(right);
        var core = a.Major.CompareTo(b.Major);
        if (core != 0) return core;
        core = a.Minor.CompareTo(b.Minor);
        if (core != 0) return core;
        core = a.Patch.CompareTo(b.Patch);
        if (core != 0) return core;
        if (a.Pre.Length == 0 && b.Pre.Length == 0) return 0;
        if (a.Pre.Length == 0) return 1;
        if (b.Pre.Length == 0) return -1;
        for (var i = 0; i < Math.Max(a.Pre.Length, b.Pre.Length); i++)
        {
            if (i >= a.Pre.Length) return -1;
            if (i >= b.Pre.Length) return 1;
            var ai = a.Pre[i];
            var bi = b.Pre[i];
            var an = ai.All(char.IsDigit);
            var bn = bi.All(char.IsDigit);
            if (an && bn)
            {
                var cmp = ai.Length.CompareTo(bi.Length);
                if (cmp != 0) return cmp;
                cmp = string.CompareOrdinal(ai, bi);
                if (cmp != 0) return cmp;
            }
            else if (an != bn) return an ? -1 : 1;
            else
            {
                var cmp = string.CompareOrdinal(ai, bi);
                if (cmp != 0) return cmp;
            }
        }
        return 0;
    }

    private static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            var bytes = new UTF8Encoding(false, true).GetBytes(content);
            try
            {
                using var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    public void Dispose() => _http.Dispose();

    // The pending marker is an index, not an authority.  The operation
    // payload below is DPAPI-bound to the current Windows user and the exact
    // update inbox; the installer must decrypt and compare every field before
    // it can touch a staging tree or service.
    public sealed record PendingOperationRecord(
        string OperationId,
        string EnvelopeDigest,
        string ManifestDigest,
        string AllowlistDigest,
        long Sequence,
        long Floor,
        long AuthorityGeneration,
        string AuthorityDigest,
        string RequiredArtifactSet,
        string StageDirectory,
        string UpdateRoot,
        string InstallRoot,
        long ExpectedPreviousSequence,
        string StageIdentity = "",
        string ExpectedCurrentGeneration = "",
        string ExpectedCurrentEnvelopeDigest = "",
        string ExpectedCurrentManifestDigest = "",
        long ExpectedCurrentAuthorityGeneration = 0,
        string ExpectedCurrentAuthorityDigest = "",
        string ExpectedCurrentPointerDigest = "",
        string ExpectedInstallId = "");

    public static byte[] ProtectPendingOperation(PendingOperationRecord operation)
    {
            if (operation is null || string.IsNullOrWhiteSpace(operation.OperationId) || operation.Sequence < 1 || operation.Floor < 1 || !IsDigest(operation.StageIdentity) || string.IsNullOrWhiteSpace(operation.ExpectedCurrentGeneration) || !IsDigest(operation.ExpectedCurrentEnvelopeDigest) || !IsDigest(operation.ExpectedCurrentManifestDigest) || operation.ExpectedCurrentAuthorityGeneration < 1 || !IsDigest(operation.ExpectedCurrentAuthorityDigest) || !IsDigest(operation.ExpectedCurrentPointerDigest) || !Regex.IsMatch(operation.ExpectedInstallId, "^[A-Za-z0-9._-]{16,128}$", RegexOptions.CultureInvariant)) throw new InvalidDataException("BF-RELEASE-OPERATION");
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(operation));
        // Pending update state crosses the privilege boundary from the
        // interactive desktop client to the LocalSystem installer launched by
        // BifrostClientService.  CurrentUser DPAPI makes that handoff
        // undecryptable by design.  Installation-scoped state therefore uses
        // LocalMachine DPAPI; all mutable fields are still rebound to the
        // signed envelope, immutable install identity, current pointer digest
        // and verified staging-tree digest before promotion.
        try { return ProtectedData.Protect(bytes, Encoding.UTF8.GetBytes("Bifrost.ReleaseOperation.v2"), DataProtectionScope.LocalMachine); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private string ReadInstallIdForPendingOperation()
    {
        var path = Path.Combine(_installRoot, ".bifrost-state", "ownership.json");
        if (!File.Exists(path)) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
        var bytes = File.ReadAllBytes(path);
        try
        {
            using var document = ParseStrictJson(bytes, 8);
            var root = document.RootElement;
            if (root.EnumerateObject().Any(item => item.Name is not ("product_id" or "install_id" or "root_identity" or "state_schema" or "current_generation" or "previous_generation" or "state_digest" or "pointer_digest" or "ipc_binding_digest" or "ipc_interactive_sid" or "checksum" or "mac")) || root.GetProperty("product_id").GetString() != "bifrost.windows-client" || root.GetProperty("state_schema").GetString() != "bifrost-install-v2") throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
            var id = root.GetProperty("install_id").GetString();
            if (!Regex.IsMatch(id ?? "", "^[A-Za-z0-9._-]{16,128}$", RegexOptions.CultureInvariant) || root.GetProperty("ipc_binding_digest").GetString() is not { Length: 64 } || string.IsNullOrWhiteSpace(root.GetProperty("ipc_interactive_sid").GetString())) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
            var unsigned = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["product_id"] = root.GetProperty("product_id").GetString(), ["install_id"] = id,
                ["root_identity"] = root.GetProperty("root_identity").GetString(), ["state_schema"] = root.GetProperty("state_schema").GetString(),
                ["current_generation"] = root.GetProperty("current_generation").GetString(), ["previous_generation"] = root.GetProperty("previous_generation").GetString(),
                ["state_digest"] = root.GetProperty("state_digest").GetString(), ["pointer_digest"] = root.GetProperty("pointer_digest").GetString(),
                ["ipc_binding_digest"] = root.GetProperty("ipc_binding_digest").GetString(), ["ipc_interactive_sid"] = root.GetProperty("ipc_interactive_sid").GetString()
            };
            var canonical = JsonSerializer.Serialize(unsigned);
            var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            if (!string.Equals(checksum, root.GetProperty("checksum").GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
            var protectedBytes = Convert.FromBase64String(root.GetProperty("mac").GetString() ?? string.Empty);
            try
            {
                var clear = UnprotectInstallationState(protectedBytes, "Bifrost.InstallOwnership.v2");
                try { if (!CryptographicOperations.FixedTimeEquals(clear, Encoding.UTF8.GetBytes(canonical))) throw new CryptographicException(); }
                finally { CryptographicOperations.ZeroMemory(clear); }
            }
            finally { CryptographicOperations.ZeroMemory(protectedBytes); }
            return id!;
        }
        catch { throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private string ReadCurrentGenerationForPendingOperation()
    {
        var path = Path.Combine(_installRoot, ".bifrost-state", "current.json");
        if (!File.Exists(path)) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
        var bytes = File.ReadAllBytes(path);
        try
        {
            using var document = ParseStrictJson(bytes, 8);
            var value = document.RootElement;
            var generation = value.GetProperty("current_generation").GetString();
            if (string.IsNullOrWhiteSpace(generation) || generation.Length > 128 || generation.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.'))) throw new InvalidDataException();
            return generation;
        }
        catch { throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string DigestFileForPendingOperation(string path)
    {
        if (!File.Exists(path)) throw new InvalidDataException("BF-RELEASE-STATE-CORRUPT");
        var bytes = File.ReadAllBytes(path);
        try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static PendingOperationRecord UnprotectPendingOperation(byte[] protectedBytes)
    {
        if (protectedBytes is null || protectedBytes.Length is < 32 or > 64 * 1024) throw new InvalidDataException("BF-RELEASE-OPERATION");
        byte[] bytes;
        try { bytes = UnprotectInstallationState(protectedBytes, "Bifrost.ReleaseOperation.v2"); }
        catch { throw new CryptographicException("BF-RELEASE-OPERATION"); }
        try
        {
            var operation = JsonSerializer.Deserialize<PendingOperationRecord>(bytes) ?? throw new InvalidDataException("BF-RELEASE-OPERATION");
            if (!Regex.IsMatch(operation.OperationId, "^[A-Za-z0-9._-]{8,128}$", RegexOptions.CultureInvariant) || operation.Sequence < 1 || operation.Floor < 1 || operation.AuthorityGeneration < 1 || !IsDigest(operation.EnvelopeDigest) || !IsDigest(operation.ManifestDigest) || !IsDigest(operation.AllowlistDigest) || !IsDigest(operation.AuthorityDigest) || !IsDigest(operation.StageIdentity) || string.IsNullOrWhiteSpace(operation.ExpectedCurrentGeneration) || !IsDigest(operation.ExpectedCurrentEnvelopeDigest) || !IsDigest(operation.ExpectedCurrentManifestDigest) || operation.ExpectedCurrentAuthorityGeneration < 1 || !IsDigest(operation.ExpectedCurrentAuthorityDigest) || !IsDigest(operation.ExpectedCurrentPointerDigest) || !Regex.IsMatch(operation.ExpectedInstallId, "^[A-Za-z0-9._-]{16,128}$", RegexOptions.CultureInvariant) || string.IsNullOrWhiteSpace(operation.RequiredArtifactSet) || !Path.IsPathFullyQualified(operation.StageDirectory) || !Path.IsPathFullyQualified(operation.UpdateRoot) || !Path.IsPathFullyQualified(operation.InstallRoot) || operation.ExpectedPreviousSequence < 0) throw new InvalidDataException("BF-RELEASE-OPERATION");
            return operation;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] UnprotectInstallationState(byte[] protectedBytes, string aad)
    {
        var entropy = Encoding.UTF8.GetBytes(aad);
        try
        {
            try { return ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.LocalMachine); }
            catch
            {
                // Compatibility bridge for installations created before the
                // LocalSystem updater handoff was corrected.  Any successful
                // install/update rewrites the state using LocalMachine scope.
                return ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.CurrentUser);
            }
        }
        finally { CryptographicOperations.ZeroMemory(entropy); }
    }

    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(ch => Uri.IsHexDigit(ch)) && value == value.ToLowerInvariant();

    private static string FingerprintPem(string pem)
    {
        var der = ExportPublicDer(pem);
        try { return Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    // Plans are verifier-owned capabilities.  Public mutable/constructible
    // records let a caller forge an allowlist or swap artifacts after
    // verification, so construction is internal and collections are copied
    // into read-only snapshots.
    public sealed class Artifact
    {
        public string Id { get; }
        public string Path { get; }
        public string? InstallPath { get; }
        public string Platform { get; }
        public string Arch { get; }
        public string Kind { get; }
        public long Bytes { get; }
        public string Sha256 { get; }
        public string? SourceBundle { get; }
        public string? Notice { get; }
        public IReadOnlyList<string> Dependencies { get; }
        internal Artifact(string path, string? installPath, string platform, string arch, string kind, long bytes, string sha256, string? sourceBundle = null, string? notice = null, IReadOnlyList<string>? dependencies = null, string? id = null)
        {
            Id = id ?? string.Empty; Path = path; InstallPath = installPath; Platform = platform; Arch = arch; Kind = kind; Bytes = bytes; Sha256 = sha256; SourceBundle = sourceBundle; Notice = notice;
            Dependencies = Array.AsReadOnly((dependencies ?? Array.Empty<string>()).ToArray());
        }
    }
    public sealed class VerifiedReleasePlan
    {
        public string EnvelopeDigest { get; }
        public string ManifestDigest { get; }
        public string AllowlistDigest { get; }
        public long Sequence { get; }
        public string? Channel { get; }
        public long Floor { get; }
        public string? RootKeyId { get; }
        public string? RootFingerprint { get; }
        public string? AuthorityDigest { get; }
        public long AuthorityGeneration { get; }
        public long DelegationGeneration { get; }
        public string? SigningKeyId { get; }
        public string? SigningKeyFingerprint { get; }
        public bool HasTransition { get; }
        public IReadOnlyList<Artifact> Artifacts { get; }
        internal VerifiedReleasePlan(string envelopeDigest, string manifestDigest, string allowlistDigest, long sequence, string? channel, long floor, string? rootKeyId, string? rootFingerprint, string? authorityDigest, long authorityGeneration, long delegationGeneration, string? signingKeyId, string? signingKeyFingerprint, bool hasTransition, IReadOnlyList<Artifact> artifacts)
        {
            EnvelopeDigest = envelopeDigest; ManifestDigest = manifestDigest; AllowlistDigest = allowlistDigest; Sequence = sequence; Channel = channel; Floor = floor; RootKeyId = rootKeyId; RootFingerprint = rootFingerprint; AuthorityDigest = authorityDigest; AuthorityGeneration = authorityGeneration; DelegationGeneration = delegationGeneration; SigningKeyId = signingKeyId; SigningKeyFingerprint = signingKeyFingerprint; HasTransition = hasTransition;
            Artifacts = Array.AsReadOnly(artifacts.ToArray());
        }
    }
    public sealed class VerifiedEnvelope
    {
        public long Sequence { get; }
        public string ManifestText { get; }
        public string SignatureText { get; }
        public IReadOnlyList<Artifact> Artifacts { get; }
        public VerifiedReleasePlan? Plan { get; }
        internal VerifiedEnvelope(long sequence, string manifestText, string signatureText, IReadOnlyList<Artifact> artifacts, VerifiedReleasePlan? plan = null)
        {
            Sequence = sequence; ManifestText = manifestText; SignatureText = signatureText; Artifacts = Array.AsReadOnly(artifacts.ToArray()); Plan = plan;
        }
    }
}

/// <summary>Operator-owned HTTPS transport alias selected with credential-free
/// health requests before sending the original request exactly once.</summary>
internal sealed class BifrostControlRelayHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private const string Relay = "https://bifrost-client-entry.pages.dev";
    private readonly SemaphoreSlim _selection = new(1, 1);
    private bool _relay;
    private DateTimeOffset _expires;

    internal static Uri? Alternate(Uri uri)
    {
        if (uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0) return null;
        var control = uri.Host == "edge.bifrostlog.com" && uri.AbsolutePath.StartsWith("/v1/", StringComparison.Ordinal) && !uri.AbsolutePath.StartsWith("/v1/admin/", StringComparison.Ordinal);
        var blob = uri.Host == "bifrostlog.com" && Regex.IsMatch(uri.AbsolutePath, "^/v1/releases/blobs/[0-9a-f]{64}/[A-Za-z0-9._-]+\\.bin$");
        return control || blob ? new Uri(Relay + uri.AbsolutePath) : null;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var original = request.RequestUri!;
        var alternate = Alternate(original);
        if (alternate is null) return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await _selection.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow >= _expires)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                async Task<bool?> Probe(bool relay)
                {
                    try
                    {
                        using var health = new HttpRequestMessage(HttpMethod.Get, (relay ? Relay : "https://edge.bifrostlog.com") + "/health");
                        using var response = await base.SendAsync(health, deadline.Token).ConfigureAwait(false);
                        return response.StatusCode == HttpStatusCode.OK ? relay : null;
                    }
                    catch (HttpRequestException) { return null; }
                    catch (OperationCanceledException) { return null; }
                }
                var pending = new List<Task<bool?>> { Probe(false), Probe(true) };
                _relay = false;
                while (pending.Count > 0)
                {
                    var completed = await Task.WhenAny(pending).ConfigureAwait(false);
                    pending.Remove(completed);
                    if (await completed.ConfigureAwait(false) is bool selected)
                    {
                        _relay = selected;
                        _expires = DateTimeOffset.UtcNow.AddMinutes(2);
                        break;
                    }
                }
                deadline.Cancel();
                await Task.WhenAll(pending).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (_relay) request.RequestUri = alternate;
        }
        finally { _selection.Release(); }
        try { return await base.SendAsync(request, cancellationToken).ConfigureAwait(false); }
        catch (HttpRequestException) { _expires = default; throw; }
        finally { request.RequestUri = original; }
    }
}

public sealed record ReleaseUpdateProgress(int Percent, string Stage, string Message);

public sealed record ReleaseCheckResult(string State, long Sequence, string Message, string? StageDirectory)
{
#if false
    public bool SignatureVerified => State is "verified" or "staged" or "up-to-date";
    public static ReleaseCheckResult Disabled(string message) => new("disabled", 0, message, null);
    public static ReleaseCheckResult NoRelease(string message) => new("unavailable", 0, message, null);
    public static ReleaseCheckResult UpToDate(long sequence) => new("up-to-date", sequence, "已经是最新签名发布", null);
    public static ReleaseCheckResult Verified(long sequence, string message) => new("verified", sequence, message, null);
    public static ReleaseCheckResult Staged(long sequence, string stage) => new("staged", sequence, "签名发布已校验并交给外部更新器", stage);
#endif
    public bool SignatureVerified => State is "verified" or "staged" or "up-to-date";
    public static ReleaseCheckResult Disabled(string message) => new("disabled", 0, message, null);
    public static ReleaseCheckResult NoRelease(string message) => new("unavailable", 0, message, null);
    public static ReleaseCheckResult UpToDate(long sequence) => new("up-to-date", sequence, "BF-RELEASE-UP-TO-DATE", null);
    public static ReleaseCheckResult Verified(long sequence, string message) => new("verified", sequence, message, null);
    public static ReleaseCheckResult Staged(long sequence, string stage) => new("staged", sequence, "BF-RELEASE-STAGED", stage);
}

// Small, allocation-safe Ed25519 verifier used on Windows versions where the
// platform provider is unavailable. It rejects malformed points and non-canonical S.
internal static class Ed25519
{
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, P - 2, P));
    private static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
    private static readonly Point Base = new(BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"), BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

    /// <summary>
    /// RFC 8032 Ed25519 signing.  Windows client enrollment cannot rely on
    /// ECDsa.Create("ed25519"): Ed25519 is EdDSA and that API is provider
    /// dependent (and absent on supported Windows/.NET combinations).  This
    /// implementation shares the verifier arithmetic below and keeps the
    /// protocol representation identical to Node/Android: a 32-byte seed,
    /// 32-byte raw public key and a 64-byte raw signature.
    /// </summary>
    public static byte[] Sign(byte[] message, byte[] seed, out byte[] publicKey)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes", nameof(seed));
        var expanded = SHA512.HashData(seed);
        expanded[0] &= 248;
        expanded[31] &= 63;
        expanded[31] |= 64;
        var scalar = FromLittleEndian(expanded[..32]);
        var point = Multiply(Base, scalar);
        publicKey = Encode(point);

        var nonceInput = new byte[32 + message.Length];
        Buffer.BlockCopy(expanded, 32, nonceInput, 0, 32);
        Buffer.BlockCopy(message, 0, nonceInput, 32, message.Length);
        var nonce = FromLittleEndian(SHA512.HashData(nonceInput)) % L;
        var encodedR = Encode(Multiply(Base, nonce));
        var challengeInput = new byte[32 + 32 + message.Length];
        Buffer.BlockCopy(encodedR, 0, challengeInput, 0, 32);
        Buffer.BlockCopy(publicKey, 0, challengeInput, 32, 32);
        Buffer.BlockCopy(message, 0, challengeInput, 64, message.Length);
        var challenge = FromLittleEndian(SHA512.HashData(challengeInput)) % L;
        var s = (nonce + challenge * scalar) % L;
        var signature = new byte[64];
        Buffer.BlockCopy(encodedR, 0, signature, 0, 32);
        Buffer.BlockCopy(ToLittleEndian(s, 32), 0, signature, 32, 32);
        return signature;
    }

    public static byte[] GenerateSeed() => RandomNumberGenerator.GetBytes(32);

    public static byte[] DerivePublicKey(byte[] seed)
    {
        _ = Sign(Array.Empty<byte>(), seed, out var publicKey);
        return publicKey;
    }

    public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
    {
        try
        {
            if (signature.Length != 64 || publicKey.Length != 32) return false;
            var rBytes = signature[..32]; var s = FromLittleEndian(signature[32..]); if (s >= L) return false;
            var a = Decode(publicKey); var r = Decode(rBytes);
            var hashInput = new byte[64 + message.Length]; Buffer.BlockCopy(rBytes, 0, hashInput, 0, 32); Buffer.BlockCopy(publicKey, 0, hashInput, 32, 32); Buffer.BlockCopy(message, 0, hashInput, 64, message.Length);
            var h = FromLittleEndian(SHA512.HashData(hashInput)) % L;
            return Equal(Multiply(Base, s), Add(r, Multiply(a, h)));
        }
        catch { return false; }
    }

    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)
    {
        public Point(BigInteger x, BigInteger y) : this(x, y, BigInteger.One, Mod(x * y)) { }
    }

    private static Point Decode(byte[] encoded)
    {
        var bytes = encoded.ToArray(); var sign = (bytes[31] & 0x80) != 0; bytes[31] &= 0x7f; var y = FromLittleEndian(bytes); if (y >= P) throw new CryptographicException("non-canonical point");
        var y2 = Mod(y * y); var x2 = Mod((y2 - 1) * BigInteger.ModPow(Mod(D * y2 + 1), P - 2, P)); var x = BigInteger.ModPow(x2, (P + 3) / 8, P); if (Mod(x * x - x2) != 0) x = Mod(x * I); if (Mod(x * x - x2) != 0) throw new CryptographicException("invalid point"); if (((x & 1) != 0) != sign) x = P - x; return new Point(x, y);
    }

    private static Point Add(Point p, Point q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X)); var b = Mod((p.Y + p.X) * (q.Y + q.X)); var c = Mod(2 * D * p.T * q.T); var d = Mod(2 * p.Z * q.Z); var e = Mod(b - a); var f = Mod(d - c); var g = Mod(d + c); var h = Mod(b + a); return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Double(Point p)
    {
        var a = Mod(p.X * p.X); var b = Mod(p.Y * p.Y); var c = Mod(2 * p.Z * p.Z); var d = Mod(-a); var e = Mod((p.X + p.Y) * (p.X + p.Y) - a - b); var g = Mod(d + b); var f = Mod(g - c); var h = Mod(d - b); return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Point Multiply(Point point, BigInteger scalar)
    {
        var result = new Point(BigInteger.Zero, BigInteger.One); var addend = point; for (var bit = 0; bit < 256; bit++) { if (((scalar >> bit) & 1) != 0) result = Add(result, addend); addend = Double(addend); } return result;
    }

    private static bool Equal(Point a, Point b) => Mod(a.X * b.Z - b.X * a.Z) == 0 && Mod(a.Y * b.Z - b.Y * a.Z) == 0;
    private static BigInteger FromLittleEndian(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: false);
    private static byte[] ToLittleEndian(BigInteger value, int length)
    {
        var result = new byte[length];
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (bytes.Length > length) throw new CryptographicException("integer does not fit");
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }

    private static byte[] Encode(Point point)
    {
        var inverseZ = BigInteger.ModPow(point.Z, P - 2, P);
        var x = Mod(point.X * inverseZ);
        var y = Mod(point.Y * inverseZ);
        var result = ToLittleEndian(y, 32);
        if ((x & BigInteger.One) != 0) result[31] |= 0x80;
        return result;
    }

    private static BigInteger Mod(BigInteger value) { var result = value % P; return result < 0 ? result + P : result; }
}
