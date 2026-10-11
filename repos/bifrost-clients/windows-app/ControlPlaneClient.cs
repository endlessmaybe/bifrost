using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Numerics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.Release;
using Bifrost.ClientService;

namespace Bifrost;

/// <summary>Native Windows control-plane client; state is DPAPI protected.</summary>
public sealed class BifrostControlClient : IDisposable
{
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private const string ConfigKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAEfImTB3NTAc2b44XLcA0a67Dj3+Ohh0js+AhJkizsBo=\n-----END PUBLIC KEY-----";
    private static string ConfigSigningKeyPem => string.IsNullOrWhiteSpace(BifrostBuildConstants.TestConfigSigningPublicKey) ? ConfigKey : BifrostBuildConstants.TestConfigSigningPublicKey;
    private const int MaxResponseBytes = 1024 * 1024;
    private const int MaxJsonDepth = 8;
    private const int MaxJsonProperties = 4096;
    private const int MaxJsonArrayItems = 1024;
    private const int MaxJsonTokens = 16384;
    private const int MaxJsonStringBytes = 64 * 1024;
    private const int MaxConfigPlaintextBytes = 512 * 1024;
    private const int MaxStatePlaintextBytes = 1024 * 1024;
    private const int MaxStateProtectedBytes = 2 * 1024 * 1024;
    // A source is usable while any signed candidate remains healthy. Probe the
    // complete signed set (the service contract caps it at 600) while bounding
    // simultaneous sockets so a large source cannot spike the host network.
    private const int MaxProbeCandidates = 600;
    // Network probes are I/O-bound. Scale beyond the old fixed four-socket
    // ceiling on modern x64 hosts, but retain a hard cap so a 600-candidate
    // source cannot turn one refresh into a connection storm.
    private static readonly int MaxProbeConcurrency = Math.Clamp(Environment.ProcessorCount, 4, 16);
    private const int ProbeCacheVersion = 3;
    private static readonly TimeSpan RequestDeadline = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan SessionRenewalSkew = TimeSpan.FromMinutes(5);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions StateJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = MaxJsonDepth
    };
    private static readonly HashSet<string> StatePropertyNames = new(StringComparer.Ordinal)
    {
        nameof(ControlState.ControlUrl), nameof(ControlState.PublicId), nameof(ControlState.DeviceId),
        nameof(ControlState.RecoveryCode), nameof(ControlState.RecoveryPending), nameof(ControlState.RecoveryDeliveryIdempotency),
        nameof(ControlState.EnrollmentInviteFingerprint), nameof(ControlState.EnrollmentIdempotency),
        nameof(ControlState.SessionToken), nameof(ControlState.SessionExpiresAtUnixMilliseconds), nameof(ControlState.SigningSeed),
        nameof(ControlState.SigningPrivatePkcs8), nameof(ControlState.SigningPublicKey),
        nameof(ControlState.EncryptionPrivatePkcs8), nameof(ControlState.EncryptionPublicKey),
        nameof(ControlState.ConfigJson), nameof(ControlState.ConfigVersion), nameof(ControlState.ConfigDigest), nameof(ControlState.ConfigEnvelopeJson),
        nameof(ControlState.ConfigKeyStateJson), nameof(ControlState.ConfigKeyStateGeneration), nameof(ControlState.ConfigKeyStateDigest)
    };
    // 2.1.35-2.1.37 could migrate an otherwise valid production state from the
    // dedicated client edge to the apex site.  The apex serves immutable
    // release blobs, but it is not the authenticated Control API: production
    // device/enrollment/release-manifest routes live on edge.bifrostlog.com.
    // Accept exactly the corrective apex -> edge migration for a fully
    // validated enrolled DPAPI state.  Arbitrary origin changes continue to
    // fail closed.
    private const string HistoricalProductionControlOrigin = "https://bifrostlog.com";
    private const string CurrentProductionControlOrigin = "https://edge.bifrostlog.com";
    private readonly HttpClient _http;
    private readonly CandidateProbeEngine _probeEngine = new();
    private readonly WindowsNetworkBucket _networkBucket;
    private readonly object _networkProbeGate = new();
    private CancellationTokenSource _networkProbeCancellation = new();
    private long _probeRoundGeneration;
    private long _physicalNetworkGeneration;
    private string _networkProbeEpoch = Guid.NewGuid().ToString("N");
    private string? _physicalIpv4GatewaySignature;
    private readonly NetworkAddressChangedEventHandler _networkAddressChangedHandler;
    private readonly NetworkAvailabilityChangedEventHandler _networkAvailabilityChangedHandler;
    private string _stateFile;
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly SemaphoreSlim _enrollmentGate = new(1, 1);
    // Candidate selection is a bounded local/network round shared by connect
    // and the lifecycle owner. Serialize callers so an identical later round
    // can consume the fresh cache written by the first instead of probing the
    // same signed source twice. Cancellation still releases the gate.
    private readonly SemaphoreSlim _candidateSelectionGate = new(1, 1);
    private readonly TrustedControlOrigin? _trustedOrigin;
    private readonly string _configurationStatus;
    private ControlState _state;
    private byte[]? _lifecycleTrustedConfigKey;
    private bool _lifecycleOnly;

    /// Raised from the OS network event thread.  The WPF caller debounces it
    /// on its dispatcher and starts a new probe generation; no live tunnel is
    /// hot-swapped by this notification.
    public event Action? NetworkProbeInvalidated;

    public BifrostControlClient() : this(false, null) { }

#if BIFROST_TEST_HARNESS
    /// <summary>
    /// Headless, read-only production-state loader used only by the local live
    /// diagnostic fixture.  It deliberately bypasses the fixture assembly's
    /// unconfigured build origin while retaining the normal DPAPI and state
    /// validation path.  No shipping build contains this entry point.
    /// </summary>
    internal static BifrostControlClient CreateLiveDiagnosticClientForTest()
    {
        var client = new BifrostControlClient(screenshotOnly: true);
        client._lifecycleOnly = true;
        var stateFile = Path.Combine(ResolveClientStateRoot("secure"), "control-state.bin");
        client._stateFile = stateFile;
        byte[]? protectedBytes = null;
        byte[]? plaintext = null;
        try
        {
            // The release fixture intentionally has no production release
            // authority compiled into it, so the normal full LoadState gate
            // cannot validate the persisted update trust binding.  For this
            // explicit live-node diagnostic only, DPAPI authenticates the
            // current user's blob and we then accept only the minimal,
            // structurally valid config projection needed by local probes.
            protectedBytes = BifrostIpcWire.ReadBoundedFile(stateFile, MaxStateProtectedBytes);
            plaintext = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            var state = JsonSerializer.Deserialize<ControlState>(plaintext, StateJsonOptions)
                ?? throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            // A device can be enrolled and retain a valid session before its
            // first signed configuration has arrived.  The live diagnostic is
            // specifically used to refresh that state, so an empty ConfigJson
            // must not be parsed as JSON or treated as a corrupt identity.
            var hasConfig = !string.IsNullOrWhiteSpace(state.ConfigJson);
            var config = hasConfig ? JsonNode.Parse(state.ConfigJson!) as JsonObject : null;
            if (!TrustedControlOrigin.TryParse(state.ControlUrl, out _) ||
                (hasConfig && (state.ConfigVersion <= 0 || config?["sources"] is not JsonArray)))
                throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            client._state = state;
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        }
        return client;
    }
#endif

#if BIFROST_TEST_HARNESS
    internal BifrostControlClient(bool screenshotOnly, HttpMessageHandler? transport = null)
#else
    private BifrostControlClient(bool screenshotOnly, HttpMessageHandler? transport = null)
#endif
    {
        _http = new HttpClient(transport ?? new Bifrost.Release.BifrostControlRelayHandler(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            // Respect the OS-configured proxy.  In regions/networks where a
            // direct TLS path to the public Control edge is unavailable, the
            // previous UseProxy=false setting made enrollment, config refresh
            // and release discovery fail even though Windows had a working
            // local/system proxy.  HTTPS certificate validation and the
            // root-signed config/release envelopes remain the authority; the
            // proxy is transport only and receives no implicit Windows creds.
            UseProxy = true,
            DefaultProxyCredentials = null,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            MaxConnectionsPerServer = Math.Clamp(Environment.ProcessorCount * 2, 8, 32),
            EnableMultipleHttp2Connections = false,
        }))
        {
            Timeout = RequestDeadline,
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Bifrost", "1.0"));
        if (screenshotOnly)
        {
            _trustedOrigin = null;
            _configurationStatus = "TEST-ONLY";
            _stateFile = string.Empty;
            _state = new ControlState();
            _networkBucket = new WindowsNetworkBucket(string.Empty, () => null, initialize: false);
            _networkAddressChangedHandler = (_, _) => { };
            _networkAvailabilityChangedHandler = (_, _) => { };
            return;
        }
        _trustedOrigin = TrustedControlOrigin.Compiled;
        _configurationStatus = _trustedOrigin is null ? TrustedControlOrigin.CompiledStatus : "CONFIGURED";
        if (_trustedOrigin is null)
        {
            // An unconfigured audit build must fail before key creation,
            // state-file access, network buckets, or OS network callbacks.
            _stateFile = string.Empty;
            _state = new ControlState();
            _networkBucket = new WindowsNetworkBucket(string.Empty, () => null, initialize: false);
            _networkAddressChangedHandler = (_, _) => { };
            _networkAvailabilityChangedHandler = (_, _) => { };
            return;
        }
        var root = ResolveClientStateRoot("secure");
        Directory.CreateDirectory(root);
        _stateFile = Path.Combine(root, "control-state.bin");
        try
        {
            _state = LoadState(_stateFile);
            if (!string.IsNullOrEmpty(_state.ControlUrl) && !string.Equals(_state.ControlUrl, _trustedOrigin.Value, StringComparison.Ordinal))
            {
                if (TryMigrateHistoricalProductionState(_stateFile, _state, _trustedOrigin, out var migrated))
                {
                    _state = migrated;
                    _configurationStatus = "CONFIGURED";
                }
                else
                {
                    _state = new ControlState();
                    _configurationStatus = "BF-CONTROL-ORIGIN-MISMATCH";
                }
            }
        }
        catch (InvalidDataException)
        {
            // Release promotion from the historical LocalEvaluation control
            // origin to the signed public edge must not consume a second
            // invitation or mint a new device identity.  Accept exactly that
            // one-way migration after the full DPAPI payload, keys and config
            // have passed the normal state validators; arbitrary HTTP origins
            // and production-origin changes continue to fail closed.
            if (TryMigrateLegacyLocalEvaluationState(_stateFile, _trustedOrigin, out var migrated))
            {
                _state = migrated;
                _configurationStatus = "CONFIGURED";
            }
            else
            {
                _state = new ControlState();
                _configurationStatus = "BF-CONTROL-STATE-CORRUPT";
            }
        }
        _networkBucket = new WindowsNetworkBucket(ResolveClientStateRoot("runtime"));
        _physicalIpv4GatewaySignature = TryGetPhysicalIpv4GatewaySignature();
        _networkAddressChangedHandler = (_, _) => OnNetworkTopologyChanged();
        _networkAvailabilityChangedHandler = (_, _) => OnNetworkTopologyChanged();
        NetworkChange.NetworkAddressChanged += _networkAddressChangedHandler;
        NetworkChange.NetworkAvailabilityChanged += _networkAvailabilityChangedHandler;
    }

    /// <summary>
    /// Narrow lifecycle seam: it uses the production refresh, sender/session,
    /// DPAPI state reader and offline classifier against an explicitly supplied
    /// loopback origin.  It is not reachable from a release caller.
    /// </summary>
    internal static BifrostControlClient CreateLifecycleRefreshClient(string stateFile, string loopbackOrigin, HttpMessageHandler transport)
    {
        if (!Path.IsPathFullyQualified(stateFile) || !Uri.TryCreate(loopbackOrigin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp || uri.Host is not ("127.0.0.1" or "localhost" or "::1") ||
            uri.Port is < 1 or > 65535)
            throw new InvalidDataException("BF-TEST-SCOPE");
        var client = new BifrostControlClient(screenshotOnly: true, transport) { _lifecycleOnly = true, _stateFile = stateFile };
        client._state = LoadState(stateFile);
        client._state.ControlUrl = uri.GetLeftPart(UriPartial.Authority);
        client._state.SessionToken = "TEST-ONLY-lifecycle-session";
        client._state.SessionExpiresAtUnixMilliseconds = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds();
        return client;
    }

    /// <summary>TEST-ONLY client for the lost-enrollment-response identity recovery path.</summary>
    internal static BifrostControlClient CreateEnrollmentIdentityClientForTest(string stateFile, string loopbackOrigin, HttpMessageHandler transport)
    {
        if (!Path.IsPathFullyQualified(stateFile) || !Uri.TryCreate(loopbackOrigin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp || uri.Host is not ("127.0.0.1" or "localhost" or "::1") || uri.Port is < 1 or > 65535)
            throw new InvalidDataException("BF-TEST-SCOPE");
        var client = new BifrostControlClient(screenshotOnly: true, transport) { _lifecycleOnly = true, _stateFile = stateFile };
        client._state = client.EnsureKeys(new ControlState(), persist: false);
        client._state.ControlUrl = uri.GetLeftPart(UriPartial.Authority);
        client._state.SessionToken = "TEST-ONLY-legacy-session-token";
        client._state.SessionExpiresAtUnixMilliseconds = 0;
        return client;
    }

    /// <summary>TEST-ONLY seed for replacing a stale pending enrollment after Control proves the old device row is absent.</summary>
    internal static BifrostControlClient CreatePendingEnrollmentReplacementClientForTest(
        string stateFile,
        string loopbackOrigin,
        HttpMessageHandler transport,
        string oldInviteCode)
    {
        if (!Path.IsPathFullyQualified(stateFile) || string.IsNullOrWhiteSpace(oldInviteCode) ||
            !Uri.TryCreate(loopbackOrigin, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            uri.Host is not ("127.0.0.1" or "localhost" or "::1") || uri.Port is < 1 or > 65535)
            throw new InvalidDataException("BF-TEST-SCOPE");
        var client = new BifrostControlClient(screenshotOnly: true, transport) { _lifecycleOnly = true, _stateFile = stateFile };
        client._state = client.EnsureKeys(new ControlState(), persist: false);
        client._state.ControlUrl = uri.GetLeftPart(UriPartial.Authority);
        client._state.EnrollmentInviteFingerprint = EnrollmentInviteFingerprint(oldInviteCode.Trim());
        client._state.EnrollmentIdempotency = "TEST-ONLY-old-enrollment-idempotency-0001";
        SaveState(stateFile, client._state, allowLifecycleOrigin: true);
        return client;
    }

    /// <summary>TEST-ONLY loader for a persisted enrollment state used by the isolated real-Control replacement fixture.</summary>
    internal static BifrostControlClient CreatePersistedEnrollmentClientForTest(
        string stateFile,
        string loopbackOrigin,
        HttpMessageHandler transport)
    {
        if (!Path.IsPathFullyQualified(stateFile) || !File.Exists(stateFile) ||
            !Uri.TryCreate(loopbackOrigin, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            uri.Host is not ("127.0.0.1" or "localhost" or "::1") || uri.Port is < 1 or > 65535)
            throw new InvalidDataException("BF-TEST-SCOPE");
        var client = new BifrostControlClient(screenshotOnly: true, transport) { _lifecycleOnly = true, _stateFile = stateFile };
        client._state = LoadState(stateFile, allowLifecycleOrigin: true);
        if (!string.Equals(client._state.ControlUrl, uri.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal))
            throw new InvalidDataException("BF-TEST-SCOPE");
        return client;
    }

    /// <summary>TEST-ONLY marker that reproduces the old-client pending-enrollment residue without changing the retained identity.</summary>
    internal void MarkPendingEnrollmentForTest(string inviteCode)
    {
        if (!_lifecycleOnly || string.IsNullOrWhiteSpace(inviteCode) || string.IsNullOrWhiteSpace(_state.DeviceId))
            throw new InvalidDataException("BF-TEST-SCOPE");
        var pending = CloneState(_state);
        pending.EnrollmentInviteFingerprint = EnrollmentInviteFingerprint(inviteCode.Trim());
        pending.EnrollmentIdempotency = $"TEST-ONLY-pending-enrollment-{Guid.NewGuid():N}";
        SaveState(_stateFile, pending, allowLifecycleOrigin: true);
        _state = pending;
    }

    internal async Task RestoreSessionIdentityForTestAsync(CancellationToken cancellationToken = default)
        => await EnsureEnrollmentIdentitySessionAsync(cancellationToken).ConfigureAwait(false);

    internal async Task EnsureSessionForTestAsync(CancellationToken cancellationToken = default)
        => await EnsureSessionAsync(null, cancellationToken).ConfigureAwait(false);

    internal void ExpireSessionForTest()
    {
        if (string.IsNullOrWhiteSpace(_state.SessionToken)) throw new InvalidOperationException("BF-TEST-SCOPE");
        var candidate = CloneState(_state);
        candidate.SessionExpiresAtUnixMilliseconds = DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeMilliseconds();
        SaveState(_stateFile, candidate, allowLifecycleOrigin: _lifecycleOnly);
        _state = candidate;
    }

    internal string? PublicIdForTest => _state.PublicId;
    internal string? DeviceIdForTest => _state.DeviceId;
    internal string? EnrollmentInviteFingerprintForTest => _state.EnrollmentInviteFingerprint;
    internal string? EnrollmentIdempotencyForTest => _state.EnrollmentIdempotency;
    internal bool EnrollmentCandidateExistsForTest => File.Exists(EnrollmentCandidateStateFile(_stateFile));

    /// <summary>TEST-ONLY state seed for the injected HTTP refresh boundary.</summary>
    internal static void SeedLifecycleRefreshStateForTest(string stateFile, long version, string configJson)
    {
        if (!Path.IsPathFullyQualified(stateFile) || version <= 0 || string.IsNullOrWhiteSpace(configJson)) throw new InvalidDataException("BF-TEST-SCOPE");
        var signingSeed = Ed25519.GenerateSeed();
        var signingPublic = Ed25519SubjectPublicKeyInfo(Ed25519.DerivePublicKey(signingSeed));
        var encryptionPrivate = new byte[] { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20 }.Concat(RandomNumberGenerator.GetBytes(32)).ToArray();
        var encryptionPublic = X25519Managed.PublicFromPkcs8(encryptionPrivate);
        try
        {
            SaveState(stateFile, new ControlState
            {
                ControlUrl = "https://control.test.invalid",
                PublicId = "TEST-ONLY-public-id",
                DeviceId = Guid.NewGuid().ToString("D"),
                SigningSeed = B64(signingSeed),
                SigningPublicKey = B64(signingPublic),
                EncryptionPrivatePkcs8 = B64(encryptionPrivate),
                EncryptionPublicKey = B64(encryptionPublic),
                ConfigJson = configJson,
                ConfigVersion = version,
                ConfigDigest = Sha256(configJson),
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingSeed);
            CryptographicOperations.ZeroMemory(signingPublic);
            CryptographicOperations.ZeroMemory(encryptionPrivate);
            CryptographicOperations.ZeroMemory(encryptionPublic);
        }
    }

    /// <summary>TEST-ONLY mutation used to prove the content half of the LKG identity gate.</summary>
    internal static void ReplaceLifecycleContentForTest(string stateFile, string configJson)
    {
        if (!Path.IsPathFullyQualified(stateFile) || string.IsNullOrWhiteSpace(configJson)) throw new InvalidDataException("BF-TEST-SCOPE");
        var state = LoadState(stateFile);
        state.ConfigJson = configJson;
        SaveState(stateFile, state);
    }

    public bool IsEnrolled => _lifecycleOnly
        ? !string.IsNullOrWhiteSpace(_state.DeviceId) && !string.IsNullOrWhiteSpace(_state.ControlUrl)
        : _trustedOrigin is not null &&
          !string.IsNullOrWhiteSpace(_state.DeviceId) &&
          !string.IsNullOrWhiteSpace(_state.PublicId) &&
          _state.ConfigVersion > 0 &&
          !string.IsNullOrWhiteSpace(_state.ConfigJson) &&
          IsSha256Digest(_state.ConfigDigest) &&
          string.Equals(_state.ControlUrl, _trustedOrigin.Value, StringComparison.Ordinal);
    public string? ControlUrl => _lifecycleOnly ? _state.ControlUrl : (IsEnrolled ? _trustedOrigin!.Value : null);
    public string ConfigurationStatus => _configurationStatus;
    public bool IsLocalEvaluation => !_lifecycleOnly && TrustedControlOrigin.IsLocalEvaluation;
    public string CompiledOriginDisplay => _lifecycleOnly ? (_state.ControlUrl ?? "TEST-ONLY") : (TrustedControlOrigin.CompiledValue.Length == 0 ? "未配置" : TrustedControlOrigin.CompiledValue);
    public string? SessionToken => _state.SessionToken;
    // The complete recovery code is persisted only inside the existing
    // CurrentUser DPAPI-protected control state.  It is intentionally exposed
    // to the local settings view so a user can move to another device later.
    public string? RecoveryCode => IsEnrolled ? _state.RecoveryCode : null;
    public long LastConfigVersion => _state.ConfigVersion;
    public string? NodeConfigurationFingerprint => NodeConfigurationNotifications.Fingerprint(_state.ConfigJson);
    public bool HasPendingRecovery => _state.RecoveryPending;
    public bool HasPendingEnrollment =>
        !IsEnrolled &&
        !string.IsNullOrWhiteSpace(_state.EnrollmentInviteFingerprint) &&
        !string.IsNullOrWhiteSpace(_state.EnrollmentIdempotency);

    /// <summary>
    /// Ensures that an enrolled device has a current authenticated session before
    /// a caller signs a request outside the normal control-plane transport.
    /// </summary>
    public Task EnsureSessionForUpdateAsync(CancellationToken cancellationToken) =>
        EnsureSessionAsync(null, cancellationToken);

    /// <summary>
    /// Replaces precisely the session rejected by an out-of-band authenticated
    /// request. The observed-token guard preserves a session another caller
    /// refreshed while this request was in flight.
    /// </summary>
    public async Task<string> RefreshSessionForUpdateAsync(string observedToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(observedToken)) throw new InvalidOperationException("BF-AUTH-SESSION");
        await EnsureSessionAsync(observedToken, cancellationToken).ConfigureAwait(false);
        return _state.SessionToken ?? throw new InvalidOperationException("BF-AUTH-SESSION");
    }

    private static string ResolveClientStateRoot(string leaf)
    {
        if (BifrostBuildConstants.LocalEvaluationFixture) return LocalEvaluationStateRoot.Resolve(leaf);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost", leaf);
    }

    /// <summary>
    /// Test-only production consumer used by the isolated lifecycle harness.
    /// It feeds the same signed X25519/AES-GCM verifier and DPAPI LKG writer
    /// used by RefreshAsync, with only the state path and recipient key
    /// injected into a temporary root.  No release caller can select this
    /// path because the assembly exposes it only to the fixture friend.
    /// </summary>
    internal LifecyclePackageResult ConsumePackageForLifecycleTest(JsonObject envelope, long expectedVersion, byte[] encryptionPrivatePkcs8, string stateFile, byte[]? trustedConfigPublicKey = null)
    {
        if (envelope is null || encryptionPrivatePkcs8.Length == 0 || !Path.IsPathFullyQualified(stateFile)) throw new InvalidDataException("BF-TEST-SCOPE");
        var parent = Path.GetDirectoryName(stateFile) ?? throw new InvalidDataException("BF-TEST-SCOPE");
        Directory.CreateDirectory(parent);
        _stateFile = stateFile;
        if (File.Exists(stateFile)) _state = LoadState(stateFile);
        else
        {
            var signingSeed = Ed25519.GenerateSeed();
            var signingPublic = Ed25519SubjectPublicKeyInfo(Ed25519.DerivePublicKey(signingSeed));
            try
            {
                _state = new ControlState
                {
                    ControlUrl = "https://control.test.invalid",
                    DeviceId = Guid.NewGuid().ToString("D"),
                    SigningSeed = B64(signingSeed),
                    SigningPublicKey = B64(signingPublic),
                    EncryptionPrivatePkcs8 = B64(encryptionPrivatePkcs8),
                    EncryptionPublicKey = B64(X25519Managed.PublicFromPkcs8(encryptionPrivatePkcs8)),
                    ConfigVersion = 0
                };
            }
            finally { CryptographicOperations.ZeroMemory(signingSeed); CryptographicOperations.ZeroMemory(signingPublic); }
        }
        _lifecycleTrustedConfigKey = trustedConfigPublicKey?.ToArray();
        try
        {
            var config = DecryptAndVerifyPackage(envelope, expectedVersion);
            var packageDigest = PackageDigest(envelope);
            if (_state.ConfigVersion > expectedVersion)
                throw new InvalidDataException("BF-CONFIG-ROLLBACK");
            if (_state.ConfigVersion == expectedVersion && !string.IsNullOrEmpty(_state.ConfigDigest) && !string.Equals(_state.ConfigDigest, packageDigest, StringComparison.Ordinal))
                throw new InvalidDataException("BF-CONFIG-EQUIVOCATION");
            if (_state.ConfigVersion == expectedVersion && string.Equals(_state.ConfigDigest, packageDigest, StringComparison.Ordinal))
                return new LifecyclePackageResult(_state.ConfigVersion, _state.ConfigDigest ?? string.Empty, _state.ConfigJson ?? string.Empty);
            SaveConfig(config, expectedVersion, packageDigest, envelope: envelope);
            return new LifecyclePackageResult(_state.ConfigVersion, _state.ConfigDigest ?? string.Empty, _state.ConfigJson ?? string.Empty);
        }
        finally { if (_lifecycleTrustedConfigKey is not null) CryptographicOperations.ZeroMemory(_lifecycleTrustedConfigKey); _lifecycleTrustedConfigKey = null; }
    }

    /// <summary>Fresh-process read gate used by the lifecycle harness.</summary>
    internal LifecycleStateReadback ReadPersistedLifecycleStateForTest(string stateFile)
    {
        if (string.IsNullOrWhiteSpace(stateFile) || !Path.IsPathFullyQualified(stateFile)) throw new InvalidDataException("BF-TEST-SCOPE");
        var state = LoadState(stateFile);
        if (state.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(state.ConfigJson) || string.IsNullOrWhiteSpace(state.ConfigDigest))
            throw new InvalidDataException("BF-CONFIG-LKG");
        return new LifecycleStateReadback(state.ConfigVersion, state.ConfigDigest, state.ConfigJson, "atomic_dpapi");
    }

    /// <summary>
    /// TEST-ONLY matrix over the same UI compiler/selection path. Every case
    /// supplies a candidate label from the signed source, so this exercise is
    /// deterministic and cannot open a real socket or silently probe another
    /// source. The production compiler still owns mode/core/policy checks.
    /// </summary>
    internal async Task<LifecycleSelectionMatrixResult> CompileSelectionMatrixForLifecycleTest(string stateFile)
    {
        if (string.IsNullOrWhiteSpace(stateFile) || !Path.IsPathFullyQualified(stateFile)) throw new InvalidDataException("BF-TEST-SCOPE");
        _stateFile = stateFile;
        _state = LoadState(stateFile);
        var config = JsonNode.Parse(_state.ConfigJson ?? throw new InvalidDataException("BF-CONFIG-NOT-AVAILABLE")) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
        var cases = new[]
        {
            (Source: "A", Country: "default", Mode: ProtocolCodes.ModeSmart, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: Array.Empty<string>(), Exclude: Array.Empty<string>()),
            (Source: "B", Country: "default", Mode: ProtocolCodes.ModeGlobal, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: Array.Empty<string>(), Exclude: Array.Empty<string>()),
            (Source: "A", Country: "XX", Mode: ProtocolCodes.ModePerApp, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: new[] { "test.only.allow" }, Exclude: Array.Empty<string>()),
            (Source: "B", Country: "default", Mode: ProtocolCodes.ModePerApp, Core: ProtocolCodes.CoreMihomo, Policy: "exclude", Include: Array.Empty<string>(), Exclude: new[] { "test.only.exclude" })
        };
        var digests = new List<string>(cases.Length);
        foreach (var item in cases)
        {
            var source = SelectSource(config, item.Source);
            var candidate = (source["candidates"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE");
            var label = candidate["label"]?.GetValue<string>() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE-LABEL");
            var compiled = await PrepareSignedPackageAsync(item.Source, item.Country, item.Mode, item.Core, label, item.Include, item.Exclude, null, item.Policy, CancellationToken.None, null, "direct-vmess").ConfigureAwait(false);
            if (!string.Equals(compiled.Source, item.Source, StringComparison.OrdinalIgnoreCase) || !string.Equals(compiled.Mode, item.Mode, StringComparison.Ordinal) || !string.Equals(compiled.Core, item.Core, StringComparison.Ordinal)) throw new InvalidDataException("BF-SELECTION-REBIND");
            var text = compiled.SignedConfigJson ?? throw new InvalidDataException("BF-CONFIG-SIGNED-PACKAGE-REQUIRED");
            if (text.Contains("socks5://", StringComparison.OrdinalIgnoreCase) || text.Contains("socks_password", StringComparison.OrdinalIgnoreCase) || text.Contains("TEST-ONLY-user", StringComparison.Ordinal) || text.Contains("TEST-ONLY-pass", StringComparison.Ordinal)) throw new InvalidDataException("BF-SECRET-CLIENT-PACKAGE");
            var evidence = StrictUtf8.GetBytes($"{compiled.ConfigContentDigest}|{compiled.Source}|{compiled.Country}|{compiled.Mode}|{compiled.Core}|{compiled.SelectedCandidateLabel}|{compiled.FrontSource}|{compiled.FrontCandidateLabel}");
            try { digests.Add(Convert.ToHexString(SHA256.HashData(evidence)).ToLowerInvariant()); }
            finally { CryptographicOperations.ZeroMemory(evidence); }
        }
        var sourceA = SelectSource(config, "A");
        var sourceACandidate = (sourceA["candidates"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()?["label"]?.GetValue<string>() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE-LABEL");
        var crossSourceRejected = false;
        try
        {
            await PrepareSignedPackageAsync("B", "default", ProtocolCodes.ModeGlobal, ProtocolCodes.CoreMihomo, sourceACandidate, Array.Empty<string>(), Array.Empty<string>(), null, "allow", CancellationToken.None, null, "direct-vmess").ConfigureAwait(false);
        }
        catch (InvalidDataException error) when (error.Message is "BF-CONFIG-CANDIDATE-NOT-IN-SOURCE" or "BF-CANDIDATE-NOT-READY") { crossSourceRejected = true; }
        if (!crossSourceRejected) throw new InvalidDataException("BF-SELECTION-CROSS-SOURCE");
        return new LifecycleSelectionMatrixResult(cases.Length, string.Join(',', digests), crossSourceRejected);
    }

    /// <summary>
    /// Executes the production connection ordering with owned test adapters.
    /// Compilation, route selection and the fail-closed runtime coordinator are
    /// the same code used by the WPF/service path; adapters only replace OS
    /// core/TUN effects for the offline lifecycle fixture.
    /// </summary>
    internal async Task<ControlledRuntimeMatrixResult> RunControlledRuntimeMatrixForLifecycleTest(string stateFile)
    {
        if (string.IsNullOrWhiteSpace(stateFile) || !Path.IsPathFullyQualified(stateFile)) throw new InvalidDataException("BF-TEST-SCOPE");
        _stateFile = stateFile;
        _state = LoadState(stateFile);
        var config = JsonNode.Parse(_state.ConfigJson ?? throw new InvalidDataException("BF-CONFIG-NOT-AVAILABLE")) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
        var cases = new[]
        {
            (Source: "A", Country: "default", Mode: ProtocolCodes.ModeSmart, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: Array.Empty<string>(), Exclude: Array.Empty<string>(), Connection: "direct-vmess"),
            (Source: "B", Country: "default", Mode: ProtocolCodes.ModeGlobal, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: Array.Empty<string>(), Exclude: Array.Empty<string>(), Connection: "direct-vmess"),
            (Source: "A", Country: "XX", Mode: ProtocolCodes.ModePerApp, Core: ProtocolCodes.CoreMihomo, Policy: "allow", Include: new[] { "test.only.allow" }, Exclude: Array.Empty<string>(), Connection: "smartgate"),
            (Source: "B", Country: "default", Mode: ProtocolCodes.ModePerApp, Core: ProtocolCodes.CoreMihomo, Policy: "exclude", Include: Array.Empty<string>(), Exclude: new[] { "test.only.exclude" }, Connection: "smartgate")
        };
        var routes = new List<string>(cases.Length); var failClosed = 0;
        foreach (var item in cases)
        {
            var source = SelectSource(config, item.Source);
            var candidate = (source["candidates"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE");
            var label = candidate["label"]?.GetValue<string>() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE-LABEL");
            var package = await PrepareSignedPackageAsync(item.Source, item.Country, item.Mode, item.Core, label, item.Include, item.Exclude, null, item.Policy, CancellationToken.None, null, item.Connection).ConfigureAwait(false);
            var core = new LifecycleCoreAdapter(); var boundary = new LifecycleNetworkBoundary();
            var coordinator = new ControlledRuntimeCoordinator(core, boundary);
            var connected = coordinator.Connect(package);
            if (!connected.Connected || connected.FailClosed || !boundary.IsBound || core.StartCount != 1) throw new InvalidDataException("BF-RUNTIME-CONNECT");
            routes.Add($"{connected.Route}:{connected.Core}");
            coordinator.Disconnect();
            if (boundary.IsBound || core.StopCount != 1) throw new InvalidDataException("BF-RUNTIME-DISCONNECT");
        }
        try
        {
            var sourceA = SelectSource(config, "A");
            var labelA = (sourceA["candidates"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()?["label"]?.GetValue<string>() ?? throw new InvalidDataException("BF-SOURCE-CANDIDATE-LABEL");
            var package = await PrepareSignedPackageAsync("A", "default", ProtocolCodes.ModeSmart, ProtocolCodes.CoreMihomo, labelA, Array.Empty<string>(), Array.Empty<string>(), null, "allow", CancellationToken.None, null, "direct-vmess").ConfigureAwait(false);
            var core = new LifecycleCoreAdapter { FailStart = true }; var boundary = new LifecycleNetworkBoundary();
            var coordinator = new ControlledRuntimeCoordinator(core, boundary);
            AssertRuntimeFailure(coordinator, package);
            if (!boundary.IsBound || core.StopCount != 1) throw new InvalidDataException("BF-RUNTIME-DIRECT-FALLBACK");
            failClosed++;
        }
        catch (InvalidDataException) { throw; }
        return new ControlledRuntimeMatrixResult(cases.Length, failClosed, string.Join(',', routes));
    }

    private static void AssertRuntimeFailure(ControlledRuntimeCoordinator coordinator, SignedClientPackageRequest package)
    {
        try { coordinator.Connect(package); throw new InvalidDataException("BF-RUNTIME-FAILURE-ACCEPTED"); }
        catch (InvalidOperationException error) when (error.Message == "BF-PROXY-REQUIRED") { }
    }

    public UiConfigOptions GetUiConfigOptions()
    {
        if (string.IsNullOrWhiteSpace(_state.ConfigJson)) return UiConfigOptions.Empty;
        var config = JsonNode.Parse(_state.ConfigJson) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
        static IReadOnlyList<UiOption> Read(JsonNode? node, string codeKey, string nameKey, string? fallbackNameKey = null)
        {
            return node is JsonArray array
                ? array.OfType<JsonObject>()
                    .Select(item => (Code: item[codeKey]?.GetValue<string>(), Name: item[nameKey]?.GetValue<string>(), Fallback: fallbackNameKey is null ? null : item[fallbackNameKey]?.GetValue<string>()))
                    .Where(item => !string.IsNullOrWhiteSpace(item.Code))
                    .Select(item => new UiOption(item.Code!, string.IsNullOrWhiteSpace(item.Name) ? (string.IsNullOrWhiteSpace(item.Fallback) ? item.Code! : item.Fallback!) : item.Name!))
                    .ToArray()
                : Array.Empty<UiOption>();
        }
        // The compiler and source selector accept only signed sources whose
        // authority is explicitly configured.  Keep the option surface in
        // lock-step so an unconfigured A/B entry cannot be selected in the
        // UI only to fail later at compile/connect time.
        static IReadOnlyList<UiOption> ReadConfiguredSources(JsonNode? node)
        {
            return node is JsonArray array
                ? array.OfType<JsonObject>()
                    .Where(item => item["configured"]?.GetValue<bool>() == true)
                    .Select(item => new UiOption(
                        item["code"]?.GetValue<string>() ?? string.Empty,
                        item["display_name"]?.GetValue<string>() ?? item["name"]?.GetValue<string>() ?? item["code"]?.GetValue<string>() ?? string.Empty))
                    .Where(item => !string.IsNullOrWhiteSpace(item.Code))
                    .ToArray()
                : Array.Empty<UiOption>();
        }
        var sources = ReadConfiguredSources(config["sources"]);
        var candidatesBySource = new Dictionary<string, IReadOnlyList<UiOption>>(StringComparer.OrdinalIgnoreCase);
        if (config["sources"] is JsonArray sourceArray)
        {
            foreach (var source in sourceArray.OfType<JsonObject>())
            {
                if (source["configured"]?.GetValue<bool>() != true || source["code"]?.GetValue<string>() is not { Length: > 0 } sourceCode) continue;
                var candidates = source["candidates"] is JsonArray candidateArray
                    ? candidateArray.OfType<JsonObject>()
                        .Select(item => (Code: item["label"]?.GetValue<string>(), Name: item["display_name"]?.GetValue<string>() ?? item["name"]?.GetValue<string>()))
                        .Where(item => !string.IsNullOrWhiteSpace(item.Code) && SafeUiLabel(item.Code!) && (string.IsNullOrWhiteSpace(item.Name) || SafeUiLabel(item.Name!)))
                        .Select(item => new UiOption(item.Code!, string.IsNullOrWhiteSpace(item.Name) ? item.Code! : item.Name!))
                        .DistinctBy(item => item.Code, StringComparer.Ordinal)
                        .ToArray()
                    : Array.Empty<UiOption>();
                candidatesBySource[sourceCode] = candidates;
            }
        }
        return new UiConfigOptions(sources, sources, Read(config["countries"], "code", "name_zh", "name"), candidatesBySource);
    }

    private static bool SafeUiLabel(string value) => value.Length <= 128 && !value.Any(char.IsControl) &&
        !value.Contains('/', StringComparison.Ordinal) && !value.Contains(':', StringComparison.Ordinal) && !value.Contains('@', StringComparison.Ordinal);

    public async Task<string?> ProbeSelectedCandidateAsync(string sourceCode, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(_state.ConfigJson)) return null;
        var config = JsonNode.Parse(_state.ConfigJson) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
        var source = SelectSource(config, sourceCode);
        var selected = await SelectCandidateAsync(source, null, cancellationToken).ConfigureAwait(false);
        return selected["label"]?.GetValue<string>();
    }

    /// <summary>
    /// Measures every signed candidate in one source for the manual route
    /// detail view.  This is intentionally separate from automatic selection:
    /// auto mode retains its rotating three-candidate cohort and bounded round,
    /// while an explicit detail request may inspect the complete signed source.
    /// At most three handshakes run concurrently and every candidate owns an
    /// independent bounded byte budget.
    /// </summary>
    public async Task<CandidateProbeSnapshot> ProbeCandidateStatusesAsync(string sourceCode, CancellationToken cancellationToken = default)
    {
        await _candidateSelectionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(_state.ConfigJson))
                return new CandidateProbeSnapshot(sourceCode, null, Array.Empty<CandidateProbeStatus>());
            var config = JsonNode.Parse(_state.ConfigJson) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
            var source = SelectSource(config, sourceCode);
            return await ProbeCandidateStatusesCoreAsync(source, cancellationToken).ConfigureAwait(false);
        }
        finally { _candidateSelectionGate.Release(); }
    }

    public async Task<ControlResult> EnrollAsync(string inviteCode, CancellationToken cancellationToken = default)
    {
        await _enrollmentGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var fixtureStage = "origin";
        try
        {
            var url = RequireTrustedOrigin();
            fixtureStage = "ensure-keys";
            EnsureKeys();
            var normalizedInvite = inviteCode.Trim();
            var inviteFingerprint = EnrollmentInviteFingerprint(normalizedInvite);
            var hasPendingEnrollment = !string.IsNullOrWhiteSpace(_state.EnrollmentIdempotency);
            if (hasPendingEnrollment &&
                !string.Equals(_state.EnrollmentInviteFingerprint, inviteFingerprint, StringComparison.Ordinal))
            {
                // A different code must never overwrite an unresolved local
                // identity merely because the UI changed. First prove whether
                // the retained identity still exists at Control. A valid
                // identity wins and the newly typed code is never redeemed.
                try
                {
                    fixtureStage = "resume-old-before-new-code";
                    var resumed = await ResumeEnrollmentAsync(cancellationToken).ConfigureAwait(false);
                    ClearEnrollmentAttempt();
                    return new ControlResult(true, "enrollment resumed", _state.PublicId, null, resumed.ConfigVersion);
                }
                catch (InvalidOperationException error) when (error.Message is "BF-DEVICE-404" or "BF-AUTH-003")
                {
                    // A missing or revoked old identity cannot resume. Try the
                    // explicitly supplied credential with a separate candidate;
                    // Control still enforces that credential's account status
                    // and entitlement. Preserve the old state until success.
                }
                fixtureStage = "fresh-candidate";
                return await EnrollWithFreshCandidateAsync(url, normalizedInvite, inviteFingerprint, cancellationToken).ConfigureAwait(false);
            }
            return await EnrollCurrentIdentityAsync(url, normalizedInvite, inviteFingerprint, cancellationToken, stage => fixtureStage = stage).ConfigureAwait(false);
        }
        catch (Exception error) when (BifrostBuildConstants.LocalEvaluationFixture)
        {
            throw new InvalidOperationException($"TEST-ONLY-STAGE-{fixtureStage}", error);
        }
        finally { _enrollmentGate.Release(); }
    }

    private async Task<ControlResult> EnrollCurrentIdentityAsync(
        string url,
        string normalizedInvite,
        string inviteFingerprint,
        CancellationToken cancellationToken,
        Action<string>? stage = null)
    {
        // Redeeming a code creates server state. Keep one identity and one
        // idempotency key until the local activation transaction finishes, so
        // a lost response can be resumed without consuming the code twice.
        var hasPendingEnrollment = !string.IsNullOrWhiteSpace(_state.EnrollmentIdempotency);
        if (hasPendingEnrollment &&
            !string.Equals(_state.EnrollmentInviteFingerprint, inviteFingerprint, StringComparison.Ordinal))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");

        var enrollmentIdempotency = _state.EnrollmentIdempotency ?? CreateIdempotencyKey();
        if (!string.Equals(_state.EnrollmentIdempotency, enrollmentIdempotency, StringComparison.Ordinal))
        {
            var pending = CloneState(_state);
            pending.EnrollmentInviteFingerprint = inviteFingerprint;
            pending.EnrollmentIdempotency = enrollmentIdempotency;
            SaveState(_stateFile, pending, allowLifecycleOrigin: _lifecycleOnly);
            _state = pending;
        }

        try
        {
            // Try the retained device identity before redeeming. A successful
            // device proof restores a lost enrollment response. Absence allows
            // first enrollment with this identity; confirmed old revocation
            // requires a separate candidate and independently valid credential.
            try
            {
                stage?.Invoke("resume");
                var resumed = await ResumeEnrollmentAsync(cancellationToken).ConfigureAwait(false);
                ClearEnrollmentAttempt();
                return new ControlResult(true, "enrollment resumed", _state.PublicId, null, resumed.ConfigVersion);
            }
            catch (InvalidOperationException error) when (error.Message == "BF-DEVICE-404") { }
            catch (InvalidOperationException error) when (error.Message == "BF-AUTH-003" &&
                !_stateFile.EndsWith(".enrollment-candidate", StringComparison.Ordinal))
            {
                return await EnrollWithFreshCandidateAsync(url, normalizedInvite, inviteFingerprint, cancellationToken).ConfigureAwait(false);
            }

            var body = new JsonObject
            {
                ["invite_code"] = normalizedInvite, ["platform"] = "windows", ["device_id"] = _state.DeviceId,
                ["signing_public_key"] = _state.SigningPublicKey, ["encryption_public_key"] = _state.EncryptionPublicKey, ["key_level"] = "software"
            };
            stage?.Invoke("redeem");
            JsonObject response;
            try
            {
                response = await SendJsonAsync(HttpMethod.Post, new Uri(new Uri(url), "/v1/enrollment/redeem"), body, cancellationToken, url, enrollmentIdempotency).ConfigureAwait(false);
            }
            catch (InvalidOperationException error) when (error.Message == "BF-ENROLL-003")
            {
                // The server may have committed the same identity before the
                // response was lost. Resume it instead of minting another
                // identity or asking the user to re-enter a consumed code.
                var resumed = await ResumeEnrollmentAsync(cancellationToken).ConfigureAwait(false);
                ClearEnrollmentAttempt();
                return new ControlResult(true, "enrollment resumed", _state.PublicId, null, resumed.ConfigVersion);
            }
            var version = response["config_version"]?.GetValue<long>() ?? 0;
            var trustState = VerifyConfigKeyState(response, version);
            stage?.Invoke("recovery");
            var recoveryEnvelope = response["recovery_delivery"] as JsonObject;
            var recoveryCode = BifrostBuildConstants.LocalEvaluationFixture || recoveryEnvelope is null
                ? null
                : DecryptRecoveryDelivery(recoveryEnvelope, trustState);
            stage?.Invoke("device-response");
            ApplyDeviceResponse(url, response, trustState, recoveryCode);
            stage?.Invoke("refresh");
            await RefreshAsync(cancellationToken).ConfigureAwait(false);
            ClearEnrollmentAttempt();
            return new ControlResult(true, "enrolled", _state.PublicId, recoveryCode, _state.ConfigVersion);
        }
        catch (Exception error) when (IsRejectedEnrollment(error))
        {
            ClearEnrollmentAttempt();
            throw;
        }
    }

    private async Task<ControlResult> EnrollWithFreshCandidateAsync(
        string url,
        string normalizedInvite,
        string inviteFingerprint,
        CancellationToken cancellationToken)
    {
        var primaryFile = _stateFile;
        var primaryState = _state;
        var candidateFile = EnrollmentCandidateStateFile(primaryFile);
        ControlState candidate;

        if (File.Exists(candidateFile))
        {
            candidate = LoadState(candidateFile, allowLifecycleOrigin: _lifecycleOnly);
            if (string.IsNullOrWhiteSpace(candidate.DeviceId) || string.IsNullOrWhiteSpace(candidate.SigningPublicKey) ||
                string.IsNullOrWhiteSpace(candidate.EncryptionPublicKey) || !string.Equals(candidate.ControlUrl, url, StringComparison.Ordinal))
                throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");

            // A prior candidate can itself have suffered a lost response. If
            // the user types yet another code, validate that candidate before
            // replacing it. An active candidate wins and the later code is not
            // consumed. Only explicit absence permits a new candidate.
            if (!string.Equals(candidate.EnrollmentInviteFingerprint, inviteFingerprint, StringComparison.Ordinal))
            {
                _stateFile = candidateFile;
                _state = candidate;
                try
                {
                    var resumed = await ResumeEnrollmentAsync(cancellationToken).ConfigureAwait(false);
                    ClearEnrollmentAttempt();
                    var completed = CloneState(_state);
                    _stateFile = primaryFile;
                    _state = primaryState;
                    SaveState(primaryFile, completed, allowLifecycleOrigin: _lifecycleOnly);
                    _state = completed;
                    DeleteEnrollmentCandidateState(candidateFile);
                    return new ControlResult(true, "enrollment resumed", _state.PublicId, null, resumed.ConfigVersion);
                }
                catch (InvalidOperationException error) when (error.Message is "BF-DEVICE-404" or "BF-AUTH-003")
                {
                    _stateFile = primaryFile;
                    _state = primaryState;
                    DeleteEnrollmentCandidateState(candidateFile);
                    candidate = CreateEnrollmentCandidate(url, inviteFingerprint, candidateFile);
                }
                finally
                {
                    if (!string.Equals(_stateFile, primaryFile, StringComparison.Ordinal))
                    {
                        _stateFile = primaryFile;
                        _state = primaryState;
                    }
                }
            }
        }
        else candidate = CreateEnrollmentCandidate(url, inviteFingerprint, candidateFile);

        _stateFile = candidateFile;
        _state = candidate;
        try
        {
            var result = await EnrollCurrentIdentityAsync(url, normalizedInvite, inviteFingerprint, cancellationToken).ConfigureAwait(false);
            var completed = CloneState(_state);
            _stateFile = primaryFile;
            _state = primaryState;
            SaveState(primaryFile, completed, allowLifecycleOrigin: _lifecycleOnly);
            _state = completed;
            DeleteEnrollmentCandidateState(candidateFile);
            return result with { PublicId = _state.PublicId, ConfigVersion = _state.ConfigVersion };
        }
        catch (Exception error) when (IsRejectedEnrollment(error))
        {
            // Rejected codes do not create a device row, so the fresh
            // candidate can be discarded. The original pending identity stays
            // byte-for-byte protected in the primary state file.
            _stateFile = primaryFile;
            _state = primaryState;
            DeleteEnrollmentCandidateState(candidateFile);
            throw;
        }
        finally
        {
            if (!string.Equals(_stateFile, primaryFile, StringComparison.Ordinal))
            {
                _stateFile = primaryFile;
                _state = primaryState;
            }
        }
    }

    private ControlState CreateEnrollmentCandidate(string url, string inviteFingerprint, string candidateFile)
    {
        var candidate = EnsureKeys(new ControlState(), persist: false);
        candidate.ControlUrl = url;
        candidate.EnrollmentInviteFingerprint = inviteFingerprint;
        candidate.EnrollmentIdempotency = CreateIdempotencyKey();
        SaveState(candidateFile, candidate, allowLifecycleOrigin: _lifecycleOnly);
        return candidate;
    }

    private static string EnrollmentCandidateStateFile(string primaryFile)
    {
        if (string.IsNullOrWhiteSpace(primaryFile) || !Path.IsPathFullyQualified(primaryFile))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        return primaryFile + ".enrollment-candidate";
    }

    private static void DeleteEnrollmentCandidateState(string candidateFile)
    {
        RejectReparsePoint(candidateFile, true);
        if (File.Exists(candidateFile)) File.Delete(candidateFile);
    }

    public async Task<ControlResult> RecoverAsync(string publicId, string recoveryCode, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(publicId) || string.IsNullOrWhiteSpace(recoveryCode)) throw new ArgumentException("BF-RECOVERY-INPUT");
        var url = RequireTrustedOrigin();
        // Recovery replaces a device identity that may still be retained by
        // the control plane as revoked. Reusing its id would make every valid
        // recovery code fail with BF-RECOVERY-006 ("device id already
        // enrolled"). Generate a complete fresh key set, but do not persist
        // it until the recovery request has been accepted so a bad code or a
        // temporary service failure cannot discard the existing local state.
        var candidate = EnsureKeys(new ControlState(), persist: false);
        candidate.ControlUrl = url;
        candidate.PublicId = publicId.Trim();
        var body = new JsonObject
        {
            ["public_id"] = publicId.Trim(), ["recovery_code"] = recoveryCode.Trim(), ["platform"] = "windows",
            ["device_id"] = candidate.DeviceId, ["signing_public_key"] = candidate.SigningPublicKey,
            ["encryption_public_key"] = candidate.EncryptionPublicKey, ["key_level"] = "software"
        };
        var request = await SendJsonAsync(HttpMethod.Post, new Uri(new Uri(url), "/v1/recovery/request"), body, cancellationToken, url, CreateIdempotencyKey());
        candidate.RecoveryPending = true;
        // The delivery is consumed server-side. Persist this key before the
        // first read so an interrupted response can be replayed after a
        // restart instead of turning into an unrecoverable 410 response.
        candidate.RecoveryDeliveryIdempotency = CreateIdempotencyKey();
        SaveState(_stateFile, candidate);
        _state = candidate;
        return new ControlResult(true, "recovery pending administrator approval", request["public_id"]?.GetValue<string>() ?? candidate.PublicId, null, candidate.ConfigVersion);
    }

    /// <summary>
    /// Retrieves the administrator-approved recovery envelope.  The server
    /// consumes it in the same transaction as the sender nonce; only the
    /// device-encrypted envelope crosses the wire and the decrypted code is
    /// returned in memory for the existing one-time sensitive UI lifecycle.
    /// </summary>
    public async Task<ControlResult> RetrieveRecoveryDeliveryAsync(CancellationToken cancellationToken = default)
    {
        // A newly accepted recovery has identity keys but deliberately no
        // signed configuration yet. IsEnrolled therefore remains false until
        // we consume the administrator-approved delivery and refresh it.
        // Do not make an approved recovery impossible by applying the normal
        // post-enrollment gate here.
        if (string.IsNullOrWhiteSpace(_state.ControlUrl) ||
            string.IsNullOrWhiteSpace(_state.PublicId) ||
            string.IsNullOrWhiteSpace(_state.DeviceId) ||
            string.IsNullOrWhiteSpace(_state.SigningPublicKey) ||
            string.IsNullOrWhiteSpace(_state.EncryptionPublicKey))
            throw new InvalidOperationException("BF-RECOVERY-DELIVERY");
        var endpoint = new Uri(new Uri(_state.ControlUrl!), "/v1/recovery/delivery");
        if (!_state.RecoveryPending || string.IsNullOrWhiteSpace(_state.RecoveryDeliveryIdempotency))
            throw new InvalidOperationException("BF-RECOVERY-NOT-PENDING");
        var deliveryIdempotency = _state.RecoveryDeliveryIdempotency;
        JsonObject response;
        try
        {
            response = await SendAuthorizedAsync(HttpMethod.Get, endpoint, null, cancellationToken, deliveryIdempotency).ConfigureAwait(false);
        }
        catch (InvalidOperationException error) when (error.Message == "BF-AUTH-REQUIRED")
        {
            await EnsureSessionAsync(null, cancellationToken).ConfigureAwait(false);
            response = await SendAuthorizedAsync(HttpMethod.Get, endpoint, null, cancellationToken, deliveryIdempotency).ConfigureAwait(false);
        }
        var version = response["config_version"]?.GetValue<long>() ?? 0;
        var trustState = VerifyConfigKeyState(response, version);
        var recoveryCode = DecryptRecoveryDelivery(response["recovery_delivery"] as JsonObject, trustState);
        SaveConfigKeyState(trustState);
        var refreshed = await RefreshOnlineAsync(cancellationToken).ConfigureAwait(false);
        var completed = CloneState(_state);
        completed.RecoveryCode = recoveryCode;
        completed.RecoveryPending = false;
        completed.RecoveryDeliveryIdempotency = null;
        SaveState(_stateFile, completed);
        _state = completed;
        return new ControlResult(true, "recovery complete", _state.PublicId, recoveryCode, refreshed.ConfigVersion);
    }

    public async Task<ControlResult> RotateRecoveryCodeAsync(CancellationToken cancellationToken = default)
    {
        if (!IsEnrolled || string.IsNullOrWhiteSpace(_state.ControlUrl))
            throw new InvalidOperationException("BF-AUTH-REQUIRED");
        var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            new Uri(new Uri(_state.ControlUrl), "/v1/recovery/rotate"),
            new JsonObject(),
            cancellationToken,
            CreateIdempotencyKey()).ConfigureAwait(false);
        var version = response["config_version"]?.GetValue<long>() ?? 0;
        var trustState = VerifyConfigKeyState(response, version);
        var recoveryCode = DecryptRecoveryDelivery(response["recovery_delivery"] as JsonObject, trustState);
        SaveConfigKeyState(trustState);
        var completed = CloneState(_state);
        completed.RecoveryCode = recoveryCode;
        SaveState(_stateFile, completed);
        _state = completed;
        return new ControlResult(true, "recovery code rotated", _state.PublicId, recoveryCode, _state.ConfigVersion);
    }

    public async Task<ControlResult> CreatePairingAsync(string targetPlatform, CancellationToken cancellationToken = default)
    {
        if (targetPlatform is not ("android" or "windows")) throw new ArgumentException("BF-PAIR-PLATFORM");
        var response = await SendAuthorizedAsync(HttpMethod.Post, new Uri(new Uri(_state.ControlUrl!), "/v1/pairing/create"), new JsonObject { ["target_platform"] = targetPlatform }, cancellationToken, CreateIdempotencyKey());
        var code = response["pairing_code"]?.GetValue<string>() ?? throw new InvalidDataException("BF-PAIR-CREATE-RESPONSE");
        return new ControlResult(true, "pairing code created; expires in ten minutes", _state.PublicId, null, _state.ConfigVersion, code);
    }

    public async Task<ControlResult> RedeemPairingAsync(string pairingCode, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(pairingCode)) throw new ArgumentException("BF-PAIR-CODE");
        var url = RequireTrustedOrigin();
        EnsureKeys();
        var body = new JsonObject
        {
            ["pairing_code"] = pairingCode.Trim(), ["platform"] = "windows", ["device_id"] = _state.DeviceId,
            ["signing_public_key"] = _state.SigningPublicKey, ["encryption_public_key"] = _state.EncryptionPublicKey,
            ["key_level"] = "software"
        };
        var response = await SendJsonAsync(HttpMethod.Post, new Uri(new Uri(url), "/v1/pairing/redeem"), body, cancellationToken, url, CreateIdempotencyKey());
        ApplyDeviceResponse(url, response);
        await RefreshAsync(cancellationToken);
        return new ControlResult(true, "paired", _state.PublicId, null, _state.ConfigVersion);
    }

    public async Task<ControlResult> RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (!IsEnrolled)
        {
            // A device can already be registered by Control while the client is
            // missing the first signed configuration (for example when the
            // redeem response was lost or an older client stopped halfway).
            // The retained device key is the durable activation credential, so
            // every refresh path must first try to finish that activation. This
            // also lets warm start and update checks recover without asking the
            // user to submit an already-consumed invitation again.
            if (_trustedOrigin is null && !_lifecycleOnly)
                return new ControlResult(false, "not enrolled", null, null, 0);
            try
            {
                return await ResumeEnrollmentAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException error) when (error.Message == "BF-AUTH-003")
            {
                // The retained key is genuinely unknown to Control. Only this
                // response means a new invitation or account recovery is needed.
                return new ControlResult(false, "not enrolled", null, null, 0);
            }
        }
        // The in-memory state is the last value successfully committed by
        // SaveState.  Use it as the pre-request identity so a healthy online
        // refresh does not decrypt/read/hash the DPAPI state file every time
        // the user presses Connect. If transport fails, the persisted state is
        // still re-read and must match this exact identity before LKG is used.
        var hasLkg = _state.ConfigVersion > 0 && !string.IsNullOrWhiteSpace(_state.ConfigJson) && IsSha256Digest(_state.ConfigDigest);
        var before = hasLkg ? CurrentLkgIdentity() : default;
        try
        {
            return await RefreshOnlineAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (hasLkg && BifrostWindowsAvailabilityClassifier.CanUseOffline(error, cancellationToken))
        {
            var after = ReadLkgIdentity();
            if (before != after) throw new InvalidDataException("BF-CONFIG-LKG");
            return new ControlResult(true, "offline: using the last known-good configuration", _state.PublicId, null, after.Version);
        }
    }

    /// <summary>
    /// Completes an enrollment which reached the control plane but was
    /// interrupted before the first signed configuration was written locally.
    /// RefreshAsync intentionally rejects this state because it is not yet
    /// enrolled; this method instead proves the retained device identity,
    /// creates a session, and obtains that first configuration.  The pending
    /// invite is only cleared by the caller after this succeeds.
    /// </summary>
    private async Task<ControlResult> ResumeEnrollmentAsync(CancellationToken cancellationToken)
    {
        var origin = RequireTrustedOrigin();
        EnsureKeys();
        if (!string.Equals(_state.ControlUrl, origin, StringComparison.Ordinal))
        {
            var pending = CloneState(_state);
            pending.ControlUrl = origin;
            SaveState(_stateFile, pending);
            _state = pending;
        }

        await EnsureEnrollmentIdentitySessionAsync(cancellationToken).ConfigureAwait(false);
        var resumed = await RefreshOnlineAsync(cancellationToken).ConfigureAwait(false);
        if (!resumed.Ok || resumed.ConfigVersion <= 0 || !IsEnrolled)
            throw new InvalidDataException("BF-ENROLL-RESUME");
        return resumed;
    }

    private Task EnsureEnrollmentIdentitySessionAsync(CancellationToken cancellationToken)
    {
        // A 2.1.13-era resume attempt can leave a valid session token behind
        // without the account identity. Force precisely that token to renew so
        // the opted-in identity response is actually requested.
        var observedToken = string.IsNullOrWhiteSpace(_state.PublicId) ? _state.SessionToken : null;
        return EnsureSessionAsync(observedToken, cancellationToken);
    }

    private async Task<ControlResult> RefreshOnlineAsync(CancellationToken cancellationToken)
    {
        var manifest = await SendAuthorizedAsync(HttpMethod.Get, new Uri(new Uri(_state.ControlUrl!), "/v1/config/manifest"), null, cancellationToken).ConfigureAwait(false);
        var version = manifest["config_version"]?.GetValue<long>() ?? 0;
        var floor = manifest["rollback_floor"]?.GetValue<long>() ?? 1;
        var manifestDigest = manifest["digest"]?.GetValue<string>();
        if (version < floor || version < _state.ConfigVersion) throw new InvalidDataException("BF-CONFIG-ANTI-ROLLBACK");
        if (!IsSha256Digest(manifestDigest)) throw new InvalidDataException("BF-CONFIG-DIGEST");
        var trustState = VerifyConfigKeyState(manifest, version);
        if (version == _state.ConfigVersion)
        {
            if (!string.IsNullOrWhiteSpace(_state.ConfigJson) && string.Equals(_state.ConfigDigest, manifestDigest, StringComparison.OrdinalIgnoreCase))
            {
                SaveConfigKeyState(trustState);
                return new ControlResult(true, "already current", _state.PublicId, null, version);
            }
            if (!string.IsNullOrWhiteSpace(_state.ConfigJson) && !string.Equals(_state.ConfigDigest, manifestDigest, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-CONFIG-EQUIVOCATION");
        }
        var envelope = await SendAuthorizedAsync(HttpMethod.Get, new Uri(new Uri(_state.ControlUrl!), $"/v1/config/packages/{version}"), null, cancellationToken).ConfigureAwait(false);
        var packageDigest = PackageDigest(envelope);
        if (!string.Equals(packageDigest, manifestDigest, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-CONFIG-DIGEST");
        SaveConfig(DecryptAndVerifyPackage(envelope, version, trustState), version, packageDigest, trustState, envelope);
        return new ControlResult(true, "node configuration updated", _state.PublicId, null, version);
    }

    private (long Version, string Digest, string ContentDigest) ReadLkgIdentity()
    {
        if (string.IsNullOrWhiteSpace(_stateFile)) throw new InvalidDataException("BF-CONFIG-LKG");
        var persisted = LoadState(_stateFile);
        if (persisted.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(persisted.ConfigJson) || !IsSha256Digest(persisted.ConfigDigest))
            throw new InvalidDataException("BF-CONFIG-LKG");
        var contentBytes = StrictUtf8.GetBytes(persisted.ConfigJson);
        try
        {
            return (persisted.ConfigVersion, persisted.ConfigDigest!, Convert.ToHexString(SHA256.HashData(contentBytes)).ToLowerInvariant());
        }
        finally { CryptographicOperations.ZeroMemory(contentBytes); }
    }

    private (long Version, string Digest, string ContentDigest) CurrentLkgIdentity()
    {
        if (_state.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(_state.ConfigJson) || !IsSha256Digest(_state.ConfigDigest))
            throw new InvalidDataException("BF-CONFIG-LKG");
        var contentBytes = StrictUtf8.GetBytes(_state.ConfigJson);
        try
        {
            return (_state.ConfigVersion, _state.ConfigDigest!, Convert.ToHexString(SHA256.HashData(contentBytes)).ToLowerInvariant());
        }
        finally { CryptographicOperations.ZeroMemory(contentBytes); }
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        if (IsEnrolled)
        {
            // Preserve the encrypted identity when remote logout fails so the
            // same operation can be retried instead of stranding a bound slot.
            var revoked = false;
            try { await EstablishSessionAsync(cancellationToken); }
            catch (InvalidOperationException error) when (error.Message is "BF-AUTH-003" or "BF-DEVICE-404")
            {
                // The device challenge/session, not an expired bearer, has
                // confirmed this identity no longer has authorization.
                revoked = true;
            }
            if (!revoked)
                await SendAuthorizedAsync(HttpMethod.Post, new Uri(new Uri(_state.ControlUrl!), "/v1/device/logout"), new JsonObject(), cancellationToken);
        }
        var candidate = new ControlState();
        SaveState(_stateFile, candidate);
        _state = candidate;
    }

    public async Task<SignedClientPackageRequest> PrepareSignedPackageAsync(string sourceCode, string countryCode, string mode, string core, string? candidateCode = null, IEnumerable<string>? includeApplications = null, IEnumerable<string>? excludeApplications = null, string? frontSourceCode = null, string appPolicyMode = "allow", CancellationToken cancellationToken = default, ApplicationPolicySnapshot? applicationPolicySnapshot = null, string connectionType = "direct-vmess")
    {
        if (string.IsNullOrWhiteSpace(_state.ConfigJson)) throw new InvalidOperationException("BF-CONFIG-NOT-AVAILABLE");
        var config = JsonNode.Parse(_state.ConfigJson) as JsonObject ?? throw new InvalidDataException("BF-CONFIG-JSON");
        _ = ConnectionRouteSelection.Parse(connectionType, mode);
        var requestedCandidate = CandidateSelectionContract.ValidateManual(
            config,
            sourceCode,
            string.IsNullOrWhiteSpace(candidateCode) ? CandidateMode.Auto : CandidateMode.Manual,
            candidateCode
        );
        var requestedPolicy = appPolicyMode.Trim().ToLowerInvariant();
        if (requestedPolicy is not ("none" or "allow" or "exclude")) throw new InvalidDataException("BF-APP-POLICY");
        if (mode == ProtocolCodes.ModePerApp && requestedPolicy is not ("allow" or "exclude")) throw new InvalidDataException("BF-APP-POLICY");
        var policy = mode == ProtocolCodes.ModePerApp ? requestedPolicy : "none";
        var snapshot = applicationPolicySnapshot is null
            ? ApplicationPolicySnapshot.Create(mode, policy, includeApplications ?? Array.Empty<string>(), excludeApplications ?? Array.Empty<string>(), Guid.NewGuid().ToString("N"))
            : ApplicationPolicySnapshot.Parse(applicationPolicySnapshot.CanonicalJson);
        if (snapshot != applicationPolicySnapshot && applicationPolicySnapshot is not null) throw new InvalidDataException("BF-APP-POLICY-SNAPSHOT");
        if (snapshot.RouteMode != mode || snapshot.PolicyMode != policy) throw new InvalidDataException("BF-APP-POLICY-SNAPSHOT");
        if (string.IsNullOrWhiteSpace(snapshot.Digest) || string.IsNullOrWhiteSpace(snapshot.Generation)) throw new InvalidDataException("BF-APP-POLICY-SNAPSHOT");
        if (mode == ProtocolCodes.ModePerApp && policy == "allow" && snapshot.IncludeIdentities.Count == 0) throw new InvalidDataException("BF-APP-ALLOW-EMPTY");
        if (mode == ProtocolCodes.ModePerApp && policy == "exclude" && snapshot.ExcludeIdentities.Count == 0) throw new InvalidDataException("BF-APP-EXCLUDE-EMPTY");
        _ = config["routing"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-ROUTING");
        var selectedSource = SelectSource(config, sourceCode);
        _ = selectedSource["transport"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-TRANSPORT");
        _ = SelectProfile(selectedSource, countryCode);
        var front = countryCode.Equals("default", StringComparison.OrdinalIgnoreCase) ? selectedSource : ResolveFrontSource(config, selectedSource, config["countries"]?.AsArray().OfType<JsonObject>().FirstOrDefault(n => string.Equals(n["code"]?.GetValue<string>(), countryCode, StringComparison.OrdinalIgnoreCase)), frontSourceCode);
        // Match Android: automatic Smart/SmartGate startup resolves a signed
        // seed only. The native group probes every member and the service's
        // actual data-plane gate admits the first working connection.
        var nativeAutomatic = mode == ProtocolCodes.ModeSmart && requestedCandidate is null;
        var selection = await CandidateSelectionPlan.SelectAsync(selectedSource, front, requestedCandidate,
            (source, requested, token) => SelectCandidateAsync(source,
                nativeAutomatic ? requested ?? CandidateSelectionPlan.SignedSeed(source) : requested, token),
            cancellationToken).ConfigureAwait(false);
        var selectedCandidate = selection.SelectedCandidate;
        JsonObject? frontCandidate = selection.FrontCandidate;
        if (!ReferenceEquals(front, selectedSource))
        {
            _ = front["transport"] as JsonObject ?? throw new InvalidDataException("BF-SMARTGATE-FRONT-TRANSPORT");
            _ = SelectProfile(front, "default");
        }
        if (core is not (ProtocolCodes.CoreAuto or ProtocolCodes.CoreMihomo)) throw new InvalidDataException("BF-CONFIG-CORE");
        var corePolicy = config["core_policy"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-CORE");
        var allowedCores = (corePolicy["allowed"] as JsonArray)?.OfType<JsonValue>().Select(value => value.GetValue<string>()).ToHashSet(StringComparer.Ordinal)
            ?? throw new InvalidDataException("BF-CONFIG-CORE");
        if (core != ProtocolCodes.CoreAuto && !allowedCores.Contains(core)) throw new InvalidDataException("BF-CONFIG-CORE");
        var signedEnvelope = _state.ConfigEnvelopeJson ?? throw new InvalidDataException("BF-CONFIG-SIGNED-PACKAGE-REQUIRED");
        var signedContentDigest = GetRequiredString(JsonNode.Parse(signedEnvelope)?.AsObject() ?? throw new InvalidDataException("BF-CONFIG-PACKAGE"), "content_digest");
        var bootstrapCandidate = frontCandidate ?? selectedCandidate;
        var bootstrapProxyType = bootstrapCandidate["bootstrap_proxy_type"]?.GetValue<string>();
        int? bootstrapProxyPort = bootstrapCandidate["bootstrap_proxy_port"] is JsonValue bootstrapPortValue
            ? bootstrapPortValue.GetValue<int>()
            : null;
        return new SignedClientPackageRequest(mode, core, sourceCode, countryCode, snapshot.PolicyMode, snapshot, connectionType,
            _state.ConfigVersion, signedContentDigest, _state.ConfigJson!, signedEnvelope, _state.ConfigKeyStateJson,
            selectedCandidate["label"]?.GetValue<string>(), ReferenceEquals(front, selectedSource) ? null : front["code"]?.GetValue<string>(), frontCandidate?["label"]?.GetValue<string>(),
            bootstrapProxyType, bootstrapProxyPort);
    }

    private static JsonObject SelectProfile(JsonObject source, string countryCode)
    {
        var profiles = source["profiles"] as JsonObject ?? throw new InvalidDataException("BF-PROFILE-MISSING");
        JsonObject? profile = string.Equals(countryCode, "default", StringComparison.OrdinalIgnoreCase)
            ? profiles["direct"] as JsonObject
            : (profiles["countries"] as JsonObject)?[countryCode] as JsonObject;
        if (profile is null || profile["uuid"]?.GetValue<string>() is not { Length: > 0 } uuid || !Guid.TryParseExact(uuid, "D", out _))
            throw new InvalidDataException("BF-PROFILE-MISSING");
        if (profile.Any(property => property.Key is not ("profile_id" or "uuid")))
            throw new InvalidDataException("BF-PROFILE-SHAPE");
        return profile;
    }

    private static JsonObject ResolveFrontSource(JsonObject config, JsonObject selectedSource, JsonObject? country, string? requestedCode)
    {
        var selectedCode = selectedSource["code"]?.GetValue<string>() ?? string.Empty;
        var mappedCode = country?["front_source_code"]?.GetValue<string>()?.Trim();
        var explicitRequest = !string.IsNullOrWhiteSpace(requestedCode) && !string.Equals(requestedCode.Trim(), "auto", StringComparison.OrdinalIgnoreCase);
        var code = !explicitRequest
            ? (string.IsNullOrWhiteSpace(mappedCode) ? selectedCode : mappedCode)
            : requestedCode!.Trim();
        var allowed = country?["front_source_options"]?.AsArray().OfType<JsonValue>().Select(value => value.GetValue<string>()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (explicitRequest && (!string.IsNullOrWhiteSpace(mappedCode) || allowed is { Count: > 0 }))
        {
            var explicitlyAuthorized = allowed is { Count: > 0 } && allowed.Contains(code)
                || (allowed is not { Count: > 0 } && string.Equals(mappedCode, code, StringComparison.OrdinalIgnoreCase));
            if (!explicitlyAuthorized) throw new InvalidDataException("BF-SMARTGATE-FRONT-NOT-MAPPED");
        }
        if (!string.Equals(code, selectedCode, StringComparison.OrdinalIgnoreCase))
        {
            var authorized = allowed is { Count: > 0 } && allowed.Contains(code)
                || (allowed is not { Count: > 0 } && string.Equals(mappedCode, code, StringComparison.OrdinalIgnoreCase));
            if (!authorized || (explicitRequest && string.IsNullOrWhiteSpace(mappedCode) && allowed is not { Count: > 0 }))
                throw new InvalidDataException("BF-SMARTGATE-FRONT-NOT-MAPPED");
        }
        if (string.Equals(code, selectedCode, StringComparison.OrdinalIgnoreCase)) return selectedSource;
        return SelectSource(config, code);
    }

    private static string ReadDnsUrl(JsonObject config, string key)
    {
        var dns = ((config["routing"] as JsonObject)?["dns_policy"] as JsonObject) ?? throw new InvalidDataException("BF-DNS-POLICY-MISSING");
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "version", "remote", "direct", "smart_gate_remote", "plaintext_fallback", "ipv4", "ipv6", "failure" };
        if (dns.Select(property => property.Key).Any(name => !allowed.Contains(name)) || dns.Count != allowed.Count || dns["version"]?.GetValue<string>() != "dns-policy-v1" || dns["smart_gate_remote"]?.GetValue<bool>() != true || dns["plaintext_fallback"]?.GetValue<bool>() != false || dns["failure"]?.GetValue<string>() != "block" || dns["ipv4"]?.GetValue<string>() is not ("proxy" or "block") || dns["ipv6"]?.GetValue<string>() is not ("proxy" or "block")) throw new InvalidDataException("BF-DNS-POLICY");
        var value = dns[key]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("BF-DNS-POLICY-MISSING");
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || (uri.Port != -1 && uri.Port != 443) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) throw new InvalidDataException("BF-DNS-PLAINTEXT");
        var host = uri.Host.TrimEnd('.');
        if (System.Net.IPAddress.TryParse(host, out _) || host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) || host.Equals("test", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".test", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-DNS-POLICY");
        return value;
    }

    private async Task<JsonObject> SelectCandidateAsync(JsonObject source, string? requested, CancellationToken cancellationToken = default)
    {
        await _candidateSelectionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // A genuine physical default-path transition may cancel the probe
            // that was already bound to the old underlay. Retry that precise
            // case once after the topology settles. Manual cancellation and
            // caller/lifetime cancellation do not advance this generation and
            // therefore never get silently restarted.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var physicalGeneration = Volatile.Read(ref _physicalNetworkGeneration);
                try
                {
                    return await SelectCandidateCoreAsync(source, requested, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    attempt == 0 &&
                    !cancellationToken.IsCancellationRequested &&
                    physicalGeneration != Volatile.Read(ref _physicalNetworkGeneration))
                {
                    // Exactly one automatic retry is permitted. A second real
                    // network transition propagates cancellation to the caller.
                }
            }
            throw new OperationCanceledException(cancellationToken);
        }
        finally { _candidateSelectionGate.Release(); }
    }

    private async Task<JsonObject> SelectCandidateCoreAsync(JsonObject source, string? requested, CancellationToken cancellationToken = default)
    {
        var candidates = source["candidates"]?.AsArray().OfType<JsonObject>().ToList() ?? throw new InvalidDataException("BF-CONFIG-CANDIDATE");
        if (candidates.Count == 0) throw new InvalidDataException("BF-CONFIG-CANDIDATE");
        var sourceCode = source["code"]?.GetValue<string>() ?? throw new InvalidDataException("BF-CONFIG-SOURCE");
        var transport = source["transport"] as JsonObject ?? new JsonObject();
        var descriptor = BuildProbeDescriptor(source, transport);
        var preferred = requested;
        if (preferred is not null)
        {
            var preferredCandidate = candidates.FirstOrDefault(c => CandidateMatches(c, preferred))
                ?? throw new InvalidDataException("BF-CONFIG-CANDIDATE-NOT-IN-SOURCE");
            return preferredCandidate;
        }
        // Selection must measure the path that the shipping Mihomo runtime
        // will actually use. Every provider socket and every DIRECT outbound
        // is bound to the verified physical underlay, so routing the probe via
        // a third-party loopback proxy can select a node that fails as soon as
        // Bifrost takes over (and made healthy B candidates look dead here).
        var network = _networkBucket.GetFingerprint();
        var roundGeneration = Interlocked.Increment(ref _probeRoundGeneration);
        var candidateFingerprint = FingerprintCandidates(candidates);
        var transportFingerprint = FingerprintTransport(transport);
        string networkEpoch;
        lock (_networkProbeGate) networkEpoch = _networkProbeEpoch;
        var cacheRoot = LoadProbeCache() ?? new JsonObject { ["version"] = ProbeCacheVersion, ["buckets"] = new JsonObject() };
        var bucket = GetProbeBucket(cacheRoot, sourceCode, network, networkEpoch, candidateFingerprint, transportFingerprint, _state.ConfigVersion, _state.ConfigDigest);
        if (bucket is not null &&
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (bucket["at"]?.GetValue<long>() ?? 0) < 2 * 60 * 60 * 1000L)
        {
            var cachedLabel = bucket["label"]?.GetValue<string>();
            var cached = candidates.FirstOrDefault(c => CandidateMatches(c, cachedLabel));
            if (cached is not null) return cached;
        }
        var start = bucket?["cohort"]?.GetValue<int>() ?? 0;
        var incumbentLabel = bucket?["label"]?.GetValue<string>();
        var cohort = candidates.Where(c => !string.IsNullOrWhiteSpace(c["label"]?.GetValue<string>())).ToList();
        if (cohort.Count == 0) throw new InvalidDataException("BF-CONFIG-CANDIDATE-LABEL");
        var probes = CandidateSelectionPolicy.BuildCohort(
            cohort, start, MaxProbeCandidates, incumbentLabel,
            candidate => candidate["label"]?.GetValue<string>()).ToList();
        CancellationToken networkCancellation;
        lock (_networkProbeGate) networkCancellation = _networkProbeCancellation.Token;
        using var roundCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, networkCancellation);
        using var concurrency = new SemaphoreSlim(MaxProbeConcurrency, MaxProbeConcurrency);
        var measurements = await Task.WhenAll(probes.Select(async candidate =>
        {
            await concurrency.WaitAsync(roundCancellation.Token).ConfigureAwait(false);
            try
            {
                var candidateBudget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes);
                return (candidate, probe: await ProbeCandidateAsync(candidate, descriptor, candidateBudget,
                    roundCancellation.Token, cancellationToken).ConfigureAwait(false));
            }
            finally { concurrency.Release(); }
        })).ConfigureAwait(false);
        if (cancellationToken.IsCancellationRequested)
            throw new OperationCanceledException(cancellationToken);
        if (roundGeneration != Volatile.Read(ref _probeRoundGeneration) || networkCancellation.IsCancellationRequested)
            throw new OperationCanceledException(networkCancellation);
        var cacheToWrite = bucket is null
            ? new JsonObject()
            : JsonNode.Parse(bucket.ToJsonString())!.AsObject();
        var history = cacheToWrite["history"] as JsonObject ?? new JsonObject();
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        foreach (var measurement in measurements)
        {
            var label = measurement.candidate["label"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(label)) UpdateProbeHistory(history, label!, measurement.probe, now);
        }
        cacheToWrite["history"] = history;
        var successful = measurements
            .Where(value => value.probe is { Success: true })
            .Select(value => (candidate: value.candidate, probe: value.probe!, score: ScoreProbe(value.candidate, value.probe!, history, now)))
            .OrderBy(value => value.score)
            .ToList();
        if (successful.Count == 0)
        {
            // A failed refresh is not a successful refresh.  Retain a
            // last-good candidate only when it is still in this signed source
            // and preserve its previous success timestamp for a later retry.
            var saved = incumbentLabel is null ? null : candidates.FirstOrDefault(c => CandidateMatches(c, incumbentLabel));
            var previousAt = bucket?["at"]?.GetValue<long>() ?? 0L;
            var fallbackNow = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            cacheToWrite["source"] = sourceCode;
            cacheToWrite["network"] = network;
            cacheToWrite["network_epoch"] = networkEpoch;
            cacheToWrite["config_version"] = _state.ConfigVersion;
            cacheToWrite["config_digest"] = _state.ConfigDigest;
            cacheToWrite["candidate_fingerprint"] = candidateFingerprint;
            cacheToWrite["transport_fingerprint"] = transportFingerprint;
            cacheToWrite["round_generation"] = roundGeneration;
            cacheToWrite["label"] = saved?["label"]?.GetValue<string>();
            cacheToWrite["at"] = CandidateSelectionPolicy.SuccessTimestamp(previousAt, fallbackNow, false);
            cacheToWrite["last_attempt"] = fallbackNow;
            cacheToWrite["cohort"] = cohort.Count == 0 ? 0 : (start + Math.Max(1, probes.Count)) % cohort.Count;
            var bucketsOnFailure = cacheRoot["buckets"] as JsonObject ?? new JsonObject();
            bucketsOnFailure[ProbeBucketKey(sourceCode, network, networkEpoch, candidateFingerprint, transportFingerprint, _state.ConfigVersion, _state.ConfigDigest)] = cacheToWrite;
            cacheRoot["version"] = ProbeCacheVersion;
            cacheRoot["buckets"] = PruneProbeBuckets(bucketsOnFailure);
            SaveProbeCache(cacheRoot);
            if (saved is null) throw new InvalidDataException("BF-CANDIDATE-PROBE-FAILED");
            return saved;
        }
        var best = successful[0];
        var incumbent = successful.FirstOrDefault(value => CandidateMatches(value.candidate, incumbentLabel));
        var selected = incumbent.candidate is not null && incumbent.score <= best.score + 35.0 ? incumbent : best;
        cacheToWrite["source"] = sourceCode;
        cacheToWrite["network"] = network;
        cacheToWrite["network_epoch"] = networkEpoch;
        cacheToWrite["config_version"] = _state.ConfigVersion;
        cacheToWrite["config_digest"] = _state.ConfigDigest;
        cacheToWrite["candidate_fingerprint"] = candidateFingerprint;
        cacheToWrite["transport_fingerprint"] = transportFingerprint;
        cacheToWrite["round_generation"] = roundGeneration;
        cacheToWrite["at"] = CandidateSelectionPolicy.SuccessTimestamp(bucket?["at"]?.GetValue<long>() ?? 0L, now, true);
        cacheToWrite["last_attempt"] = now;
        cacheToWrite["label"] = selected.candidate["label"]?.GetValue<string>();
        cacheToWrite["cohort"] = (start + Math.Max(1, probes.Count)) % cohort.Count;
        cacheToWrite["rtt_ms"] = selected.probe.RttMs;
        cacheToWrite["jitter_ms"] = selected.probe.JitterMs;
        cacheToWrite["loss_percent"] = selected.probe.LossPercent;
        cacheToWrite["tls_success"] = selected.probe.TlsSuccess;
        cacheToWrite["last_used"] = now;
        var buckets = cacheRoot["buckets"] as JsonObject ?? new JsonObject();
        buckets[ProbeBucketKey(sourceCode, network, networkEpoch, candidateFingerprint, transportFingerprint, _state.ConfigVersion, _state.ConfigDigest)] = cacheToWrite;
        cacheRoot["version"] = ProbeCacheVersion;
        cacheRoot["buckets"] = PruneProbeBuckets(buckets);
        SaveProbeCache(cacheRoot);
        return selected.candidate;
    }

    private async Task<CandidateProbeSnapshot> ProbeCandidateStatusesCoreAsync(JsonObject source, CancellationToken cancellationToken)
    {
        var candidates = source["candidates"]?.AsArray().OfType<JsonObject>()
            .Where(candidate => !string.IsNullOrWhiteSpace(candidate["label"]?.GetValue<string>()))
            .ToList() ?? throw new InvalidDataException("BF-CONFIG-CANDIDATE");
        var sourceCode = source["code"]?.GetValue<string>() ?? throw new InvalidDataException("BF-CONFIG-SOURCE");
        if (candidates.Count == 0)
            return new CandidateProbeSnapshot(sourceCode, null, Array.Empty<CandidateProbeStatus>());

        var transport = source["transport"] as JsonObject ?? new JsonObject();
        var descriptor = BuildProbeDescriptor(source, transport);
        var network = _networkBucket.GetFingerprint();
        var roundGeneration = Interlocked.Increment(ref _probeRoundGeneration);
        var candidateFingerprint = FingerprintCandidates(candidates);
        var transportFingerprint = FingerprintTransport(transport);
        string networkEpoch;
        CancellationToken networkCancellation;
        lock (_networkProbeGate)
        {
            networkEpoch = _networkProbeEpoch;
            networkCancellation = _networkProbeCancellation.Token;
        }

        using var roundCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, networkCancellation);
        using var concurrency = new SemaphoreSlim(MaxProbeConcurrency, MaxProbeConcurrency);
        var measurements = await Task.WhenAll(candidates.Select(async candidate =>
        {
            await concurrency.WaitAsync(roundCancellation.Token).ConfigureAwait(false);
            try
            {
                var budget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes);
                var probe = await ProbeCandidateAsync(candidate, descriptor, budget, roundCancellation.Token, cancellationToken).ConfigureAwait(false);
                return (candidate, probe);
            }
            finally { concurrency.Release(); }
        })).ConfigureAwait(false);
        if (roundGeneration != Volatile.Read(ref _probeRoundGeneration) || roundCancellation.IsCancellationRequested)
            throw new OperationCanceledException(roundCancellation.Token);

        var cacheRoot = LoadProbeCache() ?? new JsonObject { ["version"] = ProbeCacheVersion, ["buckets"] = new JsonObject() };
        var bucket = GetProbeBucket(cacheRoot, sourceCode, network, networkEpoch, candidateFingerprint, transportFingerprint, _state.ConfigVersion, _state.ConfigDigest);
        var cacheToWrite = bucket is null ? new JsonObject() : JsonNode.Parse(bucket.ToJsonString())!.AsObject();
        var history = cacheToWrite["history"] as JsonObject ?? new JsonObject();
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        foreach (var measurement in measurements)
        {
            var label = measurement.candidate["label"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(label)) UpdateProbeHistory(history, label!, measurement.probe, now);
        }

        var successful = measurements
            .Where(value => value.probe is { Success: true })
            .Select(value => (candidate: value.candidate, probe: value.probe!, score: ScoreProbe(value.candidate, value.probe!, history, now)))
            .OrderBy(value => value.score)
            .ToList();
        var incumbentLabel = bucket?["label"]?.GetValue<string>();
        JsonObject? selectedCandidate = null;
        ProbeResult? selectedProbe = null;
        if (successful.Count > 0)
        {
            var best = successful[0];
            var incumbent = successful.FirstOrDefault(value => CandidateMatches(value.candidate, incumbentLabel));
            var selected = incumbent.candidate is not null && incumbent.score <= best.score + 35.0 ? incumbent : best;
            selectedCandidate = selected.candidate;
            selectedProbe = selected.probe;
        }
        else if (!string.IsNullOrWhiteSpace(incumbentLabel))
        {
            selectedCandidate = candidates.FirstOrDefault(candidate => CandidateMatches(candidate, incumbentLabel));
        }

        cacheToWrite["source"] = sourceCode;
        cacheToWrite["network"] = network;
        cacheToWrite["network_epoch"] = networkEpoch;
        cacheToWrite["config_version"] = _state.ConfigVersion;
        cacheToWrite["config_digest"] = _state.ConfigDigest;
        cacheToWrite["candidate_fingerprint"] = candidateFingerprint;
        cacheToWrite["transport_fingerprint"] = transportFingerprint;
        cacheToWrite["round_generation"] = roundGeneration;
        cacheToWrite["history"] = history;
        cacheToWrite["last_attempt"] = now;
        cacheToWrite["label"] = selectedCandidate?["label"]?.GetValue<string>();
        if (selectedProbe is not null)
        {
            cacheToWrite["at"] = CandidateSelectionPolicy.SuccessTimestamp(bucket?["at"]?.GetValue<long>() ?? 0L, now, true);
            cacheToWrite["rtt_ms"] = selectedProbe.RttMs;
            cacheToWrite["jitter_ms"] = selectedProbe.JitterMs;
            cacheToWrite["loss_percent"] = selectedProbe.LossPercent;
            cacheToWrite["tls_success"] = selectedProbe.TlsSuccess;
            cacheToWrite["last_used"] = now;
        }
        else
        {
            cacheToWrite["at"] = bucket?["at"]?.GetValue<long>() ?? 0L;
        }
        var buckets = cacheRoot["buckets"] as JsonObject ?? new JsonObject();
        buckets[ProbeBucketKey(sourceCode, network, networkEpoch, candidateFingerprint, transportFingerprint, _state.ConfigVersion, _state.ConfigDigest)] = cacheToWrite;
        cacheRoot["version"] = ProbeCacheVersion;
        cacheRoot["buckets"] = PruneProbeBuckets(buckets);
        SaveProbeCache(cacheRoot);

        var statuses = measurements.Select(value =>
        {
            var code = value.candidate["label"]?.GetValue<string>() ?? string.Empty;
            var ok = value.probe is { Success: true };
            return new CandidateProbeStatus(
                code,
                ok,
                ok ? value.probe!.RttMs : null,
                value.probe is null ? null : value.probe.LossPercent,
                now);
        }).ToArray();
        return new CandidateProbeSnapshot(sourceCode, selectedCandidate?["label"]?.GetValue<string>(), statuses);
    }

    private static ProbeDescriptor BuildProbeDescriptor(JsonObject source, JsonObject transport)
    {
        var serverName = source["server_name"]?.GetValue<string>()?.Trim() ?? string.Empty;
        var host = (transport["host"]?.GetValue<string>() ?? string.Empty).Trim();
        var sni = (transport["sni"]?.GetValue<string>() ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(sni)) sni = serverName;
        if (string.IsNullOrWhiteSpace(host)) host = string.IsNullOrWhiteSpace(serverName) ? sni : serverName;
        if (string.IsNullOrWhiteSpace(sni)) sni = host;
        var path = source["ws_path"]?.GetValue<string>()?.Trim();
        if (string.IsNullOrWhiteSpace(path)) path = "/";
        if (!path.StartsWith('/')) path = "/" + path;
        return new ProbeDescriptor(
            ValidateHeader(host), ValidateHeader(sni), ValidatePath(path),
            transport["tls"]?.GetValue<bool>() ?? true,
            transport["network"]?.GetValue<string>() ?? "tcp");
    }

    private static string ValidateHeader(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(ch => ch == '\0' || char.IsControl(ch)) || value.Length > 255)
            throw new InvalidDataException("BF-PROBE-DESCRIPTOR");
        return value;
    }

    private static string ValidatePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || !value.StartsWith("/", StringComparison.Ordinal) ||
            value.Contains('\r') || value.Contains('\n') || value.Contains('\0') || value.Any(char.IsControl))
            throw new InvalidDataException("BF-PROBE-DESCRIPTOR");
        return value;
    }

    private static bool CandidateMatches(JsonObject candidate, string? value) => !string.IsNullOrWhiteSpace(value) &&
        new[] { "label", "id", "code", "dial_address", "address" }.Any(key => string.Equals(candidate[key]?.GetValue<string>(), value, StringComparison.OrdinalIgnoreCase));

    private static double ScoreProbe(JsonObject candidate, ProbeResult probe, JsonObject history, long now)
    {
        // Use only measurements from this device/network.  Signed control
        // plane telemetry such as recent_failure_rate/network_fit is not a
        // substitute for local success, TLS and latency evidence.
        var label = candidate["label"]?.GetValue<string>() ?? string.Empty;
        var local = history[label] as JsonObject;
        var success = local?["success_ewma"]?.GetValue<double>() ?? (probe.Success ? 1d : 0d);
        var cooldown = ReadProbeTimestamp(local?["cooldown_until"]);
        var cooldownPenalty = cooldown > now ? 10_000d : 0d;
        return probe.RttMs + probe.JitterMs * 0.8 + probe.LossPercent * 12 + (probe.TlsSuccess ? 0 : 500) + (1 - success) * 160 + cooldownPenalty;
    }

    private static void UpdateProbeHistory(JsonObject history, string label, ProbeResult? probe, long now)
    {
        var item = history[label] as JsonObject ?? new JsonObject();
        var success = probe?.Success == true;
        const double alpha = 0.2;
        var oldSuccess = item["success_ewma"]?.GetValue<double>() ?? (success ? 1d : 0d);
        var oldRtt = item["rtt_ewma"]?.GetValue<double>() ?? (probe?.RttMs ?? 9_999d);
        var oldJitter = item["jitter_ewma"]?.GetValue<double>() ?? (probe?.JitterMs ?? 9_999d);
        var oldLoss = item["loss_ewma"]?.GetValue<double>() ?? (probe?.LossPercent ?? 100d);
        var failures = success ? 0 : (item["consecutive_failures"]?.GetValue<int>() ?? 0) + 1;
        item["success_ewma"] = oldSuccess * (1 - alpha) + (success ? 1 : 0) * alpha;
        item["rtt_ewma"] = oldRtt * (1 - alpha) + (probe?.RttMs ?? 9_999d) * alpha;
        item["jitter_ewma"] = oldJitter * (1 - alpha) + (probe?.JitterMs ?? 9_999d) * alpha;
        item["loss_ewma"] = oldLoss * (1 - alpha) + (probe?.LossPercent ?? 100d) * alpha;
        item["consecutive_failures"] = failures;
        item["cooldown_until"] = success
            ? 0L
            : checked(now + (long)TimeSpan.FromMinutes(5).TotalMilliseconds * Math.Min(12, failures));
        history[label] = item;
    }

    private static long ReadProbeTimestamp(JsonNode? node)
    {
        if (node is not JsonValue value) return 0L;
        if (value.TryGetValue<long>(out var integer)) return integer;
        // Older probe-cache entries written before the timestamp type fix can
        // contain an integral JSON double. Accept only finite, non-negative
        // values so migration never turns malformed cache data into authority.
        if (value.TryGetValue<double>(out var floating) && double.IsFinite(floating) && floating >= 0d && floating <= long.MaxValue)
            return checked((long)floating);
        return 0L;
    }

    private async Task<ProbeResult?> ProbeCandidateAsync(JsonObject candidate, ProbeDescriptor descriptor, ProbeBudget budget, CancellationToken roundToken, CancellationToken callerToken, CandidateProbeEngine.LoopbackBootstrapProxy? bootstrapProxy = null)
    {
        var host = candidate["dial_address"]?.GetValue<string>() ?? candidate["address"]?.GetValue<string>();
        var port = candidate["port"]?.GetValue<int>() ?? 443;
        if (string.IsNullOrWhiteSpace(host) || port is < 1 or > 65535) return null;
        try
        {
            callerToken.ThrowIfCancellationRequested();
            return await _probeEngine.ProbeAsync(host, port, descriptor, budget, roundToken, bootstrapProxy).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (budget.IsExhausted && !callerToken.IsCancellationRequested)
        {
            // ProbeBudget deliberately cancels the shared round token as soon
            // as the byte ceiling is reached so sibling sockets stop promptly.
            // That is an internal bounded-resource outcome, not caller or
            // network-generation cancellation. Convert it to a failed sample
            // so already-completed successes remain eligible and automatic
            // selection can still try the loopback bootstrap fallback.
            return new ProbeResult(false, 9_999, 9_999, 100, false, budget.ConsumedBytes);
        }
        catch (OperationCanceledException) when (callerToken.IsCancellationRequested || roundToken.IsCancellationRequested) { throw; }
        catch (InvalidDataException) when (budget.IsExhausted) { return new ProbeResult(false, 9_999, 9_999, 100, false, budget.ConsumedBytes); }
        catch (SocketException) { return null; }
        catch (IOException) { return null; }
        catch (AuthenticationException) { return null; }
        catch (TimeoutException) { return null; }
    }

    private static async Task<CandidateProbeEngine.LoopbackBootstrapProxy?> GetLoopbackBootstrapProxyAsync(
        ProbeDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Uri.TryCreate($"https://{descriptor.Sni}/", UriKind.Absolute, out var destination)) return null;
            var systemProxy = HttpClient.DefaultProxy;
            if (systemProxy.IsBypassed(destination)) return null;
            var endpoint = systemProxy.GetProxy(destination);
            if (endpoint is null || endpoint == destination || endpoint.Scheme != Uri.UriSchemeHttp ||
                !string.IsNullOrEmpty(endpoint.UserInfo) || endpoint.Port is < 1 or > 65535)
                return null;
            if (!IPAddress.TryParse(endpoint.Host, out var address) || !IPAddress.IsLoopback(address)) return null;
            // v2rayN's mixed listener accepts both HTTP CONNECT and SOCKS5.
            // Prefer SOCKS5 when the loopback endpoint proves the no-auth
            // greeting because SOCKS5 can also carry UDP association; that is
            // required to keep QUIC control tunnels (for example cloudflared)
            // alive while Bifrost owns the host TUN. HTTP CONNECT remains a
            // compatibility fallback for ordinary HTTP-only local proxies.
            var type = await SupportsLoopbackSocks5Async(endpoint.Port, cancellationToken).ConfigureAwait(false)
                ? CandidateProbeEngine.LoopbackBootstrapProxy.Socks5
                : CandidateProbeEngine.LoopbackBootstrapProxy.HttpConnect;
            var candidate = new CandidateProbeEngine.LoopbackBootstrapProxy(type, endpoint.Port);
            return candidate.IsValid ? candidate : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    private static async Task<bool> SupportsLoopbackSocks5Async(int port, CancellationToken cancellationToken)
    {
        if (port is < 1 or > 65535) return false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(250));
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token).ConfigureAwait(false);
            if (!client.Connected) return false;
            using var stream = client.GetStream();
            var greeting = new byte[] { 0x05, 0x01, 0x00 };
            await stream.WriteAsync(greeting, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);
            var reply = new byte[2];
            var offset = 0;
            while (offset < reply.Length)
            {
                var read = await stream.ReadAsync(reply.AsMemory(offset), timeout.Token).ConfigureAwait(false);
                if (read <= 0) return false;
                offset += read;
            }
            return reply[0] == 0x05 && reply[1] == 0x00;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    private static JsonObject AttachBootstrapProxy(JsonObject candidate, CandidateProbeEngine.LoopbackBootstrapProxy proxy)
    {
        var clone = JsonNode.Parse(candidate.ToJsonString())!.AsObject();
        clone["bootstrap_proxy_type"] = proxy.Type;
        clone["bootstrap_proxy_port"] = proxy.Port;
        return clone;
    }

    private static string ProbeCachePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost", "runtime", "candidate-probe.bin");
    private static string LegacyProbeCachePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost", "runtime", "candidate-probe.json");
    private static string ProbeBucketKey(string source, string network, string networkEpoch, string candidateFingerprint, string transportFingerprint, long configVersion, string? configDigest) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\0", source.Trim().ToLowerInvariant(), network, networkEpoch, candidateFingerprint, transportFingerprint, configVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), configDigest ?? string.Empty)))).ToLowerInvariant();

    private static JsonObject? GetProbeBucket(JsonObject root, string source, string network, string networkEpoch, string candidateFingerprint, string transportFingerprint, long configVersion, string? configDigest)
    {
        var buckets = root["buckets"] as JsonObject;
        var bucket = buckets?[ProbeBucketKey(source, network, networkEpoch, candidateFingerprint, transportFingerprint, configVersion, configDigest)] as JsonObject;
        if (bucket is null) return null;
        if (!string.Equals(bucket["source"]?.GetValue<string>(), source, StringComparison.Ordinal) ||
            !string.Equals(bucket["network"]?.GetValue<string>(), network, StringComparison.Ordinal) ||
            !string.Equals(bucket["network_epoch"]?.GetValue<string>(), networkEpoch, StringComparison.Ordinal) ||
            !string.Equals(bucket["candidate_fingerprint"]?.GetValue<string>(), candidateFingerprint, StringComparison.Ordinal) ||
            !string.Equals(bucket["transport_fingerprint"]?.GetValue<string>(), transportFingerprint, StringComparison.Ordinal) ||
            (bucket["config_version"]?.GetValue<long>() ?? -1L) != configVersion ||
            !string.Equals(bucket["config_digest"]?.GetValue<string>(), configDigest, StringComparison.Ordinal)) return null;
        return bucket;
    }

    private static string FingerprintCandidates(IReadOnlyList<JsonObject> candidates)
    {
        var material = string.Join("\n", candidates.Select(candidate => string.Join("\0",
            candidate["label"]?.GetValue<string>() ?? string.Empty,
            candidate["dial_address"]?.GetValue<string>() ?? candidate["address"]?.GetValue<string>() ?? string.Empty,
            candidate["port"]?.GetValue<int>().ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty)));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private static string FingerprintTransport(JsonObject transport)
    {
        var material = string.Join("\0", transport["host"]?.GetValue<string>() ?? string.Empty,
            transport["sni"]?.GetValue<string>() ?? string.Empty,
            transport["network"]?.GetValue<string>() ?? string.Empty,
            transport["tls"]?.GetValue<bool>().ToString() ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private static JsonObject PruneProbeBuckets(JsonObject buckets)
    {
        const int maxBuckets = 8;
        var keep = buckets.OrderByDescending(pair => (pair.Value as JsonObject)?["last_used"]?.GetValue<long>() ?? 0L)
            .Take(maxBuckets).ToArray();
        var result = new JsonObject();
        foreach (var pair in keep) result[pair.Key] = pair.Value?.DeepClone();
        return result;
    }

    private static JsonObject? LoadProbeCache()
    {
        try
        {
            if (File.Exists(ProbeCachePath))
            {
                var protectedBytes = File.ReadAllBytes(ProbeCachePath);
                var plaintext = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                var parsed = JsonNode.Parse(plaintext) as JsonObject;
                if (parsed?["version"]?.GetValue<int>() == ProbeCacheVersion && parsed["buckets"] is JsonObject) return parsed;
                File.Delete(ProbeCachePath); // old/single-bucket data is not reused across networks
                return null;
            }
            if (File.Exists(LegacyProbeCachePath))
            {
                File.Delete(LegacyProbeCachePath); // plaintext legacy cache is never migrated
            }
        }
        catch
        {
            try { File.Delete(ProbeCachePath); } catch { }
            try { File.Delete(LegacyProbeCachePath); } catch { }
        }
        return null;
    }
    private static void SaveProbeCache(JsonObject cache)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ProbeCachePath)!);
            var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(cache.ToJsonString()), null, DataProtectionScope.CurrentUser);
            var temp = ProbeCachePath + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
            File.WriteAllBytes(temp, protectedBytes);
            File.Move(temp, ProbeCachePath, true);
        }
        catch { }
    }

    private static void WriteAtomic(string path, JsonObject value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(temp, value.ToJsonString(new JsonSerializerOptions { WriteIndented = false }), new UTF8Encoding(false));
        File.Move(temp, path, true);
    }

    private void OnNetworkTopologyChanged()
    {
        // NetworkChange is extremely noisy on Windows: Wintun, Radmin,
        // Tailscale, ZeroTier, Hyper-V and other virtual adapters can raise it
        // without changing the machine's real Internet underlay. Cancelling a
        // candidate round for those notifications creates a self-inflicted
        // prepare-signed-package failure. Observe only the real physical IPv4
        // gateway route identity and ignore topology notifications that leave
        // it unchanged.
        var current = TryGetPhysicalIpv4GatewaySignature();
        if (current is null) return;
        var changed = false;
        lock (_networkProbeGate)
        {
            if (_physicalIpv4GatewaySignature is null)
            {
                _physicalIpv4GatewaySignature = current;
                return;
            }
            if (!string.Equals(_physicalIpv4GatewaySignature, current, StringComparison.Ordinal))
            {
                _physicalIpv4GatewaySignature = current;
                Interlocked.Increment(ref _physicalNetworkGeneration);
                changed = true;
            }
        }
        if (changed) InvalidateNetworkProbeRound();
    }

    private static string? TryGetPhysicalIpv4GatewaySignature()
    {
        try
        {
            var routes = new List<string>();
            foreach (var item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus != OperationalStatus.Up ||
                    item.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel ||
                    LooksLikeVirtualOrTunnelAdapter(item))
                    continue;
                var properties = item.GetIPProperties();
                if (!properties.UnicastAddresses.Any(address =>
                        address.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(address.Address) &&
                        !address.Address.Equals(IPAddress.Any) && !address.Address.Equals(IPAddress.None)))
                    continue;
                var gateways = properties.GatewayAddresses
                    .Select(gateway => gateway.Address)
                    .Where(address =>
                        address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(address) &&
                        !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.None))
                    .Select(address => address.ToString())
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(address => address, StringComparer.Ordinal)
                    .ToArray();
                if (gateways.Length == 0) continue;
                // Include the physical adapter identity as well as its gateway
                // set. Switching Wi-Fi/Ethernet on the same router is a real
                // underlay change even when both interfaces use one gateway IP.
                routes.Add(item.Id + "=" + string.Join(',', gateways));
            }
            routes.Sort(StringComparer.Ordinal);
            return routes.Count == 0 ? "physical-ipv4:none" : "physical-ipv4:" + string.Join('|', routes);
        }
        catch
        {
            // A transient enumeration failure is not evidence of a topology
            // change. Keep the current probe alive rather than manufacturing a
            // cancellation from an uncertain observation.
            return null;
        }
    }

    private static bool LooksLikeVirtualOrTunnelAdapter(NetworkInterface item)
    {
        var value = (item.Name + " " + item.Description).ToLowerInvariant();
        return value.Contains("wintun", StringComparison.Ordinal) ||
               value.Contains("v2ray", StringComparison.Ordinal) ||
               value.Contains("sing-box", StringComparison.Ordinal) ||
               value.Contains("singbox", StringComparison.Ordinal) ||
               value.Contains("tailscale", StringComparison.Ordinal) ||
               value.Contains("zerotier", StringComparison.Ordinal) ||
               value.Contains("radmin vpn", StringComparison.Ordinal) ||
               value.Contains("wireguard", StringComparison.Ordinal) ||
               value.Contains("openvpn", StringComparison.Ordinal) ||
               value.Contains("tap-windows", StringComparison.Ordinal) ||
               value.Contains("hyper-v", StringComparison.Ordinal) ||
               value.Contains("vmware", StringComparison.Ordinal) ||
               value.Contains("virtualbox", StringComparison.Ordinal) ||
               value.Contains("hamachi", StringComparison.Ordinal) ||
               value.Contains("loopback", StringComparison.Ordinal) ||
               value.Contains(" tunnel", StringComparison.Ordinal) ||
               value.Contains(" tun ", StringComparison.Ordinal) ||
               value.EndsWith(" tun", StringComparison.Ordinal) ||
               value.Contains(" tap ", StringComparison.Ordinal) ||
               value.EndsWith(" tap", StringComparison.Ordinal);
    }

    private void InvalidateNetworkProbeRound()
    {
        lock (_networkProbeGate)
        {
            var previous = _networkProbeCancellation;
            _networkProbeCancellation = new CancellationTokenSource();
            _networkProbeEpoch = Guid.NewGuid().ToString("N");
            Interlocked.Increment(ref _probeRoundGeneration);
            previous.Cancel();
            previous.Dispose();
        }
        try { NetworkProbeInvalidated?.Invoke(); } catch { /* UI observers are isolated */ }
    }

    internal void CancelNetworkProbeRound() => InvalidateNetworkProbeRound();

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= _networkAddressChangedHandler;
        NetworkChange.NetworkAvailabilityChanged -= _networkAvailabilityChangedHandler;
        lock (_networkProbeGate)
        {
            _networkProbeCancellation.Cancel();
            _networkProbeCancellation.Dispose();
        }
        _sessionGate.Dispose();
        _enrollmentGate.Dispose();
        _candidateSelectionGate.Dispose();
        _http.Dispose();
    }

    private async Task<JsonObject> SendAuthorizedAsync(HttpMethod method, Uri uri, JsonObject? body, CancellationToken cancellationToken, string? idempotencyKey = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(RequestDeadline);
        var requestToken = deadline.Token;
        var replayable = method == HttpMethod.Get || method == HttpMethod.Head;
        // This is intentionally called for every authenticated operation. It
        // is a cheap guarded no-op for a fresh session and renews legacy or
        // nearly expired sessions before the request can fail with 401.
        await EnsureSessionAsync(null, requestToken).ConfigureAwait(false);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var requestUri = RequireRequestUri(uri, _state.ControlUrl);
            using var request = new HttpRequestMessage(method, requestUri);
            AddLocalEvaluationOriginHeader(request, _state.ControlUrl);
            byte[]? bodyBytes = null;
            try
            {
                if (body is not null)
                {
                    bodyBytes = StrictUtf8.GetBytes(Canonicalize(body));
                    request.Content = new ByteArrayContent(bodyBytes);
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                }
                var sessionToken = _state.SessionToken ?? throw new InvalidOperationException("BF-AUTH-SESSION");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sessionToken);
                if (!string.IsNullOrWhiteSpace(idempotencyKey)) request.Headers.Add("X-Bifrost-Idempotency-Key", idempotencyKey);
                var pathAndQuery = requestUri.PathAndQuery;
                var bodyDigest = bodyBytes is null ? Sha256(string.Empty) : Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
                var proofTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
                var proofNonce = B64(RandomNumberGenerator.GetBytes(18));
                var proofOperation = B64(RandomNumberGenerator.GetBytes(12));
                var proofVersion = string.IsNullOrWhiteSpace(idempotencyKey) ? "1" : "2";
                var proofMessage = proofVersion == "2"
                    ? $"BIFROST-PROOF-v2|{Sha256(sessionToken)}|{method.Method.ToUpperInvariant()}|{pathAndQuery}|{bodyDigest}|{proofTimestamp}|{proofNonce}|{proofOperation}|{idempotencyKey}"
                    : $"BIFROST-PROOF-v1|{Sha256(sessionToken)}|{method.Method.ToUpperInvariant()}|{pathAndQuery}|{bodyDigest}|{proofTimestamp}|{proofNonce}|{proofOperation}";
                request.Headers.Add("X-Bifrost-Proof-Version", proofVersion);
                request.Headers.Add("X-Bifrost-Proof-Timestamp", proofTimestamp);
                request.Headers.Add("X-Bifrost-Proof-Nonce", proofNonce);
                request.Headers.Add("X-Bifrost-Proof-Operation", proofOperation);
                request.Headers.Add("X-Bifrost-Proof-Digest", bodyDigest);
                request.Headers.Add("X-Bifrost-Proof-Signature", Sign(proofMessage));
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, requestToken).ConfigureAwait(false);
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    // A 401 is not necessarily an expired session. Preserve the
                    // validated error (including malformed edge responses) and
                    // renew only a replayable request with a rejected bearer.
                    // The second rejection must retain its original code.
                    try
                    {
                        return await ReadJsonAsync(response, requestToken).ConfigureAwait(false);
                    }
                    catch (InvalidOperationException error) when (replayable && attempt == 0 &&
                        error.Message is "BF-AUTH-003" or "BF-AUTH-REQUIRED" or "BF-AUTH-SESSION")
                    {
                        await EnsureSessionAsync(request.Headers.Authorization?.Parameter, requestToken).ConfigureAwait(false);
                        continue;
                    }
                }
                return await ReadJsonAsync(response, requestToken).ConfigureAwait(false);
            }
            finally
            {
                if (bodyBytes is not null) CryptographicOperations.ZeroMemory(bodyBytes);
            }
        }
        throw new InvalidOperationException("BF-AUTH-REQUIRED");
    }

    public IReadOnlyDictionary<string, string> CreateSenderProof(HttpMethod method, Uri uri, byte[]? bodyBytes, string? idempotencyKey = null) =>
        CreateSenderProofForSession(_state.SessionToken ?? throw new InvalidOperationException("BF-AUTH-SESSION"), method, uri, bodyBytes, idempotencyKey);

    /// <summary>
    /// Creates a proof bound to the exact bearer token selected by an
    /// out-of-band request, rather than consulting mutable session state.
    /// </summary>
    public IReadOnlyDictionary<string, string> CreateSenderProofForSession(string sessionToken, HttpMethod method, Uri uri, byte[]? bodyBytes, string? idempotencyKey = null)
    {
        if (string.IsNullOrWhiteSpace(sessionToken)) throw new InvalidOperationException("BF-AUTH-SESSION");
        var nonceBytes = RandomNumberGenerator.GetBytes(18);
        var operationBytes = RandomNumberGenerator.GetBytes(12);
        try
        {
            var token = sessionToken;
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
            var nonce = B64(nonceBytes);
            var operation = B64(operationBytes);
            var digest = bodyBytes is null ? Sha256(string.Empty) : Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
            var version = string.IsNullOrWhiteSpace(idempotencyKey) ? "1" : "2";
            var message = version == "2"
                ? $"BIFROST-PROOF-v2|{Sha256(token)}|{method.Method.ToUpperInvariant()}|{uri.PathAndQuery}|{digest}|{timestamp}|{nonce}|{operation}|{idempotencyKey}"
                : $"BIFROST-PROOF-v1|{Sha256(token)}|{method.Method.ToUpperInvariant()}|{uri.PathAndQuery}|{digest}|{timestamp}|{nonce}|{operation}";
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["X-Bifrost-Proof-Version"] = version,
                ["X-Bifrost-Proof-Timestamp"] = timestamp,
                ["X-Bifrost-Proof-Nonce"] = nonce,
                ["X-Bifrost-Proof-Operation"] = operation,
                ["X-Bifrost-Proof-Digest"] = digest,
                ["X-Bifrost-Proof-Signature"] = Sign(message)
            };
            if (!string.IsNullOrWhiteSpace(idempotencyKey)) headers["X-Bifrost-Idempotency-Key"] = idempotencyKey;
            return headers;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonceBytes);
            CryptographicOperations.ZeroMemory(operationBytes);
        }
    }

    private async Task EnsureSessionAsync(string? observedToken, CancellationToken cancellationToken)
    {
        await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = _state.SessionToken;
            var renewBefore = DateTimeOffset.UtcNow.Add(SessionRenewalSkew).ToUnixTimeMilliseconds();
            var missingOrExpiring = string.IsNullOrWhiteSpace(current) ||
                _state.SessionExpiresAtUnixMilliseconds <= renewBefore;
            var mustRenew = string.IsNullOrWhiteSpace(current) ||
                missingOrExpiring ||
                (!string.IsNullOrWhiteSpace(observedToken) && string.Equals(current, observedToken, StringComparison.Ordinal));
            if (!mustRenew) return;
            // Keep the previous token durably until the replacement has been
            // obtained and saved. A temporary network failure must not turn
            // an activated device into a locally unauthenticated one.
            await EstablishSessionAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private async Task EstablishSessionAsync(CancellationToken cancellationToken)
    {
        EnsureKeys();
        var origin = RequireTrustedOrigin();
        var baseUri = new Uri(origin, UriKind.Absolute);
        var challenge = await SendJsonAsync(HttpMethod.Post, new Uri(baseUri, "/v1/device/challenge"), new JsonObject { ["device_id"] = _state.DeviceId }, cancellationToken, origin);
        var challengeText = challenge["challenge"]?.GetValue<string>() ?? throw new InvalidDataException("BF-AUTH-CHALLENGE");
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var digest = Sha256(Canonicalize(new JsonObject { ["method"] = "GET", ["path"] = "/v1/config/manifest", ["body"] = "" }));
        var proof = new JsonObject { ["device_id"] = _state.DeviceId, ["challenge"] = challengeText, ["timestamp"] = timestamp, ["nonce"] = nonce, ["request_digest"] = digest, ["signature"] = Sign($"{challengeText}|{timestamp}|{nonce}|{digest}") };
        var session = await SendJsonAsync(HttpMethod.Post, new Uri(baseUri, "/v1/device/session"), proof, cancellationToken, origin, requestSessionIdentity: true);
        var sessionToken = session["session_token"]?.GetValue<string>() ?? throw new InvalidDataException("BF-AUTH-SESSION");
        var sessionExpiresAtText = session["expires_at"]?.GetValue<string>();
        if (!DateTimeOffset.TryParse(sessionExpiresAtText, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var sessionExpiresAt) || sessionExpiresAt <= DateTimeOffset.UtcNow.Add(SessionRenewalSkew))
            throw new InvalidDataException("BF-AUTH-SESSION-EXPIRY");
        var publicId = session["public_id"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(publicId) && string.IsNullOrWhiteSpace(_state.PublicId))
            throw new InvalidDataException("BF-AUTH-IDENTITY");
        var candidate = CloneState(_state);
        candidate.SessionToken = sessionToken;
        candidate.SessionExpiresAtUnixMilliseconds = sessionExpiresAt.ToUnixTimeMilliseconds();
        if (!string.IsNullOrWhiteSpace(publicId)) candidate.PublicId = publicId.Trim();
        SaveState(_stateFile, candidate, allowLifecycleOrigin: _lifecycleOnly);
        _state = candidate;
    }

    private async Task<JsonObject> SendJsonAsync(HttpMethod method, Uri uri, JsonObject body, CancellationToken cancellationToken, string? expectedOrigin = null, string? idempotencyKey = null, bool requestSessionIdentity = false)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(RequestDeadline);
        var requestUri = RequireRequestUri(uri, expectedOrigin ?? _state.ControlUrl ?? uri.GetLeftPart(UriPartial.Authority));
        using var request = new HttpRequestMessage(method, requestUri);
        AddLocalEvaluationOriginHeader(request, expectedOrigin ?? _state.ControlUrl);
        var bodyBytes = StrictUtf8.GetBytes(Canonicalize(body));
        try
        {
            request.Content = new ByteArrayContent(bodyBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            if (!string.IsNullOrWhiteSpace(idempotencyKey)) request.Headers.Add("X-Bifrost-Idempotency-Key", idempotencyKey);
            if (requestSessionIdentity) request.Headers.Add("X-Bifrost-Session-Identity", "public-id-v1");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            return await ReadJsonAsync(response, deadline.Token).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(bodyBytes); }
    }

    private static void AddLocalEvaluationOriginHeader(HttpRequestMessage request, string? expectedOrigin)
    {
        if (!BifrostBuildConstants.LocalEvaluation || string.IsNullOrWhiteSpace(expectedOrigin)) return;
        if (!TrustedControlOrigin.TryParse(expectedOrigin, out var origin) || origin is null) throw new InvalidOperationException("BF-CONTROL-ORIGIN");
        request.Headers.TryAddWithoutValidation("Origin", origin.Value);
    }

    private static string CreateIdempotencyKey()
    {
        var bytes = RandomNumberGenerator.GetBytes(18);
        try { return B64(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string EnrollmentInviteFingerprint(string inviteCode)
    {
        var bytes = StrictUtf8.GetBytes(inviteCode);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static bool IsRejectedEnrollment(Exception error) => error.Message is "BF-ENROLL-001" or "BF-ENROLL-002";

    private void ClearEnrollmentAttempt()
    {
        if (string.IsNullOrWhiteSpace(_state.EnrollmentIdempotency) && string.IsNullOrWhiteSpace(_state.EnrollmentInviteFingerprint)) return;
        var completed = CloneState(_state);
        completed.EnrollmentInviteFingerprint = null;
        completed.EnrollmentIdempotency = null;
        SaveState(_stateFile, completed, allowLifecycleOrigin: _lifecycleOnly);
        _state = completed;
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        if (status is >= 300 and <= 399) throw new InvalidOperationException("BF-CONTROL-REDIRECT");
        // Gateway failures can be generated by the CDN/tunnel edge itself and
        // therefore are not required to carry Bifrost's JSON error schema. The
        // availability policy treats 502-504 and Cloudflare's unavailable
        // tunnel status 530 as explicitly
        // retryable, allowing a previously verified/signed LKG to remain usable
        // without weakening any 2xx/4xx/protocol/crypto validation below.
        if (status is >= 502 and <= 504 or 530) throw StatusFailure(status);
        var contentType = response.Content.Headers.ContentType;
        if (contentType is null || !string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) || (contentType.CharSet is not null && !string.Equals(contentType.CharSet.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("BF-CONTROL-CONTENT-TYPE");
        if (response.Content.Headers.ContentLength is > MaxResponseBytes) throw new InvalidDataException("BF-CONTROL-RESPONSE-LIMIT");
        Stream stream;
        try
        {
            stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            throw StatusBodyFailure(status, error);
        }
        using var responseStream = stream;
        using var memory = new MemoryStream();
        var buffer = new byte[16 * 1024];
        try
        {
            int read;
            while (true)
            {
                try
                {
                    read = await responseStream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    throw StatusBodyFailure(status, error);
                }
                if (read == 0) break;
                if (memory.Length + read > MaxResponseBytes) throw new InvalidDataException("BF-CONTROL-RESPONSE-LIMIT");
                memory.Write(buffer, 0, read);
            }
            var bytes = memory.ToArray();
            try
            {
                var parsed = ParseStrictJsonObject(bytes, allowPackageCiphertext: true);
                var path = response.RequestMessage?.RequestUri?.AbsolutePath ?? string.Empty;
                var method = response.RequestMessage?.Method.Method ?? "GET";
                ProtocolContract.ValidateResponse(path, parsed, method, status);
                if (!response.IsSuccessStatusCode)
                {
                    // The response has already passed the endpoint contract.  Preserve a
                    // registered control-plane error instead of reducing it to the HTTP
                    // status, because activation must distinguish a rejected invite from
                    // an interrupted request that is safe to resume with the same key.
                    var code = parsed["error"]?["code"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(code) && ErrorRegistry.IsRegistered(code))
                        throw new InvalidOperationException(code);
                    throw StatusFailure(status);
                }
                return parsed;
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static Exception StatusBodyFailure(int status, Exception error) =>
        status is >= 502 and <= 504 or 530
            ? new BifrostWindowsRetryableStatusException(status, error)
            : new BifrostWindowsReachableStatusException(status, error);

    private static Exception StatusFailure(int status) =>
        status is >= 502 and <= 504 or 530
            ? new BifrostWindowsRetryableStatusException(status)
            : new BifrostWindowsReachableStatusException(status);

#if BIFROST_TEST_HARNESS
    internal Task<JsonObject> SendAuthorizedForHarnessAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!_lifecycleOnly) throw new InvalidDataException("BF-TEST-SCOPE");
        return SendAuthorizedAsync(HttpMethod.Get, new Uri(new Uri(_state.ControlUrl!), path), null, cancellationToken);
    }

    internal static Task<JsonObject> ReadJsonForHarnessAsync(HttpResponseMessage response, CancellationToken cancellationToken = default) =>
        ReadJsonAsync(response, cancellationToken);
#endif

    private sealed class JsonContainer
    {
        public JsonContainer(bool isArray) { IsArray = isArray; Properties = isArray ? null : new HashSet<string>(StringComparer.Ordinal); }
        public bool IsArray { get; }
        public int ArrayItems { get; set; }
        public string? CurrentProperty { get; set; }
        public HashSet<string>? Properties { get; }
    }

    private static JsonObject ParseStrictJsonObject(byte[] bytes, bool allowPackageCiphertext = false, bool allowStoredConfig = false)
    {
        try
        {
            if (bytes.Length == 0 || bytes.Length > MaxResponseBytes) throw new JsonException();
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = MaxJsonDepth, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
            var containers = new Stack<JsonContainer>();
            var rootKind = JsonTokenType.None;
            var propertyCount = 0;
            var tokenCount = 0;
            var rootClosed = false;
            while (reader.Read())
            {
                if (++tokenCount > MaxJsonTokens || reader.CurrentDepth > MaxJsonDepth) throw new JsonException();
                if (containers.Count == 0 && rootKind != JsonTokenType.None && reader.TokenType is not (JsonTokenType.EndObject or JsonTokenType.EndArray)) throw new JsonException();
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        if (containers.Count == 0)
                        {
                            if (rootKind != JsonTokenType.None) throw new JsonException();
                            rootKind = JsonTokenType.StartObject;
                        }
                        CountArrayValue(containers);
                        containers.Push(new JsonContainer(false));
                        break;
                    case JsonTokenType.StartArray:
                        if (containers.Count == 0)
                        {
                            if (rootKind != JsonTokenType.None) throw new JsonException();
                            rootKind = JsonTokenType.StartArray;
                        }
                        CountArrayValue(containers);
                        containers.Push(new JsonContainer(true));
                        break;
                    case JsonTokenType.PropertyName:
                        if (containers.Count == 0 || containers.Peek().IsArray || !containers.Peek().Properties!.Add(reader.GetString() ?? throw new JsonException()) || ++propertyCount > MaxJsonProperties) throw new JsonException();
                        if (reader.ValueSpan.Length > MaxJsonStringBytes) throw new JsonException();
                        containers.Peek().CurrentProperty = reader.GetString();
                        break;
                    case JsonTokenType.String:
                        if (containers.Count == 0) throw new JsonException();
                        var property = containers.Peek().IsArray ? null : containers.Peek().CurrentProperty;
                        var limit = allowPackageCiphertext && property == "ciphertext"
                            ? ((MaxConfigPlaintextBytes + 2) / 3) * 4
                            : allowStoredConfig && containers.Count == 1 && property is "ConfigJson" or "ConfigEnvelopeJson"
                                ? MaxStatePlaintextBytes : MaxJsonStringBytes;
                        if (reader.ValueSpan.Length > limit) throw new JsonException();
                        CountArrayValue(containers);
                        break;
                    case JsonTokenType.Number:
                    case JsonTokenType.True:
                    case JsonTokenType.False:
                    case JsonTokenType.Null:
                        if (containers.Count == 0) throw new JsonException();
                        CountArrayValue(containers);
                        break;
                    case JsonTokenType.EndObject:
                        if (containers.Count == 0 || containers.Pop().IsArray) throw new JsonException();
                        if (containers.Count == 0) rootClosed = true;
                        break;
                    case JsonTokenType.EndArray:
                        if (containers.Count == 0 || !containers.Pop().IsArray) throw new JsonException();
                        if (containers.Count == 0) rootClosed = true;
                        break;
                }
            }
            if (rootKind != JsonTokenType.StartObject || !rootClosed || containers.Count != 0 || reader.BytesConsumed != bytes.Length) throw new JsonException();
            return JsonNode.Parse(bytes, nodeOptions: null, documentOptions: new JsonDocumentOptions { MaxDepth = MaxJsonDepth, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false }) as JsonObject ?? throw new JsonException();
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or ArgumentException)
        {
            throw new InvalidDataException("BF-CONTROL-JSON");
        }
    }

    private static void CountArrayValue(Stack<JsonContainer> containers)
    {
        if (containers.Count == 0 || !containers.Peek().IsArray) return;
        if (++containers.Peek().ArrayItems > MaxJsonArrayItems) throw new JsonException();
    }

    private VerifiedConfigKeyState? VerifyConfigKeyState(JsonObject response, long configVersion)
    {
        if (configVersion <= 0) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
        return ConfigKeyTrust.VerifyResponseState(
            response["config_key_state"] as JsonObject,
            configVersion,
            _state.ConfigKeyStateGeneration,
            _state.ConfigKeyStateDigest);
    }

    private static void ApplyConfigKeyState(ControlState candidate, VerifiedConfigKeyState? trustState)
    {
        if (trustState is null) return;
        candidate.ConfigKeyStateJson = trustState.CanonicalState;
        candidate.ConfigKeyStateGeneration = trustState.Generation;
        candidate.ConfigKeyStateDigest = trustState.Digest;
    }

    private void SaveConfigKeyState(VerifiedConfigKeyState? trustState)
    {
        if (trustState is null) return;
        if (_state.ConfigKeyStateGeneration == trustState.Generation &&
            string.Equals(_state.ConfigKeyStateDigest, trustState.Digest, StringComparison.Ordinal) &&
            string.Equals(_state.ConfigKeyStateJson, trustState.CanonicalState, StringComparison.Ordinal))
            return;
        var candidate = CloneState(_state);
        ApplyConfigKeyState(candidate, trustState);
        SaveState(_stateFile, candidate);
        _state = candidate;
    }

    private void ApplyDeviceResponse(string url, JsonObject response, VerifiedConfigKeyState? suppliedTrustState = null, string? recoveryCode = null)
    {
        ValidateConfigTrustRoot(response);
        JsonObject? verifiedConfig = null;
        var verifiedVersion = _state.ConfigVersion;
        var verifiedDigest = _state.ConfigDigest;
        VerifiedConfigKeyState? trustState = suppliedTrustState;
        if (response.TryGetPropertyValue("config_package", out var packageNode))
        {
            if (packageNode is not JsonObject package) throw new InvalidDataException("BF-CONFIG-PACKAGE");
            verifiedVersion = response["config_version"]?.GetValue<long>() ?? 0;
            trustState ??= VerifyConfigKeyState(response, verifiedVersion);
            verifiedConfig = DecryptAndVerifyPackage(package, verifiedVersion, trustState);
            verifiedDigest = PackageDigest(package);
        }

        var previous = _state;
        var candidate = new ControlState
        {
            ControlUrl = url.TrimEnd('/'),
            PublicId = response["public_id"]?.GetValue<string>(),
            // Pairing and enrollment-resume responses do not carry a new
            // recovery delivery. Preserve the prior code in those cases.
            RecoveryCode = recoveryCode ?? previous.RecoveryCode,
            RecoveryPending = false,
            RecoveryDeliveryIdempotency = null,
            EnrollmentInviteFingerprint = previous.EnrollmentInviteFingerprint,
            EnrollmentIdempotency = previous.EnrollmentIdempotency,
            DeviceId = previous.DeviceId,
            SessionToken = previous.SessionToken,
            SessionExpiresAtUnixMilliseconds = previous.SessionExpiresAtUnixMilliseconds,
            SigningSeed = previous.SigningSeed,
            SigningPrivatePkcs8 = previous.SigningPrivatePkcs8,
            SigningPublicKey = previous.SigningPublicKey,
            EncryptionPrivatePkcs8 = previous.EncryptionPrivatePkcs8,
            EncryptionPublicKey = previous.EncryptionPublicKey,
            ConfigJson = verifiedConfig is null ? previous.ConfigJson : Canonicalize(verifiedConfig),
            ConfigVersion = verifiedConfig is null ? previous.ConfigVersion : verifiedVersion,
            ConfigDigest = verifiedConfig is null ? previous.ConfigDigest : verifiedDigest,
            ConfigEnvelopeJson = verifiedConfig is null ? previous.ConfigEnvelopeJson : Canonicalize(packageNode!.AsObject()),
            ConfigKeyStateJson = previous.ConfigKeyStateJson,
            ConfigKeyStateGeneration = previous.ConfigKeyStateGeneration,
            ConfigKeyStateDigest = previous.ConfigKeyStateDigest
        };
        ApplyConfigKeyState(candidate, trustState);
        SaveState(_stateFile, candidate);
        _state = candidate;
    }

    private static void ValidateConfigTrustRoot(JsonObject response)
    {
        if (!response.TryGetPropertyValue("config_signing_public_key", out var advertised)) return;
        byte[]? expected = null;
        byte[]? actual = null;
        try
        {
            var pem = advertised?.GetValue<string>() ?? throw new CryptographicException();
            expected = ExtractRawEd25519PublicKey(ConfigSigningKeyPem);
            actual = ExtractRawEd25519PublicKey(pem);
            if (!CryptographicOperations.FixedTimeEquals(expected, actual)) throw new CryptographicException();
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException or FormatException or InvalidOperationException or JsonException)
        {
            throw new InvalidDataException("BF-CONFIG-TRUST-ROOT");
        }
        finally
        {
            if (expected is not null) CryptographicOperations.ZeroMemory(expected);
            if (actual is not null) CryptographicOperations.ZeroMemory(actual);
        }
    }

    private JsonObject DecryptAndVerifyPackage(JsonObject envelope, long expectedVersion, VerifiedConfigKeyState? trustState = null)
    {
        const string algorithm = "X25519-HKDF-SHA256-AES-256-GCM";
        var required = new HashSet<string>(StringComparer.Ordinal) { "alg", "key_id", "config_version", "anti_rollback", "content_digest", "ephemeral_public_key", "salt", "iv", "tag", "ciphertext", "signature" };
        if (envelope.Count != required.Count || envelope.Any(pair => !required.Contains(pair.Key))) throw new InvalidDataException("BF-CONFIG-PACKAGE");
        var version = envelope["config_version"]?.GetValue<long>() ?? 0;
        var anti = envelope["anti_rollback"]?.GetValue<long>() ?? 0;
        var signingKeyId = envelope["key_id"]?.GetValue<string>() ?? string.Empty;
        var contentDigest = envelope["content_digest"]?.GetValue<string>() ?? string.Empty;
        if (envelope["alg"]?.GetValue<string>() != algorithm || !ConfigKeyTrust.KeyIdPattern.IsMatch(signingKeyId) || !IsSha256Digest(contentDigest) || version != expectedVersion || anti != version || version < _state.ConfigVersion)
            throw new InvalidDataException(version < _state.ConfigVersion ? "BF-CONFIG-ANTI-ROLLBACK" : "BF-CONFIG-PACKAGE");

        byte[]? signatureBytes = null, canonicalBytes = null, configPublicKey = null, ephemeralBytes = null, saltBytes = null, ivBytes = null, tagBytes = null, ciphertext = null, shared = null, key = null, aadBytes = null, plaintext = null;
        try
        {
            signatureBytes = DecodeExactCanonical(GetRequiredString(envelope, "signature"), 64, "BF-CONFIG-SIGNATURE");
            if (signatureBytes.Length != 64) throw new InvalidDataException("BF-CONFIG-SIGNATURE");
            var unsigned = new JsonObject();
            foreach (var pair in envelope) if (pair.Key != "signature") unsigned[pair.Key] = pair.Value?.DeepClone();
            canonicalBytes = StrictUtf8.GetBytes(Canonicalize(unsigned));
            if (_lifecycleTrustedConfigKey is not null)
                configPublicKey = _lifecycleTrustedConfigKey.ToArray();
            else if (trustState is not null)
                configPublicKey = ConfigKeyTrust.RawPublicKey(trustState.Select(signingKeyId, version).PublicKeyPem);
            else
            {
                if (ReleaseContract.TrustRootProvisioned || !string.Equals(signingKeyId, "config-signing-v1", StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
                configPublicKey = ExtractRawEd25519PublicKey(ConfigSigningKeyPem);
            }
            if (!Ed25519.Verify(signatureBytes, canonicalBytes, configPublicKey)) throw new CryptographicException("BF-CONFIG-SIGNATURE");

            ephemeralBytes = DecodeExactCanonical(GetRequiredString(envelope, "ephemeral_public_key"), 44, "BF-CONFIG-CRYPTO");
            saltBytes = DecodeExactCanonical(GetRequiredString(envelope, "salt"), 16, "BF-CONFIG-CRYPTO");
            ivBytes = DecodeExactCanonical(GetRequiredString(envelope, "iv"), 12, "BF-CONFIG-CRYPTO");
            tagBytes = DecodeExactCanonical(GetRequiredString(envelope, "tag"), 16, "BF-CONFIG-CRYPTO");
            ciphertext = DecodeBounded(GetRequiredString(envelope, "ciphertext"), MaxConfigPlaintextBytes, "BF-CONFIG-CRYPTO");
            if (ephemeralBytes.Length != 44 || saltBytes.Length != 16 || ivBytes.Length != 12 || tagBytes.Length != 16 || ciphertext.Length == 0)
                throw new InvalidDataException("BF-CONFIG-CRYPTO");

            shared = X25519Managed.SharedSecretFromPkcs8(_state.EncryptionPrivatePkcs8!, ephemeralBytes);
            aadBytes = StrictUtf8.GetBytes("bifrost-config-v1");
            key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, saltBytes, aadBytes);
            plaintext = new byte[ciphertext.Length];
            using (var aes = new AesGcm(key, 16)) aes.Decrypt(ivBytes, ciphertext, tagBytes, plaintext);
            JsonObject config;
            try { config = ParseStrictJsonObject(plaintext); }
            catch (InvalidDataException) { throw new InvalidDataException("BF-CONFIG-SCHEMA"); }
            if (config["schema_version"]?.GetValue<string>() != "1.0" || config["config_version"]?.GetValue<long>() != version || config["anti_rollback"]?.GetValue<long>() != version || config["sources"] is not JsonArray || config["countries"] is not JsonArray || config["routing"] is not JsonObject || config["core_policy"] is not JsonObject)
                throw new InvalidDataException("BF-CONFIG-SCHEMA");
            var canonicalConfig = StrictUtf8.GetBytes(Canonicalize(config));
            try
            {
                var actualContentDigest = Convert.ToHexString(SHA256.HashData(canonicalConfig)).ToLowerInvariant();
                if (!string.Equals(actualContentDigest, contentDigest, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-DIGEST");
            }
            finally { CryptographicOperations.ZeroMemory(canonicalConfig); }
            return config;
        }
        finally
        {
            if (signatureBytes is not null) CryptographicOperations.ZeroMemory(signatureBytes);
            if (canonicalBytes is not null) CryptographicOperations.ZeroMemory(canonicalBytes);
            if (configPublicKey is not null) CryptographicOperations.ZeroMemory(configPublicKey);
            if (ephemeralBytes is not null) CryptographicOperations.ZeroMemory(ephemeralBytes);
            if (saltBytes is not null) CryptographicOperations.ZeroMemory(saltBytes);
            if (ivBytes is not null) CryptographicOperations.ZeroMemory(ivBytes);
            if (tagBytes is not null) CryptographicOperations.ZeroMemory(tagBytes);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (shared is not null) CryptographicOperations.ZeroMemory(shared);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (aadBytes is not null) CryptographicOperations.ZeroMemory(aadBytes);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private string DecryptRecoveryDelivery(JsonObject? envelope, VerifiedConfigKeyState? trustState)
    {
        if (envelope is null) throw new InvalidDataException("BF-RECOVERY-DELIVERY");
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "version", "alg", "key_id", "signing_key_id", "purpose", "aad", "config_version", "expires_at", "ephemeral_public_key", "salt", "iv", "tag", "ciphertext", "signature" };
        if (envelope.Count != allowed.Count || envelope.Any(pair => !allowed.Contains(pair.Key)) || envelope["version"]?.GetValue<int>() != 2 || envelope["alg"]?.GetValue<string>() != "A256GCM" || envelope["key_id"]?.GetValue<string>() != "recovery-delivery-v1" || envelope["purpose"]?.GetValue<string>() != "recovery-delivery")
            throw new InvalidDataException("BF-RECOVERY-DELIVERY");
        var expiresAt = envelope["expires_at"]?.GetValue<long>() ?? 0;
        var configVersion = envelope["config_version"]?.GetValue<long>() ?? 0;
        var signingKeyId = envelope["signing_key_id"]?.GetValue<string>() ?? string.Empty;
        if (expiresAt <= DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() || configVersion <= 0 || !ConfigKeyTrust.KeyIdPattern.IsMatch(signingKeyId)) throw new InvalidDataException("BF-RECOVERY-DELIVERY");
        byte[]? signature = null, canonical = null, trusted = null, ephemeralBytes = null, salt = null, iv = null, tag = null, ciphertext = null, shared = null, key = null, aad = null, plaintext = null;
        try
        {
            signature = DecodeExactCanonical(GetRequiredString(envelope, "signature"), 64, "BF-RECOVERY-DELIVERY");
            var unsigned = new JsonObject(); foreach (var pair in envelope) if (pair.Key != "signature") unsigned[pair.Key] = pair.Value?.DeepClone();
            canonical = StrictUtf8.GetBytes(Canonicalize(unsigned));
            if (trustState is not null)
                trusted = ConfigKeyTrust.RawPublicKey(trustState.Select(signingKeyId, configVersion).PublicKeyPem);
            else
            {
                if (ReleaseContract.TrustRootProvisioned || !string.Equals(signingKeyId, "config-signing-v1", StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-KEY-STATE");
                trusted = ExtractRawEd25519PublicKey(ConfigSigningKeyPem);
            }
            if (!Ed25519.Verify(signature, canonical, trusted)) throw new CryptographicException("BF-RECOVERY-DELIVERY");
            ephemeralBytes = DecodeExactCanonical(GetRequiredString(envelope, "ephemeral_public_key"), 44, "BF-RECOVERY-DELIVERY");
            salt = DecodeExactCanonical(GetRequiredString(envelope, "salt"), 16, "BF-RECOVERY-DELIVERY");
            iv = DecodeExactCanonical(GetRequiredString(envelope, "iv"), 12, "BF-RECOVERY-DELIVERY");
            tag = DecodeExactCanonical(GetRequiredString(envelope, "tag"), 16, "BF-RECOVERY-DELIVERY");
            ciphertext = DecodeBounded(GetRequiredString(envelope, "ciphertext"), MaxConfigPlaintextBytes, "BF-RECOVERY-DELIVERY");
            if (ephemeralBytes.Length != 44 || salt.Length != 16 || iv.Length != 12 || tag.Length != 16 || ciphertext.Length == 0) throw new InvalidDataException("BF-RECOVERY-DELIVERY");
            // Windows 10/.NET does not guarantee an X25519 CNG provider.
            // Package decryption already uses the provider-independent RFC
            // 7748 implementation below; recovery delivery must use the same
            // path or enrollment succeeds only on machines that happen to
            // expose the optional native curve.
            shared = X25519Managed.SharedSecretFromPkcs8(_state.EncryptionPrivatePkcs8!, ephemeralBytes);
            var info = StrictUtf8.GetBytes("bifrost-recovery-delivery-v1");
            try { key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, salt, info); } finally { CryptographicOperations.ZeroMemory(info); }
            aad = StrictUtf8.GetBytes(GetRequiredString(envelope, "aad"));
            plaintext = new byte[ciphertext.Length]; using (var aes = new AesGcm(key, 16)) aes.Decrypt(iv, ciphertext, tag, plaintext, aad);
            var payload = ParseStrictJsonObject(plaintext);
            var payloadKeys = new HashSet<string>(StringComparer.Ordinal) { "delivery_type", "delivery_version", "expires_at", "recovery_code" };
            if (payload.Count != payloadKeys.Count || payload.Any(pair => !payloadKeys.Contains(pair.Key)) || payload["delivery_type"]?.GetValue<string>() != "recovery-code" || payload["delivery_version"]?.GetValue<int>() != 1 || payload["expires_at"]?.GetValue<long>() != expiresAt)
                throw new InvalidDataException("BF-RECOVERY-DELIVERY");
            var code = payload["recovery_code"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(code) || code.Length > 512 || code.Any(char.IsControl)) throw new InvalidDataException("BF-RECOVERY-DELIVERY");
            return code;
        }
        catch (InvalidDataException) { throw; }
        catch { throw new InvalidDataException("BF-RECOVERY-DELIVERY"); }
        finally { foreach (var buffer in new[] { signature, canonical, trusted, ephemeralBytes, salt, iv, tag, ciphertext, shared, key, aad, plaintext }) if (buffer is not null) CryptographicOperations.ZeroMemory(buffer); }
    }

    private void SaveConfig(JsonObject config, long version, string digest, VerifiedConfigKeyState? trustState = null, JsonObject? envelope = null)
    {
        if (!IsSha256Digest(digest)) throw new InvalidDataException("BF-CONFIG-DIGEST");
        var candidate = CloneState(_state);
        candidate.ConfigJson = Canonicalize(config);
        candidate.ConfigVersion = version;
        candidate.ConfigDigest = digest.ToLowerInvariant();
        if (envelope is not null) candidate.ConfigEnvelopeJson = Canonicalize(envelope);
        ApplyConfigKeyState(candidate, trustState);
        SaveState(_stateFile, candidate);
        _state = candidate;
    }

    private static ControlState CloneState(ControlState source) => new()
    {
        ControlUrl = source.ControlUrl,
        PublicId = source.PublicId,
        DeviceId = source.DeviceId,
        RecoveryCode = source.RecoveryCode,
        RecoveryPending = source.RecoveryPending,
        RecoveryDeliveryIdempotency = source.RecoveryDeliveryIdempotency,
        EnrollmentInviteFingerprint = source.EnrollmentInviteFingerprint,
        EnrollmentIdempotency = source.EnrollmentIdempotency,
        SessionToken = source.SessionToken,
        SessionExpiresAtUnixMilliseconds = source.SessionExpiresAtUnixMilliseconds,
        SigningSeed = source.SigningSeed,
        SigningPrivatePkcs8 = source.SigningPrivatePkcs8,
        SigningPublicKey = source.SigningPublicKey,
        EncryptionPrivatePkcs8 = source.EncryptionPrivatePkcs8,
        EncryptionPublicKey = source.EncryptionPublicKey,
        ConfigJson = source.ConfigJson,
        ConfigVersion = source.ConfigVersion,
        ConfigDigest = source.ConfigDigest,
        ConfigEnvelopeJson = source.ConfigEnvelopeJson,
        ConfigKeyStateJson = source.ConfigKeyStateJson,
        ConfigKeyStateGeneration = source.ConfigKeyStateGeneration,
        ConfigKeyStateDigest = source.ConfigKeyStateDigest
    };

    private static bool IsEmptyState(ControlState state) =>
        state.ConfigVersion == 0 &&
        string.IsNullOrEmpty(state.ControlUrl) &&
        string.IsNullOrEmpty(state.PublicId) &&
        string.IsNullOrEmpty(state.DeviceId) &&
        string.IsNullOrEmpty(state.RecoveryCode) &&
        !state.RecoveryPending &&
        string.IsNullOrEmpty(state.RecoveryDeliveryIdempotency) &&
        string.IsNullOrEmpty(state.EnrollmentInviteFingerprint) &&
        string.IsNullOrEmpty(state.EnrollmentIdempotency) &&
        string.IsNullOrEmpty(state.SessionToken) &&
        state.SessionExpiresAtUnixMilliseconds == 0 &&
        string.IsNullOrEmpty(state.SigningSeed) &&
        string.IsNullOrEmpty(state.SigningPrivatePkcs8) &&
        string.IsNullOrEmpty(state.SigningPublicKey) &&
        string.IsNullOrEmpty(state.EncryptionPrivatePkcs8) &&
        string.IsNullOrEmpty(state.EncryptionPublicKey) &&
        string.IsNullOrEmpty(state.ConfigJson) &&
        string.IsNullOrEmpty(state.ConfigDigest) &&
        string.IsNullOrEmpty(state.ConfigEnvelopeJson) &&
        string.IsNullOrEmpty(state.ConfigKeyStateJson) &&
        state.ConfigKeyStateGeneration == 0 &&
        string.IsNullOrEmpty(state.ConfigKeyStateDigest);

    private static void ValidateEd25519PublicKeyMatches(byte[] seed, string encodedPublicKey)
    {
        if (seed.Length != 32 || string.IsNullOrWhiteSpace(encodedPublicKey)) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
        byte[]? stored = null;
        byte[]? storedRaw = null;
        byte[]? derived = null;
        try
        {
            stored = DecodeStateEncoded(encodedPublicKey, 4096, "BF-CONTROL-KEYS-CORRUPT");
            if (stored.Length == 44)
            {
                if (stored[0] != 0x30 || stored[1] != 0x2a || stored[2] != 0x30 || stored[3] != 0x05 ||
                    stored[4] != 0x06 || stored[5] != 0x03 || stored[6] != 0x2b || stored[7] != 0x65 ||
                    stored[8] != 0x70 || stored[9] != 0x03 || stored[10] != 0x21 || stored[11] != 0x00)
                    throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
                storedRaw = stored[12..].ToArray();
            }
            else if (stored.Length == 32)
            {
                storedRaw = stored.ToArray();
            }
            else
            {
                throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
            }

            derived = Ed25519.DerivePublicKey(seed);
            if (!CryptographicOperations.FixedTimeEquals(storedRaw, derived)) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
        }
        finally
        {
            if (stored is not null) CryptographicOperations.ZeroMemory(stored);
            if (storedRaw is not null) CryptographicOperations.ZeroMemory(storedRaw);
            if (derived is not null) CryptographicOperations.ZeroMemory(derived);
        }
    }

    private static void ValidateEncryptionMaterial(ControlState state)
    {
        if (string.IsNullOrWhiteSpace(state.EncryptionPrivatePkcs8) || string.IsNullOrWhiteSpace(state.EncryptionPublicKey))
            throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
        byte[]? privateBytes = null;
        byte[]? derivedPublic = null;
        byte[]? storedPublic = null;
        try
        {
            privateBytes = DecodeStateEncoded(state.EncryptionPrivatePkcs8, 8192, "BF-CONTROL-KEYS-CORRUPT");
            if (privateBytes.Length != 48 || privateBytes[0] != 0x30 || privateBytes[1] != 0x2e || privateBytes[2] != 0x02 || privateBytes[3] != 0x01 || privateBytes[4] != 0x00 || privateBytes[5] != 0x30 || privateBytes[6] != 0x05 || privateBytes[7] != 0x06 || privateBytes[8] != 0x03 || privateBytes[9] != 0x2b || privateBytes[10] != 0x65 || privateBytes[11] != 0x6e || privateBytes[12] != 0x04 || privateBytes[13] != 0x22 || privateBytes[14] != 0x04 || privateBytes[15] != 0x20)
                throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
            derivedPublic = X25519Managed.PublicFromPkcs8(privateBytes);
            storedPublic = DecodeStateEncoded(state.EncryptionPublicKey, 8192, "BF-CONTROL-KEYS-CORRUPT");
            if (!CryptographicOperations.FixedTimeEquals(derivedPublic, storedPublic))
                throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
        }
        finally
        {
            if (privateBytes is not null) CryptographicOperations.ZeroMemory(privateBytes);
            if (derivedPublic is not null) CryptographicOperations.ZeroMemory(derivedPublic);
            if (storedPublic is not null) CryptographicOperations.ZeroMemory(storedPublic);
        }
    }

    private ControlState EnsureKeys(ControlState? state = null, bool persist = true)
    {
        var current = state ?? _state;
        var initial = IsEmptyState(current);
        if (!initial) ValidateState(current, allowLifecycleOrigin: _lifecycleOnly);
        var candidate = CloneState(current);
        if (initial) candidate.DeviceId = Guid.NewGuid().ToString("D");

        // Ed25519 is EdDSA, not ECDSA. Keep a raw 32-byte seed and derive the
        // raw public key with the shared RFC 8032 implementation. A legacy
        // provider-specific PKCS#8 value is accepted only when it is the exact
        // RFC 8410 Ed25519 encoding and derives the advertised public key.
        byte[]? seed = null;
        byte[]? publicRaw = null;
        byte[]? publicSpki = null;
        byte[]? encryptionPrivate = null;
        byte[]? encryptionPublic = null;
        try
        {
            if (initial)
            {
                seed = Ed25519.GenerateSeed();
            }
            else
            {
                seed = !string.IsNullOrWhiteSpace(candidate.SigningSeed)
                    ? TryReadSeed(candidate.SigningSeed)
                    : TryReadLegacyEd25519Seed(candidate.SigningPrivatePkcs8);
                if (seed is null || seed.Length != 32 || string.IsNullOrWhiteSpace(candidate.SigningPublicKey))
                    throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
                ValidateEd25519PublicKeyMatches(seed, candidate.SigningPublicKey);
            }

            publicRaw = Ed25519.DerivePublicKey(seed);
            publicSpki = Ed25519SubjectPublicKeyInfo(publicRaw);
            candidate.SigningSeed = B64(seed);
            candidate.SigningPublicKey = B64(publicSpki);
            candidate.SigningPrivatePkcs8 = null;

            var hasPrivate = !string.IsNullOrWhiteSpace(candidate.EncryptionPrivatePkcs8);
            var hasPublic = !string.IsNullOrWhiteSpace(candidate.EncryptionPublicKey);
            if (hasPrivate != hasPublic) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
            if (hasPrivate)
            {
                ValidateEncryptionMaterial(candidate);
            }
            else
            {
                // X25519 is part of the wire protocol, not an optional host
                // capability.  Generate the RFC 8410 key material ourselves
                // so Windows 10 does not depend on a CNG X25519 provider.
                encryptionPrivate = CreateManagedX25519PrivatePkcs8();
                encryptionPublic = X25519Managed.PublicFromPkcs8(encryptionPrivate);
                candidate.EncryptionPrivatePkcs8 = Convert.ToBase64String(encryptionPrivate);
                candidate.EncryptionPublicKey = B64(encryptionPublic);
            }

            ValidateState(candidate, allowLifecycleOrigin: _lifecycleOnly);
            if (persist)
            {
                SaveState(_stateFile, candidate, allowLifecycleOrigin: _lifecycleOnly);
                _state = candidate;
            }
            return candidate;
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (publicRaw is not null) CryptographicOperations.ZeroMemory(publicRaw);
            if (publicSpki is not null) CryptographicOperations.ZeroMemory(publicSpki);
            if (encryptionPrivate is not null) CryptographicOperations.ZeroMemory(encryptionPrivate);
            if (encryptionPublic is not null) CryptographicOperations.ZeroMemory(encryptionPublic);
        }
    }
    private string Sign(string text)
    {
        byte[]? seed = null;
        byte[]? message = null;
        byte[]? signature = null;
        byte[]? publicRaw = null;
        try
        {
            seed = TryReadSeed(_state.SigningSeed) ?? throw new CryptographicException("BF-DEVICE-SIGNING-KEY");
            message = StrictUtf8.GetBytes(text);
            signature = Ed25519.Sign(message, seed, out publicRaw);
            return B64(signature);
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (message is not null) CryptographicOperations.ZeroMemory(message);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (publicRaw is not null) CryptographicOperations.ZeroMemory(publicRaw);
        }
    }
    private static byte[] CreateManagedX25519PrivatePkcs8()
    {
        var raw = RandomNumberGenerator.GetBytes(32);
        try
        {
            return new byte[] { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20 }
                .Concat(raw).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }
    private static JsonObject SelectSource(JsonObject config, string code)
    {
        if (string.IsNullOrWhiteSpace(code) || string.Equals(code, "auto", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-SOURCE-SELECTION-REQUIRED");
        return config["sources"]?.AsArray().OfType<JsonObject>()
            .FirstOrDefault(n => string.Equals(n["code"]?.GetValue<string>(), code, StringComparison.OrdinalIgnoreCase) && n["configured"]?.GetValue<bool>() == true)
            ?? throw new InvalidDataException("BF-CONFIG-SOURCE");
    }
    private string RequireTrustedOrigin()
    {
        if (_lifecycleOnly)
            return _state.ControlUrl ?? throw new InvalidOperationException("BF-CONTROL-ORIGIN");
        if (_trustedOrigin is null) throw new InvalidOperationException(_configurationStatus);
        return _trustedOrigin.Value;
    }
    private Uri RequireRequestUri(Uri uri, string? expectedOrigin)
    {
        if ((_lifecycleOnly || BifrostBuildConstants.LocalEvaluation) && uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttp && uri.Host is "127.0.0.1" or "localhost" or "::1")
        {
            if (uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.Port is < 1 or > 65535 ||
                !string.Equals(uri.GetLeftPart(UriPartial.Authority), expectedOrigin?.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("BF-CONTROL-ORIGIN");
            return uri;
        }
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.Port != 443 || string.IsNullOrWhiteSpace(uri.Host)) throw new InvalidOperationException("BF-CONTROL-ORIGIN");
        if (!TrustedControlOrigin.TryParse(expectedOrigin ?? string.Empty, out var expected) || expected is null)
            throw new InvalidOperationException("BF-CONTROL-ORIGIN");
        if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), expected.Value, StringComparison.Ordinal)) throw new InvalidOperationException("BF-CONTROL-ORIGIN");
        return uri;
    }
    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    private static byte[]? TryReadSeed(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded) || encoded.Length > 128 || !Regex.IsMatch(encoded, "^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)) return null;
        byte[]? value = null;
        try
        {
            value = Decode(encoded);
            if (value.Length != 32 || !string.Equals(B64(value), encoded, StringComparison.Ordinal)) return null;
            var result = value;
            value = null;
            return result;
        }
        catch { return null; }
        finally
        {
            if (value is not null) CryptographicOperations.ZeroMemory(value);
        }
    }
    private static byte[]? TryReadLegacyEd25519Seed(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded)) return null;
        byte[]? der = null;
        byte[]? seed = null;
        var transferred = false;
        try
        {
            der = DecodeStateEncoded(encoded, 128, "BF-CONTROL-KEYS-CORRUPT");
            if (der.Length != 48 || der[0] != 0x30 || der[1] != 0x2e || der[2] != 0x02 || der[3] != 0x01 || der[4] != 0x00 || der[5] != 0x30 || der[6] != 0x05 || der[7] != 0x06 || der[8] != 0x03 || der[9] != 0x2b || der[10] != 0x65 || der[11] != 0x70 || der[12] != 0x04 || der[13] != 0x22 || der[14] != 0x04 || der[15] != 0x20)
                throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
            seed = der[16..].ToArray();
            transferred = true;
            return seed;
        }
        finally
        {
            if (der is not null) CryptographicOperations.ZeroMemory(der);
            if (!transferred && seed is not null) CryptographicOperations.ZeroMemory(seed);
        }
    }
    private static byte[] DecodeStateEncoded(string value, int maxBytes, string code)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maxBytes * 2 + 32 || value.Any(char.IsWhiteSpace) || value.Any(char.IsControl)) throw new CryptographicException(code);
        var isUrl = Regex.IsMatch(value, "^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant);
        var isStandard = value.Length % 4 == 0 && Regex.IsMatch(value, "^[A-Za-z0-9+/]+={0,2}$", RegexOptions.CultureInvariant);
        if (!isUrl && !isStandard) throw new CryptographicException(code);
        byte[]? decoded = null;
        try
        {
            decoded = Decode(value);
            if (decoded.Length == 0 || decoded.Length > maxBytes || (!string.Equals(B64(decoded), value, StringComparison.Ordinal) && !string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))) throw new CryptographicException(code);
            var result = decoded;
            decoded = null;
            return result;
        }
        catch (CryptographicException) { throw; }
        catch (Exception error) when (error is FormatException or ArgumentException or OverflowException)
        {
            throw new CryptographicException(code);
        }
        finally
        {
            if (decoded is not null) CryptographicOperations.ZeroMemory(decoded);
        }
    }
    private static byte[] Ed25519SubjectPublicKeyInfo(byte[] raw)
    {
        if (raw.Length != 32) throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(raw));
        var der = new byte[44];
        der[0] = 0x30; der[1] = 0x2a; der[2] = 0x30; der[3] = 0x05;
        der[4] = 0x06; der[5] = 0x03; der[6] = 0x2b; der[7] = 0x65; der[8] = 0x70;
        der[9] = 0x03; der[10] = 0x21; der[11] = 0x00;
        Buffer.BlockCopy(raw, 0, der, 12, 32);
        return der;
    }
    private static byte[] ExtractRawEd25519PublicKey(string pem)
    {
        if (!PemEncoding.TryFind(pem.AsSpan(), out var fields)) throw new CryptographicException("BF-CONFIG-PUBLIC-KEY");
        byte[]? der = null;
        byte[]? raw = null;
        var transferred = false;
        try
        {
            der = Convert.FromBase64String(pem[fields.Base64Data].ToString());
            if (der.Length != 44 || der[0] != 0x30 || der[2] != 0x30 || der[4] != 0x06 || der[6] != 0x2b || der[7] != 0x65 || der[8] != 0x70 || der[9] != 0x03)
                throw new CryptographicException("BF-CONFIG-PUBLIC-KEY");
            raw = der[^32..].ToArray();
            transferred = true;
            return raw;
        }
        finally
        {
            if (der is not null) CryptographicOperations.ZeroMemory(der);
            if (!transferred && raw is not null) CryptographicOperations.ZeroMemory(raw);
        }
    }
    private static string Sha256(string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static string PackageDigest(JsonObject envelope) => Sha256(Canonicalize(envelope));
    private static bool IsSha256Digest(string? value) => value is not null && Regex.IsMatch(value, "^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant);
    private static string GetRequiredString(JsonObject objectNode, string property)
    {
        var value = objectNode[property]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("BF-CONFIG-PACKAGE");
        return value;
    }
    private static byte[] DecodeBounded(string value, int maxBytes, string code)
    {
        if (value.Length == 0 || value.Length > maxBytes * 2 + 16 || !Regex.IsMatch(value, "^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)) throw new InvalidDataException(code);
        try
        {
            var decoded = Decode(value);
            var canonical = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (decoded.Length == 0 || decoded.Length > maxBytes || !string.Equals(canonical, value, StringComparison.Ordinal)) { CryptographicOperations.ZeroMemory(decoded); throw new InvalidDataException(code); }
            return decoded;
        }
        catch (InvalidDataException) { throw; }
        catch (Exception error) when (error is FormatException or ArgumentException or OverflowException) { throw new InvalidDataException(code); }
    }
    private static byte[] DecodeExactCanonical(string value, int exactBytes, string code)
    {
        var decoded = DecodeBounded(value, exactBytes, code);
        if (decoded.Length == exactBytes) return decoded;
        CryptographicOperations.ZeroMemory(decoded);
        throw new InvalidDataException(code);
    }
    private static string Canonicalize(JsonNode node) => node switch
    {
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Key, CanonicalJsonOptions) + ":" + (p.Value is null ? "null" : Canonicalize(p.Value)))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(v => v is null ? "null" : Canonicalize(v))) + "]",
        JsonValue value => value.ToJsonString(CanonicalJsonOptions),
        _ => node.ToJsonString(CanonicalJsonOptions)
    };
    private static bool TryMigrateLegacyLocalEvaluationState(string file, TrustedControlOrigin target, out ControlState migrated)
    {
        migrated = new ControlState();
        try
        {
            var legacy = LoadState(file, allowLifecycleOrigin: true, discardLegacyConfigTrust: true);
            if (!string.Equals(legacy.ControlUrl, TrustedControlOrigin.LocalEvaluationOrigin, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(legacy.DeviceId) || string.IsNullOrWhiteSpace(legacy.PublicId) ||
                string.IsNullOrWhiteSpace(legacy.SigningPublicKey) || string.IsNullOrWhiteSpace(legacy.EncryptionPublicKey) ||
                string.Equals(target.Value, TrustedControlOrigin.LocalEvaluationOrigin, StringComparison.Ordinal)) return false;

            var candidate = CloneState(legacy);
            candidate.ControlUrl = target.Value;
            ValidateState(candidate);
            SaveState(file, candidate);
            migrated = candidate;
            return true;
        }
        catch (Exception error) when (error is InvalidDataException or CryptographicException or IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool TryMigrateHistoricalProductionState(
        string file,
        ControlState legacy,
        TrustedControlOrigin target,
        out ControlState migrated)
    {
        migrated = new ControlState();
        try
        {
            // LoadState has already validated the DPAPI payload, key pairs and
            // signed/LKG configuration before this method is reached.  Require
            // a fully enrolled historical production state so a partial or
            // attacker-selected state can never acquire a new authority merely
            // because its URL happens to use the retired hostname.
            if (!string.Equals(legacy.ControlUrl, HistoricalProductionControlOrigin, StringComparison.Ordinal) ||
                !string.Equals(target.Value, CurrentProductionControlOrigin, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(legacy.DeviceId) || string.IsNullOrWhiteSpace(legacy.PublicId) ||
                string.IsNullOrWhiteSpace(legacy.SigningPublicKey) || string.IsNullOrWhiteSpace(legacy.EncryptionPublicKey) ||
                legacy.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(legacy.ConfigJson) || !IsSha256Digest(legacy.ConfigDigest))
                return false;

            var candidate = CloneState(legacy);
            candidate.ControlUrl = target.Value;
            ValidateState(candidate);
            SaveState(file, candidate);
            migrated = candidate;
            return true;
        }
        catch (Exception error) when (error is InvalidDataException or CryptographicException or IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

#if BIFROST_TEST_HARNESS
    internal static bool HistoricalProductionOriginMigrationForTest(string stateFile)
    {
        if (!Path.IsPathFullyQualified(stateFile)) throw new InvalidDataException("BF-TEST-SCOPE");
        var parent = Path.GetDirectoryName(stateFile) ?? throw new InvalidDataException("BF-TEST-SCOPE");
        Directory.CreateDirectory(parent);

        using var seedClient = new BifrostControlClient(screenshotOnly: true) { _lifecycleOnly = true, _stateFile = stateFile };
        var seeded = seedClient.EnsureKeys(new ControlState(), persist: false);
        seeded.ControlUrl = HistoricalProductionControlOrigin;
        seeded.PublicId = "BF-TEST-HISTORICAL-PUBLIC-ID";
        seeded.SessionToken = "TEST-ONLY-historical-session";
        seeded.SessionExpiresAtUnixMilliseconds = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds();
        seeded.ConfigVersion = 7;
        seeded.ConfigDigest = new string('a', 64);
        seeded.ConfigJson = "{\"schema_version\":\"1.0\",\"config_version\":7,\"sources\":[],\"countries\":[],\"routing\":{},\"core_policy\":{}}";
        SaveState(stateFile, seeded);

        var target = TrustedControlOrigin.Compiled ?? throw new InvalidDataException("BF-TEST-SCOPE");
        var originalDevice = seeded.DeviceId;
        var originalSigning = seeded.SigningPublicKey;
        var originalEncryption = seeded.EncryptionPublicKey;
        if (!TryMigrateHistoricalProductionState(stateFile, seeded, target, out var migrated)) return false;
        var reloaded = LoadState(stateFile);
        return string.Equals(reloaded.ControlUrl, CurrentProductionControlOrigin, StringComparison.Ordinal) &&
               string.Equals(reloaded.DeviceId, originalDevice, StringComparison.Ordinal) &&
               string.Equals(reloaded.PublicId, seeded.PublicId, StringComparison.Ordinal) &&
               string.Equals(reloaded.SigningPublicKey, originalSigning, StringComparison.Ordinal) &&
               string.Equals(reloaded.EncryptionPublicKey, originalEncryption, StringComparison.Ordinal) &&
               reloaded.ConfigVersion == seeded.ConfigVersion &&
               string.Equals(migrated.DeviceId, originalDevice, StringComparison.Ordinal);
    }
#endif

    private static ControlState LoadState(string file, bool allowLifecycleOrigin = false, bool discardLegacyConfigTrust = false)
    {
        var parent = Path.GetDirectoryName(file);
        if (string.IsNullOrWhiteSpace(parent)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        RejectReparsePoint(parent, false);
        // The target is checked before opening and again while the same
        // handle is held below.  This is a best-effort reparse-point guard,
        // not an absolute race-free claim.
        RejectReparsePoint(file, true);
        FileStream stream;
        try
        {
            stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.SequentialScan);
        }
        catch (FileNotFoundException)
        {
            return new ControlState();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }

        byte[]? protectedBytes = null;
        byte[]? plaintext = null;
        try
        {
            using (stream)
            {
                RejectReparsePoint(file, false);
                var length = stream.Length;
                if (length <= 0 || length > MaxStateProtectedBytes) throw new InvalidDataException();
                protectedBytes = GC.AllocateUninitializedArray<byte>((int)length);
                var offset = 0;
                while (offset < protectedBytes.Length)
                {
                    var read = stream.Read(protectedBytes, offset, protectedBytes.Length - offset);
                    if (read <= 0) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
                    offset += read;
                }
                if (stream.Length != length || stream.Position != length || stream.ReadByte() != -1) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
                plaintext = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                if (plaintext.Length == 0 || plaintext.Length > MaxStatePlaintextBytes) throw new InvalidDataException();
                var root = ParseStrictJsonObject(plaintext, allowStoredConfig: true);
                ValidateStateJsonProperties(root);
                var state = JsonSerializer.Deserialize<ControlState>(plaintext, StateJsonOptions) ?? throw new InvalidDataException();
                if (discardLegacyConfigTrust)
                {
                    if (!string.Equals(state.ControlUrl, TrustedControlOrigin.LocalEvaluationOrigin, StringComparison.Ordinal)) throw new InvalidDataException();
                    var sanitized = CloneState(state);
                    sanitized.ConfigJson = null;
                    sanitized.ConfigVersion = 0;
                    sanitized.ConfigDigest = null;
                    sanitized.ConfigEnvelopeJson = null;
                    sanitized.ConfigKeyStateJson = null;
                    sanitized.ConfigKeyStateGeneration = 0;
                    sanitized.ConfigKeyStateDigest = null;
                    state = sanitized;
                }
                ValidateState(state, allowLifecycleOrigin);
                return state;
            }
        }
        catch (Exception error) when (error is CryptographicException or JsonException or InvalidDataException or FormatException or InvalidOperationException or ArgumentException or IOException or UnauthorizedAccessException or PlatformNotSupportedException or NotSupportedException or OverflowException)
        {
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static void SaveState(string file, ControlState state, bool allowLifecycleOrigin = false)
    {
        ValidateState(state, allowLifecycleOrigin);
        var parent = Path.GetDirectoryName(file);
        if (string.IsNullOrWhiteSpace(parent)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        RejectReparsePoint(parent, false);
        RejectReparsePoint(file, true);
        byte[]? plaintext = null;
        byte[]? protectedBytes = null;
        var temp = file + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            plaintext = JsonSerializer.SerializeToUtf8Bytes(state, StateJsonOptions);
            if (plaintext.Length == 0 || plaintext.Length > MaxStatePlaintextBytes) throw new InvalidDataException("BF-CONTROL-STATE-LIMIT");
            protectedBytes = ProtectedData.Protect(plaintext, null, DataProtectionScope.CurrentUser);
            if (protectedBytes.Length == 0 || protectedBytes.Length > MaxStateProtectedBytes) throw new InvalidDataException("BF-CONTROL-STATE-LIMIT");
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16 * 1024, FileOptions.WriteThrough))
            {
                RejectReparsePoint(temp, false);
                stream.Write(protectedBytes, 0, protectedBytes.Length);
                stream.Flush(true);
            }
            var targetExists = true;
            try { RejectReparsePoint(file, false); }
            catch (FileNotFoundException) { targetExists = false; }
            if (targetExists) File.Replace(temp, file, null, true);
            else File.Move(temp, file);
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            try
            {
                if (File.Exists(temp))
                {
                    RejectReparsePoint(temp, false);
                    File.Delete(temp);
                }
            }
            catch { }
        }
    }

    private static void RejectReparsePoint(string path, bool allowMissing)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }
        catch (FileNotFoundException) when (allowMissing) { }
        catch (DirectoryNotFoundException) when (allowMissing) { }
    }

    private static void ValidateStateJsonProperties(JsonObject root)
    {
        foreach (var property in root)
            if (!StatePropertyNames.Contains(property.Key)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
    }

    private static void ValidateStateString(string? value, int maxBytes, bool allowControls = false)
    {
        if (value is null || value.Length == 0) return;
        if (value.Length > maxBytes || string.IsNullOrWhiteSpace(value) || (!allowControls && value.Any(char.IsControl))) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        byte[]? bytes = null;
        try
        {
            bytes = StrictUtf8.GetBytes(value);
            if (bytes.Length > maxBytes) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateState(ControlState state, bool allowLifecycleOrigin = false)
    {
        if (IsEmptyState(state)) return;
        ValidateStateString(state.ControlUrl, 2048);
        ValidateStateString(state.PublicId, 256);
        ValidateStateString(state.DeviceId, 36);
        ValidateStateString(state.RecoveryCode, 512);
        ValidateStateString(state.RecoveryDeliveryIdempotency, 512);
        ValidateStateString(state.EnrollmentInviteFingerprint, 64);
        ValidateStateString(state.EnrollmentIdempotency, 512);
        ValidateStateString(state.SessionToken, 4096);
        ValidateStateString(state.SigningSeed, 128);
        ValidateStateString(state.SigningPrivatePkcs8, 8192);
        ValidateStateString(state.SigningPublicKey, 8192);
        ValidateStateString(state.EncryptionPrivatePkcs8, 8192);
        ValidateStateString(state.EncryptionPublicKey, 8192);
        ValidateStateString(state.ConfigJson, MaxConfigPlaintextBytes, true);
        ValidateStateString(state.ConfigDigest, 64);
        ValidateStateString(state.ConfigEnvelopeJson, MaxConfigPlaintextBytes * 2, true);
        ValidateStateString(state.ConfigKeyStateJson, 64 * 1024, true);
        ValidateStateString(state.ConfigKeyStateDigest, 64);
        if (state.ConfigVersion < 0 || state.ConfigKeyStateGeneration < 0 || state.SessionExpiresAtUnixMilliseconds < 0) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (string.IsNullOrEmpty(state.SessionToken) && state.SessionExpiresAtUnixMilliseconds != 0) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        var hasConfigKeyState = !string.IsNullOrEmpty(state.ConfigKeyStateJson) || state.ConfigKeyStateGeneration != 0 || !string.IsNullOrEmpty(state.ConfigKeyStateDigest);
        if (hasConfigKeyState)
        {
            if (string.IsNullOrEmpty(state.ConfigKeyStateJson) || state.ConfigKeyStateGeneration <= 0 || !IsSha256Digest(state.ConfigKeyStateDigest)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            if (!ReleaseContract.TrustRootProvisioned || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootPem) || string.IsNullOrWhiteSpace(ReleaseContract.TrustRootFingerprint)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            byte[]? keyStateBytes = null;
            try
            {
                keyStateBytes = StrictUtf8.GetBytes(state.ConfigKeyStateJson);
                var persistedKeyState = ParseStrictJsonObject(keyStateBytes);
                var verifiedKeyState = ConfigKeyTrust.Verify(persistedKeyState, ReleaseContract.TrustRootKeyId, ReleaseContract.TrustRootPem, ReleaseContract.TrustRootFingerprint, state.ConfigKeyStateGeneration, state.ConfigKeyStateDigest);
                if (verifiedKeyState.Generation != state.ConfigKeyStateGeneration || !string.Equals(verifiedKeyState.Digest, state.ConfigKeyStateDigest, StringComparison.Ordinal) || !string.Equals(verifiedKeyState.CanonicalState, state.ConfigKeyStateJson, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            }
            catch (InvalidDataException) { throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT"); }
            catch { throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT"); }
            finally { if (keyStateBytes is not null) CryptographicOperations.ZeroMemory(keyStateBytes); }
        }
        if (!string.IsNullOrEmpty(state.ControlUrl))
        {
            if (!allowLifecycleOrigin && (!TrustedControlOrigin.TryParse(state.ControlUrl, out var storedOrigin) || storedOrigin is null || !string.Equals(storedOrigin.Value, state.ControlUrl, StringComparison.Ordinal)))
                throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }
        if (string.IsNullOrEmpty(state.DeviceId) || !Guid.TryParseExact(state.DeviceId, "D", out var deviceId) || !string.Equals(state.DeviceId, deviceId.ToString("D"), StringComparison.Ordinal))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (!string.IsNullOrEmpty(state.PublicId) && string.IsNullOrEmpty(state.ControlUrl))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");

        var hasSigningSeed = !string.IsNullOrEmpty(state.SigningSeed);
        var hasLegacySigning = !string.IsNullOrEmpty(state.SigningPrivatePkcs8);
        if (string.IsNullOrEmpty(state.SigningPublicKey) || (!hasSigningSeed && !hasLegacySigning) || string.IsNullOrEmpty(state.EncryptionPrivatePkcs8) || string.IsNullOrEmpty(state.EncryptionPublicKey))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (!string.IsNullOrEmpty(state.RecoveryCode) && string.IsNullOrEmpty(state.PublicId)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (state.RecoveryPending != !string.IsNullOrEmpty(state.RecoveryDeliveryIdempotency)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (string.IsNullOrEmpty(state.EnrollmentInviteFingerprint) != string.IsNullOrEmpty(state.EnrollmentIdempotency) ||
            (!string.IsNullOrEmpty(state.EnrollmentInviteFingerprint) && !IsSha256Digest(state.EnrollmentInviteFingerprint)))
            throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");

        byte[]? signingSeed = null;
        byte[]? legacySeed = null;
        try
        {
            if (hasSigningSeed)
            {
                signingSeed = TryReadSeed(state.SigningSeed);
                if (signingSeed is null) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
                ValidateEd25519PublicKeyMatches(signingSeed, state.SigningPublicKey);
            }
            if (hasLegacySigning)
            {
                legacySeed = TryReadLegacyEd25519Seed(state.SigningPrivatePkcs8);
                if (legacySeed is null) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
                ValidateEd25519PublicKeyMatches(legacySeed, state.SigningPublicKey);
                if (signingSeed is not null && !CryptographicOperations.FixedTimeEquals(signingSeed, legacySeed)) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT");
            }
            ValidateEncryptionMaterial(state);
        }
        finally
        {
            if (signingSeed is not null) CryptographicOperations.ZeroMemory(signingSeed);
            if (legacySeed is not null) CryptographicOperations.ZeroMemory(legacySeed);
        }

        if (!string.IsNullOrEmpty(state.SessionToken) && string.IsNullOrEmpty(state.ControlUrl)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (string.IsNullOrEmpty(state.ConfigJson))
        {
            if (state.ConfigVersion != 0 || !string.IsNullOrEmpty(state.ConfigDigest)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            return;
        }
        var configDigest = state.ConfigDigest;
        if (string.IsNullOrEmpty(state.ControlUrl) || state.ConfigVersion <= 0 || configDigest is null || !IsSha256Digest(configDigest)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        if (!string.Equals(configDigest, configDigest.ToLowerInvariant(), StringComparison.Ordinal)) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        var configBytes = StrictUtf8.GetBytes(state.ConfigJson);
        try
        {
            if (configBytes.Length == 0 || configBytes.Length > MaxConfigPlaintextBytes) throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
            var config = ParseStrictJsonObject(configBytes);
            if (config["schema_version"]?.GetValue<string>() != "1.0" || config["config_version"]?.GetValue<long>() != state.ConfigVersion || config["sources"] is not JsonArray || config["countries"] is not JsonArray || config["routing"] is not JsonObject || config["core_policy"] is not JsonObject)
                throw new InvalidDataException("BF-CONTROL-STATE-CORRUPT");
        }
        finally { CryptographicOperations.ZeroMemory(configBytes); }
    }
    private sealed class LifecycleCoreAdapter : IControlledCoreAdapter
    {
        public bool FailStart { get; init; }
        public int StartCount { get; private set; }
        public int StopCount { get; private set; }
        public bool IsHealthy { get; private set; }
        public bool Start(IControlledPackage package) { StartCount++; IsHealthy = !FailStart; return IsHealthy; }
        public bool Stop() { StopCount++; IsHealthy = false; return true; }
    }

    private sealed class LifecycleNetworkBoundary : IControlledNetworkBoundary
    {
        public bool IsBound { get; private set; }
        public bool EnterFailClosed() { IsBound = true; return true; }
        public bool Activate() => IsBound = true;
        public bool Release() { IsBound = false; return true; }
    }

    private sealed class ControlState { public string? ControlUrl { get; set; } public string? PublicId { get; set; } public string? DeviceId { get; set; } public string? RecoveryCode { get; set; } public bool RecoveryPending { get; set; } public string? RecoveryDeliveryIdempotency { get; set; } public string? EnrollmentInviteFingerprint { get; set; } public string? EnrollmentIdempotency { get; set; } public string? SessionToken { get; set; } public long SessionExpiresAtUnixMilliseconds { get; set; } public string? SigningSeed { get; set; } public string? SigningPrivatePkcs8 { get; set; } public string? SigningPublicKey { get; set; } public string? EncryptionPrivatePkcs8 { get; set; } public string? EncryptionPublicKey { get; set; } public string? ConfigJson { get; set; } public long ConfigVersion { get; set; } public string? ConfigDigest { get; set; } public string? ConfigEnvelopeJson { get; set; } public string? ConfigKeyStateJson { get; set; } public long ConfigKeyStateGeneration { get; set; } public string? ConfigKeyStateDigest { get; set; } }
}

public sealed record ControlResult(bool Ok, string Message, string? PublicId, string? RecoveryCode, long ConfigVersion, string? PairingCode = null);

internal sealed record LifecyclePackageResult(long Version, string Digest, string Content);
internal sealed record LifecycleStateReadback(long Version, string Digest, string Content, string Persistence);

/// <summary>
/// Small, provider-independent RFC 7748 X25519 implementation used when the
/// Windows host does not expose the X25519 CNG curve.  Production package
/// verification and key validation therefore do not silently depend on a
/// machine provider.  Inputs are exact RFC 8410 PKCS#8/SPKI encodings.
/// </summary>
internal static class X25519Managed
{
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = 121665;
    private static readonly byte[] Pkcs8Prefix = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20 };
    private static readonly byte[] SpkiPrefix = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 };

    internal static byte[] PublicFromPkcs8(byte[] pkcs8)
    {
        var scalar = RawPrivate(pkcs8);
        try { return SpkiPrefix.Concat(Ladder(scalar, new byte[] { 9 })).ToArray(); }
        finally { CryptographicOperations.ZeroMemory(scalar); }
    }

    internal static byte[] SharedSecretFromPkcs8(string encodedPkcs8, byte[] spki)
    {
        var pkcs8 = Decode(encodedPkcs8);
        try { return SharedSecretFromPkcs8(pkcs8, spki); }
        finally { CryptographicOperations.ZeroMemory(pkcs8); }
    }

    internal static byte[] SharedSecretFromPkcs8(byte[] pkcs8, byte[] spki)
    {
        var scalar = RawPrivate(pkcs8);
        var u = RawPublic(spki);
        try
        {
            var result = Ladder(scalar, u);
            if (result.All(value => value == 0)) throw new CryptographicException("BF-CONFIG-CRYPTO");
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(scalar); CryptographicOperations.ZeroMemory(u); }
    }

    private static byte[] Decode(string encoded) => Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + new string('=', (4 - encoded.Length % 4) % 4));
    private static byte[] RawPrivate(byte[] value) { if (value.Length != Pkcs8Prefix.Length + 32 || !value.AsSpan(0, Pkcs8Prefix.Length).SequenceEqual(Pkcs8Prefix)) throw new CryptographicException("BF-CONTROL-KEYS-CORRUPT"); return value[^32..].ToArray(); }
    private static byte[] RawPublic(byte[] value) { if (value.Length != SpkiPrefix.Length + 32 || !value.AsSpan(0, SpkiPrefix.Length).SequenceEqual(SpkiPrefix)) throw new CryptographicException("BF-CONFIG-CRYPTO"); return value[^32..].ToArray(); }

    private static byte[] Ladder(byte[] secret, byte[] uBytes)
    {
        var k = secret.ToArray(); k[0] &= 248; k[31] &= 127; k[31] |= 64;
        var x1 = Mod(new BigInteger(uBytes, isUnsigned: true, isBigEndian: false));
        var x2 = BigInteger.One; var z2 = BigInteger.Zero; var x3 = x1; var z3 = BigInteger.One; var swap = 0;
        for (var t = 254; t >= 0; t--)
        {
            var kt = (k[t >> 3] >> (t & 7)) & 1; swap ^= kt;
            if (swap != 0) (x2, x3) = (x3, x2); if (swap != 0) (z2, z3) = (z3, z2); swap = kt;
            var a = Mod(x2 + z2); var aa = Mod(a * a); var b = Mod(x2 - z2); var bb = Mod(b * b); var e = Mod(aa - bb);
            var c = Mod(x3 + z3); var d = Mod(x3 - z3); var da = Mod(d * a); var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb)); z3 = Mod(x1 * (da - cb) * (da - cb)); x2 = Mod(aa * bb); z2 = Mod(e * (aa + A24 * e));
        }
        if (swap != 0) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
        var result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
        CryptographicOperations.ZeroMemory(k);
        return Fixed(result);
    }

    private static BigInteger Mod(BigInteger value) { var result = value % P; return result.Sign < 0 ? result + P : result; }
    private static byte[] Fixed(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false); var output = new byte[32]; Buffer.BlockCopy(bytes, 0, output, 0, Math.Min(bytes.Length, output.Length)); CryptographicOperations.ZeroMemory(bytes); return output;
    }
}

internal sealed record CandidateSelectionResult(JsonObject SelectedCandidate, JsonObject? FrontCandidate);

/// Shared production selection plan. The Mihomo compiler consumes
/// the same validated candidate objects; tests can execute this exact plan
/// with a bounded fake selector to prove that a front candidate is selected
/// once and never re-probed during LocalSystem compilation.
internal static class CandidateSelectionPlan
{
    internal static string SignedSeed(JsonObject source) =>
        source["candidates"]?.AsArray().OfType<JsonObject>().FirstOrDefault()?["label"]?.GetValue<string>()
            ?? throw new InvalidDataException("BF-CANDIDATE-MISSING");
    internal static async Task<CandidateSelectionResult> SelectAsync(
        JsonObject selectedSource,
        JsonObject frontSource,
        string? requestedCandidate,
        Func<JsonObject, string?, CancellationToken, Task<JsonObject>> selector,
        CancellationToken cancellationToken)
    {
        var selected = await selector(selectedSource, requestedCandidate, cancellationToken).ConfigureAwait(false);
        if (ReferenceEquals(selectedSource, frontSource)) return new CandidateSelectionResult(selected, null);
        var front = await selector(frontSource, null, cancellationToken).ConfigureAwait(false);
        return new CandidateSelectionResult(selected, front);
    }
}
