using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Bifrost;

const string Host = "transport.example.test";
const string Sni = "loopback.test";
var rootValidity = CreateFixtureValidityWindow();
var leafValidity = (NotBefore: rootValidity.NotBefore.AddMinutes(1), NotAfter: rootValidity.NotAfter.AddMinutes(-1));
using var root = CreateRootCertificate(rootValidity);
var leafPair = CreateLeafCertificates(root, Sni, leafValidity);
using var certificate = leafPair.Ephemeral;
using var serverCertificate = leafPair.Server;
var descriptor = new ProbeDescriptor(Host, Sni, "/test-uuid-vm", true, "ws");

await RunValidCase(root, serverCertificate, descriptor);
await RunValidCase(root, serverCertificate, descriptor, ResponseKind.RepeatedNonCriticalHeader);
await RunFailureCase(root, serverCertificate, descriptor with { Sni = "wrong-sni.test" }, ResponseKind.Valid, "wrong SNI");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.Valid, "wrong CA", acceptCertificate: false);
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.WrongStatus, "fake 101");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.WrongStatus1010, "1010 status");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.WrongAccept, "wrong accept");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.MissingToken, "missing token");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.DuplicateHeader, "duplicate header");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.ConflictingHeader, "conflicting header");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.Oversized, "oversized headers");
await RunFailureCase(root, serverCertificate, descriptor, ResponseKind.Timeout, "timeout");
await RunCancellationCase(root, serverCertificate, descriptor);
await RunBudgetCase(root, serverCertificate, descriptor);
await RunBootstrapCase(root, serverCertificate, descriptor);
RunNetworkBucketCases();
RunCandidateSelectionPolicyCases();

Console.WriteLine("PASS windows production WSS probe fixture (async/TLS/SNI/WS/budget/bootstrap/network-buckets)");

static async Task RunValidCase(X509Certificate2 root, X509Certificate2 certificate, ProbeDescriptor descriptor, ResponseKind kind = ResponseKind.Valid)
{
    await using var server = await WssFixture.StartAsync(certificate, kind);
    var budget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes);
    var result = await new CandidateProbeEngine().ProbeAsyncForTest("127.0.0.1", server.Port, descriptor, budget, CancellationToken.None,
        (_, cert, _, errors) => ValidateFixtureCertificate(root, certificate, cert, errors));
    Assert(result?.Success == true, "valid TLS 8443-equivalent WSS probe must succeed");
    Assert(server.LastPath == descriptor.Path && server.LastHost == descriptor.Host, "source.ws_path and transport.host must be exact");
    Assert(server.LastNonceLength == 16, "Sec-WebSocket-Key must decode to 16 bytes");
}

static async Task RunFailureCase(X509Certificate2 root, X509Certificate2 certificate, ProbeDescriptor descriptor, ResponseKind kind, string label, bool acceptCertificate = true)
{
    await using var server = await WssFixture.StartAsync(certificate, kind);
    var budget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes);
    var result = await new CandidateProbeEngine().ProbeAsyncForTest("127.0.0.1", server.Port, descriptor, budget, CancellationToken.None,
        (_, cert, _, errors) => acceptCertificate && ValidateFixtureCertificate(root, certificate, cert, errors));
    Assert(result?.Success != true, label + " must be rejected");
}

static async Task RunBudgetCase(X509Certificate2 root, X509Certificate2 certificate, ProbeDescriptor descriptor)
{
    var servers = await WssFixture.StartManyAsync(certificate, ResponseKind.Oversized, 3);
    var cancelled = 0;
    using var round = new CancellationTokenSource();
    var budget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes, () => { Interlocked.Increment(ref cancelled); round.Cancel(); });
    var engine = new CandidateProbeEngine();
    var tasks = servers.Select(server => engine.ProbeAsyncForTest("127.0.0.1", server.Port, descriptor, budget, round.Token, (_, cert, _, errors) =>
        ValidateFixtureCertificate(root, certificate, cert, errors))).ToArray();
    try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }
    Assert(budget.ConsumedBytes <= budget.LimitBytes, "round budget may not overshoot");
    Assert(cancelled > 0 || budget.IsExhausted, "shared budget must cancel remaining probes");
    foreach (var server in servers) await server.DisposeAsync();
}

static async Task RunCancellationCase(X509Certificate2 root, X509Certificate2 certificate, ProbeDescriptor descriptor)
{
    await using var server = await WssFixture.StartAsync(certificate, ResponseKind.Timeout);
    using var cancellation = new CancellationTokenSource(80);
    var task = new CandidateProbeEngine().ProbeAsyncForTest("127.0.0.1", server.Port, descriptor,
        new ProbeBudget(), cancellation.Token, (_, cert, _, errors) => ValidateFixtureCertificate(root, certificate, cert, errors));
    try
    {
        await task;
        throw new InvalidOperationException("ASSERT: caller cancellation must propagate");
    }
    catch (OperationCanceledException) { }
}

static async Task RunBootstrapCase(X509Certificate2 root, X509Certificate2 certificate, ProbeDescriptor descriptor)
{
    await using var server = await WssFixture.StartAsync(certificate, ResponseKind.Valid);
    await using var proxy = await HttpConnectFixture.StartAsync(server.Port);
    var bootstrap = new CandidateProbeEngine.LoopbackBootstrapProxy(CandidateProbeEngine.LoopbackBootstrapProxy.HttpConnect, proxy.Port);
    var budget = new ProbeBudget(CandidateProbeEngine.DefaultRoundBudgetBytes);
    var result = await new CandidateProbeEngine().ProbeAsyncForTest("127.0.0.1", server.Port, descriptor, budget, CancellationToken.None,
        (_, cert, _, errors) => ValidateFixtureCertificate(root, certificate, cert, errors), bootstrap);
    Assert(result?.Success == true, $"loopback HTTP CONNECT bootstrap must carry the strict TLS/WSS probe successfully; proxy_count={proxy.ConnectCount} authority={proxy.LastAuthority} path={server.LastPath} host={server.LastHost} budget={budget.ConsumedBytes}/{budget.LimitBytes} exhausted={budget.IsExhausted}");
    Assert(proxy.ConnectCount > 0 && proxy.LastAuthority == $"127.0.0.1:{server.Port}", "bootstrap must CONNECT only to the selected candidate endpoint");
    Assert(server.LastPath == descriptor.Path && server.LastHost == descriptor.Host, "bootstrap must not alter WSS path or Host authority");

    var forbidden = new CandidateProbeEngine.LoopbackBootstrapProxy(CandidateProbeEngine.LoopbackBootstrapProxy.HttpConnect, 19090);
    var rejected = await new CandidateProbeEngine().ProbeAsyncForTest("127.0.0.1", server.Port, descriptor,
        new ProbeBudget(), CancellationToken.None,
        (_, cert, _, errors) => ValidateFixtureCertificate(root, certificate, cert, errors), forbidden);
    Assert(rejected is null, "service-owned loopback ports must never be accepted as bootstrap proxies");
}

static void RunNetworkBucketCases()
{
    var root = Path.Combine(Path.GetTempPath(), "bifrost-network-bucket-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var material = "profile-a:adapter-a";
        var bucket = new WindowsNetworkBucket(root, () => material);
        var a1 = bucket.GetFingerprint();
        material = "profile-b:adapter-a";
        var b = bucket.GetFingerprint();
        material = "profile-a:adapter-a";
        var a2 = bucket.GetFingerprint();
        Assert(a1 == a2 && a1 != b, "A->B->A must isolate network profile buckets");

        var ambiguousRoot = Path.Combine(root, "ambiguous");
        var ambiguous = new WindowsNetworkBucket(ambiguousRoot, () => null);
        var firstEpoch = ambiguous.GetFingerprint();
        var secondEpoch = new WindowsNetworkBucket(ambiguousRoot, () => null).GetFingerprint();
        Assert(firstEpoch != secondEpoch, "ambiguous network identity must not cross process epochs");

        var corruptRoot = Path.Combine(root, "corrupt");
        Directory.CreateDirectory(corruptRoot);
        File.WriteAllBytes(Path.Combine(corruptRoot, "candidate-probe.salt.bin"), RandomNumberGenerator.GetBytes(7));
        var recovered = new WindowsNetworkBucket(corruptRoot, () => "profile-c");
        Assert(recovered.GetFingerprint().StartsWith("net-", StringComparison.Ordinal), "corrupt salt must be replaced safely");
    }
    finally
    {
        try { Directory.Delete(root, true); } catch { }
    }
}

static void RunCandidateSelectionPolicyCases()
{
    var candidates = Enumerable.Range(1, 10).Select(index => new Candidate("A-" + index.ToString("00"))).ToArray();
    var cohort = CandidateSelectionPolicy.BuildCohort(candidates, 6, 3, "A-01", item => item.Label);
    Assert(cohort.Count == 3 && cohort.Any(item => item.Label == "A-01"), "incumbent must be included in every bounded cohort");
    Assert(CandidateSelectionPolicy.SuccessTimestamp(400, 900, false) == 400, "failed probe must not advance success timestamp");
    Assert(CandidateSelectionPolicy.SuccessTimestamp(400, 900, true) == 900, "successful probe must advance success timestamp");
    var seen = new HashSet<string>();
    for (var start = 0; start < 10; start += 3)
        foreach (var item in CandidateSelectionPolicy.BuildCohort(candidates, start, 3, null, item => item.Label)) seen.Add(item.Label);
    Assert(seen.Count == 10, "cohort rotation must eventually cover all candidates");
}

static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) CreateFixtureValidityWindow()
{
    var now = DateTimeOffset.UtcNow;
    return (now.AddMinutes(-5), now.AddMinutes(20));
}

static X509Certificate2 CreateRootCertificate((DateTimeOffset NotBefore, DateTimeOffset NotAfter) validity)
{
    using var key = RSA.Create(2048);
    var request = new CertificateRequest("CN=Bifrost TEST-only Root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 1, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    return request.CreateSelfSigned(validity.NotBefore, validity.NotAfter);
}

static (X509Certificate2 Ephemeral, X509Certificate2 Server) CreateLeafCertificates(X509Certificate2 root, string dnsName, (DateTimeOffset NotBefore, DateTimeOffset NotAfter) validity)
{
    using var key = RSA.Create(2048);
    var request = new CertificateRequest("CN=" + dnsName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(dnsName); request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    using var generated = request.Create(root, validity.NotBefore, validity.NotAfter, RandomNumberGenerator.GetBytes(16));
    // Keep the verification copy public-only and use the already validated
    // fixture-only UserKeySet import for the SslStream server credential.  This
    // does not install anything in the machine store and is required by the
    // Windows TLS implementation for an ephemeral server key.
    using var withKey = generated.CopyWithPrivateKey(key);
    var expectedLeaf = new X509Certificate2(withKey.Export(X509ContentType.Cert));
    var pfx = withKey.Export(X509ContentType.Pfx);
    var server = new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.UserKeySet);
    return (expectedLeaf, server);
}

static bool ValidateFixtureCertificate(X509Certificate2 root, X509Certificate2 expectedLeaf, X509Certificate? certificate, SslPolicyErrors errors)
{
    if (certificate is null || certificate.GetCertHashString() != expectedLeaf.GetCertHashString()) return false;
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(root);
    chain.ChainPolicy.ExtraStore.Add(root);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    var valid = chain.Build(new X509Certificate2(certificate));
    // With the custom root, the only expected engine policy error is the
    // untrusted local root.  Name mismatch and any other policy error fail.
    return valid && errors == SslPolicyErrors.RemoteCertificateChainErrors;
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException("ASSERT: " + message);
}

enum ResponseKind { Valid, RepeatedNonCriticalHeader, WrongStatus, WrongStatus1010, WrongAccept, MissingToken, DuplicateHeader, ConflictingHeader, Oversized, Timeout }

sealed record Candidate(string Label);

sealed class HttpConnectFixture : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly int _allowedTargetPort;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly ConcurrentBag<Task> _handlers = new();
    public int Port { get; }
    public int ConnectCount { get; private set; }
    public string? LastAuthority { get; private set; }

    private HttpConnectFixture(TcpListener listener, int allowedTargetPort)
    {
        _listener = listener;
        _allowedTargetPort = allowedTargetPort;
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _acceptLoop = AcceptLoopAsync();
    }

    public static async Task<HttpConnectFixture> StartAsync(int allowedTargetPort)
    {
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var port = RandomNumberGenerator.GetInt32(10000, 18999);
            var listener = new TcpListener(IPAddress.Loopback, port);
            try
            {
                listener.Start();
                await Task.Yield();
                return new HttpConnectFixture(listener, allowedTargetPort);
            }
            catch (SocketException)
            {
                listener.Stop();
            }
        }
        throw new InvalidOperationException("TEST-only HTTP CONNECT fixture could not allocate a safe non-Bifrost loopback port");
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_stop.Token); } catch { break; }
            _handlers.Add(HandleAsync(client));
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var clientStream = client.GetStream();
                var request = await ReadHeadersAsync(clientStream, 4096, _stop.Token);
                var first = Encoding.ASCII.GetString(request).Split("\r\n", StringSplitOptions.None)[0];
                var parts = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" || parts[1] != $"127.0.0.1:{_allowedTargetPort}")
                {
                    await clientStream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"), _stop.Token);
                    return;
                }
                LastAuthority = parts[1];
                ConnectCount++;
                using var upstream = new TcpClient(AddressFamily.InterNetwork);
                await upstream.ConnectAsync(IPAddress.Loopback, _allowedTargetPort, _stop.Token);
                var upstreamStream = upstream.GetStream();
                await clientStream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), _stop.Token);
                await clientStream.FlushAsync(_stop.Token);
                var up = clientStream.CopyToAsync(upstreamStream, _stop.Token);
                var down = upstreamStream.CopyToAsync(clientStream, _stop.Token);
                await Task.WhenAll(up, down);
            }
            catch { /* TEST-only tunnel closes when either side finishes. */ }
        }
    }

    private static async Task<byte[]> ReadHeadersAsync(Stream stream, int limit, CancellationToken token)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[512];
        while (memory.Length < limit)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, limit - (int)memory.Length)), token);
            if (read <= 0) break;
            memory.Write(buffer, 0, read);
            var text = Encoding.ASCII.GetString(memory.GetBuffer(), 0, (int)memory.Length);
            if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
        }
        return memory.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        try { await _acceptLoop; } catch { }
        try { await Task.WhenAll(_handlers.ToArray()); } catch { }
        _stop.Dispose();
    }
}

sealed class WssFixture : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _certificate;
    private readonly ResponseKind _kind;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly ConcurrentBag<Task> _handlers = new();
    public int Port { get; }
    public string? LastPath { get; private set; }
    public string? LastHost { get; private set; }
    public int LastNonceLength { get; private set; }

    private WssFixture(TcpListener listener, X509Certificate2 certificate, ResponseKind kind)
    {
        _listener = listener; _certificate = certificate; _kind = kind;
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _acceptLoop = AcceptLoopAsync();
    }

    public static async Task<WssFixture> StartAsync(X509Certificate2 certificate, ResponseKind kind)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        await Task.Yield();
        return new WssFixture(listener, certificate, kind);
    }

    public static async Task<IReadOnlyList<WssFixture>> StartManyAsync(X509Certificate2 certificate, ResponseKind kind, int count)
    {
        var result = new List<WssFixture>();
        for (var i = 0; i < count; i++) result.Add(await StartAsync(certificate, kind));
        return result;
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_stop.Token); } catch { break; }
            _handlers.Add(HandleAsync(client));
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var ssl = new SslStream(client.GetStream(), false))
        {
            try
            {
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 }, _stop.Token);
                if (_kind == ResponseKind.Timeout) { await Task.Delay(2_000, _stop.Token); return; }
                var request = await ReadHeadersAsync(ssl, 16 * 1024, _stop.Token);
                var text = Encoding.ASCII.GetString(request);
                LastPath = text.Split("\r\n", StringSplitOptions.None).FirstOrDefault()?.Split(' ').ElementAtOrDefault(1);
                LastHost = text.Split("\r\n", StringSplitOptions.None).FirstOrDefault(line => line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))?.Split(':', 2).ElementAtOrDefault(1)?.Trim();
                var keyLine = text.Split("\r\n", StringSplitOptions.None).FirstOrDefault(line => line.StartsWith("Sec-WebSocket-Key:", StringComparison.OrdinalIgnoreCase));
                if (keyLine is not null) LastNonceLength = Convert.FromBase64String(keyLine.Split(':', 2)[1].Trim()).Length;
                var key = keyLine?.Split(':', 2).ElementAtOrDefault(1)?.Trim() ?? string.Empty;
                var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
                var response = _kind switch
                {
                    ResponseKind.WrongStatus => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                    ResponseKind.WrongStatus1010 => "HTTP/1.1 1010 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n",
                    ResponseKind.WrongAccept => "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bad\r\n\r\n",
                    ResponseKind.MissingToken => $"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}\r\n\r\n",
                    ResponseKind.RepeatedNonCriticalHeader => $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nReport-To: first\r\nReport-To: second\r\n\r\n",
                    ResponseKind.DuplicateHeader => $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n",
                    ResponseKind.ConflictingHeader => $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: close\r\nSec-WebSocket-Accept: {accept}\r\n\r\n",
                    ResponseKind.Oversized => "HTTP/1.1 101 Switching Protocols\r\n" + new string('X', 8 * 1024) + ": y\r\n\r\n",
                    _ => $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                };
                await ssl.WriteAsync(Encoding.ASCII.GetBytes(response), _stop.Token); await ssl.FlushAsync(_stop.Token);
            }
            catch { /* Negative TEST-only cases intentionally close the fixture connection. */ }
        }
    }

    private static async Task<byte[]> ReadHeadersAsync(Stream stream, int limit, CancellationToken token)
    {
        using var memory = new MemoryStream(); var buffer = new byte[1024];
        while (memory.Length < limit)
        {
            var read = await stream.ReadAsync(buffer, token); if (read == 0) break;
            memory.Write(buffer, 0, read);
            if (memory.Length >= 4 && Encoding.ASCII.GetString(memory.GetBuffer(), 0, (int)memory.Length).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
        }
        return memory.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel(); _listener.Stop();
        try { await _acceptLoop; } catch { }
        try { await Task.WhenAll(_handlers.ToArray()); } catch { }
        _stop.Dispose();
    }
}
