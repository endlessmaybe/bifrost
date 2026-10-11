using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Text;
using System.Runtime.InteropServices;

namespace Bifrost;

/// <summary>
/// The production candidate probe.  It deliberately owns no application
/// payload path: it only performs a bounded TCP/TLS/WebSocket handshake.
/// The certificate callback is strict by default and is injectable only by
/// the TEST-ONLY fixture so a local CA never changes production trust.
/// </summary>
public sealed class CandidateProbeEngine
{
    private const int IpProtoIp = 0;
    private const int IpProtoIpv6 = 41;
    private const int IpUnicastIf = 31;

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int setsockopt(IntPtr socket, int level, int optionName, ref int optionValue, int optionLength);

    public const int DefaultRoundBudgetBytes = 12 * 1024;
    public const int MaxHeaderBytes = 4 * 1024;
    public const int AttemptCount = 2;
    // Keep the probe bounded, but leave enough headroom for a cold TLS
    // handshake when the isolated fixture runs beside the other local gates.
    // A cold Schannel + Cloudflare WSS handshake can legitimately cross the
    // old 1.5s ceiling even on a healthy physical underlay. Keep each attempt
    // tightly bounded, but allow enough room for a real first-use TLS path.
    public const int TimeoutMilliseconds = 3000;
    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public sealed record LoopbackBootstrapProxy(string Type, int Port)
    {
        public const string HttpConnect = "http-connect";
        public const string Socks5 = "socks5";

        public bool IsValid =>
            Type is HttpConnect or Socks5 && Port is >= 1 and <= 65535 &&
            !IsBifrostOwnedLoopbackPort(Port);

        private static bool IsBifrostOwnedLoopbackPort(int port) =>
            port is >= 19000 and <= 49151;
    }

    public Task<ProbeResult?> ProbeAsync(
        string dialAddress,
        int port,
        ProbeDescriptor descriptor,
        ProbeBudget budget,
        CancellationToken cancellationToken,
        LoopbackBootstrapProxy? bootstrapProxy = null) =>
        ProbeAsyncCore(dialAddress, port, descriptor, budget, cancellationToken, null, null, bootstrapProxy);

    internal async Task<ProbeDiagnosticResult> ProbeAsyncForDiagnostics(
        string dialAddress,
        int port,
        ProbeDescriptor descriptor,
        ProbeBudget budget,
        CancellationToken cancellationToken)
    {
        var events = new List<string>();
        var result = await ProbeAsyncCore(dialAddress, port, descriptor, budget, cancellationToken, null, events.Add, null).ConfigureAwait(false);
        return new ProbeDiagnosticResult(result, events);
    }

    // Linked into the TEST-only loopback fixture, never exposed by the
    // production client.  System certificate validation remains mandatory
    // for the public path.
    internal Task<ProbeResult?> ProbeAsyncForTest(
        string dialAddress,
        int port,
        ProbeDescriptor descriptor,
        ProbeBudget budget,
        CancellationToken cancellationToken,
        RemoteCertificateValidationCallback certificateValidation,
        LoopbackBootstrapProxy? bootstrapProxy = null) =>
        ProbeAsyncCore(dialAddress, port, descriptor, budget, cancellationToken, certificateValidation, null, bootstrapProxy);

    private async Task<ProbeResult?> ProbeAsyncCore(
        string dialAddress,
        int port,
        ProbeDescriptor descriptor,
        ProbeBudget budget,
        CancellationToken cancellationToken,
        RemoteCertificateValidationCallback? certificateValidation,
        Action<string>? diagnostic,
        LoopbackBootstrapProxy? bootstrapProxy)
    {
        if (!IsPermittedDialAddress(dialAddress, certificateValidation is not null) || port is < 1 or > 65535 || !descriptor.Tls ||
            !IPAddress.TryParse(dialAddress, out var dialIp))
            return null;
        if (bootstrapProxy is not null && !bootstrapProxy.IsValid)
            return null;
        ValidateDescriptor(descriptor);
        // TEST-ONLY loopback fixtures intentionally run on the local host and
        // must not be forced onto a physical NIC. Production probes never get
        // an injected certificate callback and therefore always use the real
        // underlay resolver below.
        var underlay = certificateValidation is null && bootstrapProxy is null ? ResolveProbeUnderlay() : default;
        diagnostic?.Invoke($"underlay required={underlay.Required} ipv4={underlay.Ipv4Index} ipv6={underlay.Ipv6Index}");
        if (underlay.Required && !underlay.Supports(dialIp.AddressFamily))
            return new ProbeResult(false, 9_999, 9_999, 100, false, 0);
        var samples = new List<double>();
        var failures = 0;
        var verifiedHandshake = false;
        var bytes = 0;
        for (var attempt = 0; attempt < AttemptCount; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stage = "connect";
            try
            {
                using var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                attemptTimeout.CancelAfter(TimeoutMilliseconds);
                var token = attemptTimeout.Token;
                using var tcp = bootstrapProxy is null
                    ? new TcpClient(dialIp.AddressFamily)
                    : new TcpClient(AddressFamily.InterNetwork);
                if (bootstrapProxy is null)
                    ApplyProbeUnderlay(tcp.Client, dialIp.AddressFamily, underlay);
                var started = Stopwatch.GetTimestamp();
                if (bootstrapProxy is null)
                {
                    await tcp.ConnectAsync(dialIp, port, token).ConfigureAwait(false);
                }
                else
                {
                    await tcp.ConnectAsync(IPAddress.Loopback, bootstrapProxy.Port, token).ConfigureAwait(false);
                }
                // Meter the underlying socket, not just the HTTP headers. This
                // makes the round budget cover TLS handshake bytes as well as
                // the WebSocket request/response and is shared by all probes.
                Stream stream = new ProbeBudgetStream(tcp.GetStream(), budget);
                if (bootstrapProxy is not null)
                {
                    stage = "bootstrap";
                    if (bootstrapProxy.Type == LoopbackBootstrapProxy.Socks5)
                        await EstablishSocks5TunnelAsync(stream, dialAddress, port, token).ConfigureAwait(false);
                    else
                        await EstablishHttpConnectTunnelAsync(stream, dialAddress, port, token).ConfigureAwait(false);
                }
                SslStream? ssl = null;
                if (descriptor.Tls)
                {
                    stage = "tls";
                    ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = descriptor.Sni,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        RemoteCertificateValidationCallback = certificateValidation ?? StrictCertificateValidation,
                    }, token).ConfigureAwait(false);
                    stream = ssl;
                }
                using (ssl)
                {
                    if (descriptor.IsWebSocket)
                    {
                        stage = "websocket";
                        bytes += await WebSocketProbeAsync(stream, descriptor, token).ConfigureAwait(false);
                    }
                }
                samples.Add(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
                verifiedHandshake = true;
                diagnostic?.Invoke($"attempt={attempt + 1} stage=complete elapsed_ms={samples[^1]:F1} consumed={budget.ConsumedBytes}");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && budget.IsExhausted)
            {
                diagnostic?.Invoke($"attempt={attempt + 1} stage={stage} error=budget-timeout consumed={budget.ConsumedBytes}");
                failures++;
                break;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                diagnostic?.Invoke($"attempt={attempt + 1} stage={stage} error=timeout consumed={budget.ConsumedBytes}");
                failures++;
            }
            catch (OperationCanceledException)
            {
                // Caller/network-generation cancellation must propagate so
                // the coordinator can discard the round and close sockets.
                throw;
            }
            catch (Exception error)
            {
                diagnostic?.Invoke($"attempt={attempt + 1} stage={stage} error={error.GetType().Name}:{error.Message} consumed={budget.ConsumedBytes}");
                failures++;
            }
        }

        if (samples.Count == 0)
            return new ProbeResult(false, 9_999, 9_999, 100, false, bytes);
        var rtt = samples.Average();
        var jitter = samples.Count < 2 ? 0 : Math.Abs(samples[1] - samples[0]);
        var loss = failures * 100d / AttemptCount;
        // One complete strict TLS + WSS handshake proves reachability. A
        // second failed sample is represented as packet/attempt loss and is
        // penalized by the selector rather than erasing valid evidence.
        return new ProbeResult(verifiedHandshake, rtt, jitter, loss, verifiedHandshake, bytes);
    }

    private static async Task EstablishHttpConnectTunnelAsync(
        Stream network,
        string dialAddress,
        int port,
        CancellationToken cancellationToken)
    {
        var authority = dialAddress.Contains(':', StringComparison.Ordinal) ? $"[{dialAddress}]:{port}" : $"{dialAddress}:{port}";
        var request = Encoding.ASCII.GetBytes(
            $"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n");
        await network.WriteAsync(request.AsMemory(), cancellationToken).ConfigureAwait(false);
        await network.FlushAsync(cancellationToken).ConfigureAwait(false);

        using var response = new MemoryStream();
        var buffer = new byte[256];
        while (response.Length < MaxHeaderBytes)
        {
            var wanted = (int)Math.Min(buffer.Length, MaxHeaderBytes - response.Length);
            var read = await network.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
            if (read <= 0) break;
            response.Write(buffer, 0, read);
            var text = Encoding.ASCII.GetString(response.GetBuffer(), 0, checked((int)response.Length));
            if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
        }
        if (response.Length == 0 || response.Length >= MaxHeaderBytes)
            throw new IOException("BF-PROBE-BOOTSTRAP");
        var header = Encoding.ASCII.GetString(response.GetBuffer(), 0, checked((int)response.Length));
        var firstLineEnd = header.IndexOf("\r\n", StringComparison.Ordinal);
        var firstLine = firstLineEnd >= 0 ? header[..firstLineEnd] : header;
        if (!firstLine.StartsWith("HTTP/1.", StringComparison.Ordinal) || !firstLine.Contains(" 200 ", StringComparison.Ordinal))
            throw new IOException("BF-PROBE-BOOTSTRAP");
    }

    private static async Task EstablishSocks5TunnelAsync(
        Stream network,
        string dialAddress,
        int port,
        CancellationToken cancellationToken)
    {
        await network.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);
        await network.FlushAsync(cancellationToken).ConfigureAwait(false);
        var greeting = new byte[2];
        await ReadExactAsync(network, greeting, cancellationToken).ConfigureAwait(false);
        if (greeting[0] != 0x05 || greeting[1] != 0x00) throw new IOException("BF-PROBE-BOOTSTRAP");

        using var request = new MemoryStream();
        request.WriteByte(0x05); // version
        request.WriteByte(0x01); // CONNECT
        request.WriteByte(0x00); // reserved
        if (IPAddress.TryParse(dialAddress, out var address))
        {
            var bytes = address.GetAddressBytes();
            request.WriteByte(address.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04);
            request.Write(bytes, 0, bytes.Length);
        }
        else
        {
            var host = Encoding.ASCII.GetBytes(dialAddress);
            if (host.Length is < 1 or > 255) throw new IOException("BF-PROBE-BOOTSTRAP");
            request.WriteByte(0x03);
            request.WriteByte(checked((byte)host.Length));
            request.Write(host, 0, host.Length);
        }
        request.WriteByte(checked((byte)(port >> 8)));
        request.WriteByte(checked((byte)(port & 0xff)));
        await network.WriteAsync(request.GetBuffer().AsMemory(0, checked((int)request.Length)), cancellationToken).ConfigureAwait(false);
        await network.FlushAsync(cancellationToken).ConfigureAwait(false);

        var head = new byte[4];
        await ReadExactAsync(network, head, cancellationToken).ConfigureAwait(false);
        if (head[0] != 0x05 || head[1] != 0x00 || head[2] != 0x00) throw new IOException("BF-PROBE-BOOTSTRAP");
        var addressLength = head[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadSocksDomainLengthAsync(network, cancellationToken).ConfigureAwait(false),
            _ => throw new IOException("BF-PROBE-BOOTSTRAP"),
        };
        var tail = new byte[addressLength + 2];
        await ReadExactAsync(network, tail, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ReadSocksDomainLengthAsync(Stream network, CancellationToken cancellationToken)
    {
        var length = new byte[1];
        await ReadExactAsync(network, length, cancellationToken).ConfigureAwait(false);
        if (length[0] == 0) throw new IOException("BF-PROBE-BOOTSTRAP");
        return length[0];
    }

    private static async Task ReadExactAsync(Stream network, Memory<byte> target, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < target.Length)
        {
            var read = await network.ReadAsync(target[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0) throw new IOException("BF-PROBE-BOOTSTRAP");
            offset += read;
        }
    }

    private static bool StrictCertificateValidation(
        object _, System.Security.Cryptography.X509Certificates.X509Certificate? certificate,
        System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors errors) =>
        certificate is not null && errors == SslPolicyErrors.None;

    private readonly record struct ProbeUnderlay(bool Required, int Ipv4Index, int Ipv6Index)
    {
        public bool Supports(AddressFamily family) => family switch
        {
            AddressFamily.InterNetwork => Ipv4Index > 0,
            AddressFamily.InterNetworkV6 => Ipv6Index > 0,
            _ => false,
        };
    }

    /// <summary>
    /// Candidate selection and the eventual Bifrost core must observe the
    /// same underlay.  When another full-tunnel currently owns the Windows
    /// default route, probing through that tunnel would select candidates that
    /// may be unreachable once Bifrost intentionally bypasses it.  Resolve one
    /// routed physical adapter and force every candidate socket onto it.
    /// </summary>
    private static ProbeUnderlay ResolveProbeUnderlay()
    {
        if (!OperatingSystem.IsWindows()) return default;
        try
        {
            using var routeProbe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            routeProbe.Connect(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53));
            if (routeProbe.LocalEndPoint is not IPEndPoint local) return default;
            var active = NetworkInterface.GetAllNetworkInterfaces();
            var defaultInterface = active.FirstOrDefault(item =>
                item.OperationalStatus == OperationalStatus.Up &&
                item.GetIPProperties().UnicastAddresses.Any(address => address.Address.Equals(local.Address)));
            if (defaultInterface is null || !LooksLikeTunnel(defaultInterface)) return default;

            var physical = active.Where(item =>
                    item.OperationalStatus == OperationalStatus.Up &&
                    item.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) &&
                    !LooksLikeTunnel(item))
                .Where(item =>
                {
                    var properties = item.GetIPProperties();
                    return properties.GatewayAddresses.Any(gateway =>
                               gateway.Address.AddressFamily == AddressFamily.InterNetwork &&
                               !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.None)) &&
                           properties.UnicastAddresses.Any(address =>
                               address.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address.Address));
                })
                .ToArray();
            if (physical.Length != 1) return new ProbeUnderlay(true, 0, 0);
            var properties = physical[0].GetIPProperties();
            var ipv4 = properties.GetIPv4Properties()?.Index ?? 0;
            var ipv6 = properties.GetIPv6Properties()?.Index ?? 0;
            return new ProbeUnderlay(true, ipv4, ipv6);
        }
        catch
        {
            // Once a competing tunnel was observed ambiguously, never fall
            // back to probing through it.  The caller treats Required=true
            // with no usable index as a failed candidate round.
            try
            {
                var tunnelExists = NetworkInterface.GetAllNetworkInterfaces().Any(item =>
                    item.OperationalStatus == OperationalStatus.Up && LooksLikeTunnel(item));
                return tunnelExists ? new ProbeUnderlay(true, 0, 0) : default;
            }
            catch { return new ProbeUnderlay(true, 0, 0); }
        }
    }

    internal static bool DefaultPathUsesTunnel()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var routeProbe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            routeProbe.Connect(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53));
            if (routeProbe.LocalEndPoint is not IPEndPoint local) return false;
            var defaultInterface = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(item =>
                item.OperationalStatus == OperationalStatus.Up &&
                item.GetIPProperties().UnicastAddresses.Any(address => address.Address.Equals(local.Address)));
            return defaultInterface is not null && LooksLikeTunnel(defaultInterface);
        }
        catch
        {
            // Detection failure is not authority to invent a bootstrap path.
            // ResolveProbeUnderlay independently remains fail-closed for the
            // direct socket binding decision.
            return false;
        }
    }

    private static void ApplyProbeUnderlay(Socket socket, AddressFamily family, ProbeUnderlay underlay)
    {
        if (!underlay.Required) return;
        if (family == AddressFamily.InterNetwork)
        {
            if (underlay.Ipv4Index <= 0) throw new SocketException((int)SocketError.NetworkUnreachable);
            var networkIndex = IPAddress.HostToNetworkOrder(underlay.Ipv4Index);
            if (setsockopt(socket.Handle, IpProtoIp, IpUnicastIf, ref networkIndex, sizeof(int)) != 0)
                throw new SocketException(Marshal.GetLastWin32Error());
            return;
        }
        if (family == AddressFamily.InterNetworkV6)
        {
            if (underlay.Ipv6Index <= 0) throw new SocketException((int)SocketError.NetworkUnreachable);
            var hostIndex = underlay.Ipv6Index;
            if (setsockopt(socket.Handle, IpProtoIpv6, IpUnicastIf, ref hostIndex, sizeof(int)) != 0)
                throw new SocketException(Marshal.GetLastWin32Error());
            return;
        }
        throw new SocketException((int)SocketError.AddressFamilyNotSupported);
    }

    private static bool LooksLikeTunnel(NetworkInterface item)
    {
        if (item.NetworkInterfaceType == NetworkInterfaceType.Tunnel) return true;
        var label = $"{item.Name} {item.Description}".ToLowerInvariant();
        return new[] { " tunnel", "tun", "tap", "wintun", "wireguard", "tailscale", "zerotier", " vpn" }
            .Any(marker => label.Contains(marker, StringComparison.Ordinal));
    }

    private static void ValidateDescriptor(ProbeDescriptor descriptor)
    {
        static bool HasControl(string value) => value.Any(ch => ch == '\0' || char.IsControl(ch));
        if (string.IsNullOrWhiteSpace(descriptor.Host) || string.IsNullOrWhiteSpace(descriptor.Sni) ||
            HasControl(descriptor.Host) || HasControl(descriptor.Sni) || descriptor.Host.Length > 255 || descriptor.Sni.Length > 255 ||
            string.IsNullOrWhiteSpace(descriptor.Path) || descriptor.Path.Length > 2048 || descriptor.Path[0] != '/' ||
            descriptor.Path.Contains("\r", StringComparison.Ordinal) || descriptor.Path.Contains("\n", StringComparison.Ordinal) ||
            descriptor.Path.Contains('\0') || !descriptor.IsWebSocket)
            throw new InvalidDataException("BF-PROBE-DESCRIPTOR");
    }

    private static bool IsPermittedDialAddress(string value, bool testOnly)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        if (testOnly && IPAddress.IsLoopback(address)) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            var first = b[0];
            if (first == 0 || first == 10 || first >= 224 || first == 127 || (first == 169 && b[1] == 254) ||
                (first == 100 && b[1] is >= 64 and <= 127) || (first == 172 && b[1] is >= 16 and <= 31) ||
                (first == 192 && (b[1] == 168 || (b[1] == 0 && b[2] == 0) || (b[1] == 0 && b[2] == 2) || (b[1] == 88 && b[2] == 99))) ||
                (first == 198 && (b[1] is 18 or 19 || b[1] == 51)) ||
                (first == 203 && b[1] == 0 && b[2] == 113)) return false;
            return !(b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255);
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || address.IsIPv4MappedToIPv6)
            return false;
        var v6 = address.GetAddressBytes();
        var first16 = (v6[0] << 8) | v6[1];
        if ((first16 & 0xE000) != 0x2000) return false; // only 2000::/3 global unicast space
        if (first16 == 0x2001 && v6[2] < 0x02 || // 2001::/23 protocol/special assignments
            (first16 & 0xFF00) == 0x2002 || // 6to4
            (first16 & 0xFFF0) == 0x3FF0 || // documentation 3fff::/20
            (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8) || // RFC 3849
            (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x02) || // benchmark
            (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x10)) return false;
        return !address.Equals(IPAddress.IPv6None) && !address.Equals(IPAddress.IPv6Loopback);
    }

    private static async Task<int> WebSocketProbeAsync(
        Stream stream, ProbeDescriptor descriptor, CancellationToken cancellationToken)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var request = Encoding.ASCII.GetBytes(
            $"GET {descriptor.Path} HTTP/1.1\r\nHost: {descriptor.Host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n");
        await stream.WriteAsync(request.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        using var response = new MemoryStream();
        var buffer = new byte[512];
        while (response.Length < MaxHeaderBytes)
        {
            var requested = (int)Math.Min(buffer.Length, MaxHeaderBytes - response.Length);
            var read = await stream.ReadAsync(buffer.AsMemory(0, requested), cancellationToken).ConfigureAwait(false);
            if (read <= 0) break;
            response.Write(buffer, 0, read);
            if (response.Length >= 4)
            {
                var text = Encoding.ASCII.GetString(response.GetBuffer(), 0, checked((int)response.Length));
                if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
            }
        }

        if (response.Length == 0 || response.Length > MaxHeaderBytes)
            throw new InvalidDataException("BF-PROBE-WS-HEADERS");
        var headers = Encoding.ASCII.GetString(response.GetBuffer(), 0, checked((int)response.Length));
        var headerEnd = headers.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0) throw new InvalidDataException("BF-PROBE-WS-HEADERS");
        var lines = headers[..headerEnd].Split("\r\n", StringSplitOptions.None);
        var statusParts = lines.Length == 0 ? Array.Empty<string>() : lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !string.Equals(statusParts[0], "HTTP/1.1", StringComparison.Ordinal) || !string.Equals(statusParts[1], "101", StringComparison.Ordinal))
            throw new InvalidDataException("BF-PROBE-WS-STATUS");
        var parsed = ParseHeaders(lines);
        if (!parsed.TryGetValue("Upgrade", out var upgrade)) throw new InvalidDataException("BF-PROBE-WS-UPGRADE");
        var upgradeTokens = upgrade.SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray();
        // A 101 response selects WebSocket as the upgraded protocol. Duplicate
        // non-critical headers are legal HTTP; a conflicting Upgrade protocol
        // is not accepted as equivalent evidence.
        if (upgradeTokens.Length == 0 || upgradeTokens.Any(value => !value.Equals("websocket", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("BF-PROBE-WS-UPGRADE");
        if (!parsed.TryGetValue("Connection", out var connection)) throw new InvalidDataException("BF-PROBE-WS-CONNECTION");
        var connectionTokens = connection.SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray();
        if (!connectionTokens.Any(value => value.Equals("upgrade", StringComparison.OrdinalIgnoreCase)) ||
            connectionTokens.Any(value => value.Equals("close", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("BF-PROBE-WS-CONNECTION");
        var accept = parsed.TryGetValue("Sec-WebSocket-Accept", out var acceptValues) && acceptValues.Count == 1 ? acceptValues[0] : null;
        var expected = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + WebSocketGuid)));
        if (string.IsNullOrWhiteSpace(accept) || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(accept), Encoding.ASCII.GetBytes(expected)))
            throw new InvalidDataException("BF-PROBE-WS-ACCEPT");
        return checked(request.Length + (int)response.Length);
    }

    private static Dictionary<string, List<string>> ParseHeaders(IEnumerable<string> lines)
    {
        var parsed = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) throw new InvalidDataException("BF-PROBE-WS-HEADER");
            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (value.Length == 0) throw new InvalidDataException("BF-PROBE-WS-HEADER");
            if (!parsed.TryGetValue(name, out var values)) parsed[name] = values = new List<string>();
            values.Add(value);
        }
        return parsed;
    }

    /// <summary>Counts actual bytes crossing the socket against one shared
    /// selection-round budget. TLS and HTTP therefore cannot each spend a
    /// separate allowance.</summary>
    private sealed class ProbeBudgetStream : Stream
    {
        private readonly Stream _inner;
        private readonly ProbeBudget _budget;

        public ProbeBudgetStream(Stream inner, ProbeBudget budget)
        {
            _inner = inner;
            _budget = budget;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count == 0) return 0;
            using var lease = _budget.Reserve(Math.Min(count, Math.Max(1, _budget.RemainingBytes)));
            var read = _inner.Read(buffer, offset, Math.Min(count, lease.Reserved));
            lease.Commit(read);
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            if (buffer.Length == 0) return 0;
            using var lease = _budget.Reserve(Math.Min(buffer.Length, Math.Max(1, _budget.RemainingBytes)));
            var read = _inner.Read(buffer[..Math.Min(buffer.Length, lease.Reserved)]);
            lease.Commit(read);
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return 0;
            using var lease = _budget.Reserve(Math.Min(buffer.Length, Math.Max(1, _budget.RemainingBytes)));
            var read = await _inner.ReadAsync(buffer[..Math.Min(buffer.Length, lease.Reserved)], cancellationToken).ConfigureAwait(false);
            lease.Commit(read);
            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count == 0) return;
            using var lease = _budget.Reserve(count);
            _inner.Write(buffer, offset, count);
            lease.Commit(count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length == 0) return;
            using var lease = _budget.Reserve(buffer.Length);
            _inner.Write(buffer);
            lease.Commit(buffer.Length);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return;
            using var lease = _budget.Reserve(buffer.Length);
            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            lease.Commit(buffer.Length);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}

public sealed record ProbeDescriptor(string Host, string Sni, string Path, bool Tls, string Network)
{
    public bool IsWebSocket => Network.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
        Network.Equals("websocket", StringComparison.OrdinalIgnoreCase);
}

public sealed record ProbeResult(bool Success, double RttMs, double JitterMs, double LossPercent, bool TlsSuccess, int Bytes = 0);

/// <summary>
/// Sanitised, UI-safe measurement for one candidate from the currently
/// verified configuration.  Network addresses and transport secrets never
/// cross this boundary.
/// </summary>
public sealed record CandidateProbeStatus(
    string Code,
    bool Success,
    double? RttMs,
    double? LossPercent,
    long MeasuredAtUnixMilliseconds,
    string? ErrorCode = null);

public sealed record CandidateProbeSnapshot(
    string Source,
    string? SelectedCandidateLabel,
    IReadOnlyList<CandidateProbeStatus> Candidates);

internal sealed record ProbeDiagnosticResult(ProbeResult? Result, IReadOnlyList<string> Events);

/// <summary>Atomic shared budget for one selection round.</summary>
public sealed class ProbeBudget
{
    private int _remaining;
    private int _exhausted;
    private readonly Action? _onExhausted;

    public ProbeBudget(int limitBytes = CandidateProbeEngine.DefaultRoundBudgetBytes, Action? onExhausted = null)
    {
        if (limitBytes <= 0) throw new ArgumentOutOfRangeException(nameof(limitBytes));
        LimitBytes = limitBytes;
        _remaining = limitBytes;
        _onExhausted = onExhausted;
    }

    public int LimitBytes { get; }
    public int ConsumedBytes => LimitBytes - Volatile.Read(ref _remaining);
    public int RemainingBytes => Math.Max(0, Volatile.Read(ref _remaining));
    public bool IsExhausted => Volatile.Read(ref _exhausted) != 0;

    public ProbeBudgetLease Reserve(int requested)
    {
        if (requested <= 0) throw new ArgumentOutOfRangeException(nameof(requested));
        while (true)
        {
            var current = Volatile.Read(ref _remaining);
            if (current < requested)
            {
                if (Interlocked.Exchange(ref _exhausted, 1) == 0) _onExhausted?.Invoke();
                throw new InvalidDataException("BF-PROBE-BUDGET");
            }
            if (Interlocked.CompareExchange(ref _remaining, current - requested, current) == current)
                return new ProbeBudgetLease(this, requested);
        }
    }

    private void Refund(int amount)
    {
        if (amount > 0) Interlocked.Add(ref _remaining, amount);
    }

    public sealed class ProbeBudgetLease : IDisposable
    {
        private ProbeBudget? _budget;
        private int _reserved;
        internal ProbeBudgetLease(ProbeBudget budget, int reserved) { _budget = budget; _reserved = reserved; }
        internal int Reserved => _reserved;
        public void Commit(int used)
        {
            if (used < 0 || used > _reserved) throw new ArgumentOutOfRangeException(nameof(used));
            var refund = _reserved - used;
            _reserved = 0;
            _budget?.Refund(refund);
        }
        public void Dispose()
        {
            var budget = Interlocked.Exchange(ref _budget, null);
            if (budget is not null && _reserved > 0) budget.Refund(_reserved);
            _reserved = 0;
        }
    }
}

/// <summary>
/// Pure selection policy used by the production Windows selector and by the
/// loopback fixture.  Keeping cohort/timestamp rules here prevents the UI
/// path and the executable probe tests from drifting apart.
/// </summary>
public static class CandidateSelectionPolicy
{
    public static IReadOnlyList<T> BuildCohort<T>(
        IReadOnlyList<T> candidates,
        int start,
        int limit,
        string? incumbent,
        Func<T, string?> labelSelector)
    {
        if (candidates.Count == 0 || limit <= 0) return Array.Empty<T>();
        var clean = candidates
            .Where(candidate => !string.IsNullOrWhiteSpace(labelSelector(candidate)))
            .GroupBy(candidate => labelSelector(candidate)!, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();
        if (clean.Count == 0) return Array.Empty<T>();
        var offset = (int)((uint)Math.Max(0, start) % (uint)clean.Count);
        var selected = Enumerable.Range(0, Math.Min(limit, clean.Count))
            .Select(index => clean[(offset + index) % clean.Count])
            .ToList();
        var incumbentCandidate = clean.FirstOrDefault(candidate => string.Equals(labelSelector(candidate), incumbent, StringComparison.OrdinalIgnoreCase));
        if (incumbentCandidate is not null && !selected.Any(candidate => string.Equals(labelSelector(candidate), incumbent, StringComparison.OrdinalIgnoreCase)))
        {
            if (selected.Count == 0) selected.Add(incumbentCandidate);
            else selected[^1] = incumbentCandidate;
        }
        return selected;
    }

    public static long SuccessTimestamp(long previous, long now, bool succeeded) => succeeded ? now : previous;
}
