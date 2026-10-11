using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

internal static class Ipv4PreferenceFixture
{
    internal static void Run(string executable, MihomoCompiledPackage package) => RunAsync(executable, package).GetAwaiter().GetResult();

    private static async Task RunAsync(string executable, MihomoCompiledPackage package)
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-ip-family-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        using var dns = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var dnsPort = ((IPEndPoint)dns.Client.LocalEndPoint!).Port;
        async Task ServeDns()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var packet = await dns.ReceiveAsync(stop.Token);
                    var request = packet.Buffer;
                    var end = 12;
                    var labels = new List<string>();
                    while (request[end] != 0)
                    {
                        var length = request[end++];
                        labels.Add(Encoding.ASCII.GetString(request, end, length)); end += length;
                    }
                    end++;
                    var type = (request[end] << 8) | request[end + 1];
                    var host = string.Join('.', labels);
                    byte[]? address = type == 28 ? IPAddress.IPv6Loopback.GetAddressBytes()
                        : type == 1 && host == "dual.test" ? IPAddress.Loopback.GetAddressBytes() : null;
                    var response = request[..(end + 4)].ToList();
                    response[2] = 0x81; response[3] = 0x80;
                    response[6] = 0; response[7] = (byte)(address == null ? 0 : 1);
                    response[8] = response[9] = response[10] = response[11] = 0;
                    if (address != null)
                    {
                        response.AddRange(new byte[] { 0xc0, 0x0c, 0, (byte)type, 0, 1, 0, 0, 0, 0, 0, (byte)address.Length });
                        response.AddRange(address);
                    }
                    await dns.SendAsync(response.ToArray(), packet.RemoteEndPoint, stop.Token);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        var dnsServer = ServeDns();
        var v4 = new TcpListener(IPAddress.Loopback, 0); v4.Start();
        var port = ((IPEndPoint)v4.LocalEndpoint).Port;
        var v6 = new TcpListener(IPAddress.IPv6Loopback, port); v6.Server.DualMode = false; v6.Start();
        async Task Serve(TcpListener listener, string family)
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var peer = await listener.AcceptTcpClientAsync(stop.Token);
                    using var reader = new StreamReader(peer.GetStream(), leaveOpen: true);
                    while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
                    await peer.GetStream().WriteAsync(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{family}"), stop.Token);
                }
            }
            catch (Exception) when (stop.IsCancellationRequested || !listener.Server.IsBound) { }
        }
        var server4 = Serve(v4, "4"); var server6 = Serve(v6, "6");
        var reserve = new TcpListener(IPAddress.Loopback, 0); reserve.Start();
        var proxyPort = ((IPEndPoint)reserve.LocalEndpoint).Port; reserve.Stop();
        var direct = JsonNode.Parse(package.MainConfig)!["proxies"]!.AsArray().OfType<JsonObject>()
            .Single(item => item["name"]?.GetValue<string>() == "BIFROST-DIRECT").DeepClone().AsObject();
        // The isolated loopback fixture has no physical-underlay binding.
        // Keep the exact emitted direct outbound and family policy otherwise.
        direct.Remove("interface-name");
        var config = new JsonObject
        {
            ["mixed-port"] = proxyPort, ["bind-address"] = "127.0.0.1", ["ipv6"] = true,
            ["tcp-concurrent"] = true, ["log-level"] = "error", ["proxies"] = new JsonArray(direct),
            ["rules"] = new JsonArray("MATCH,BIFROST-DIRECT"),
            // Hosts entries are randomly pinned by tunnel metadata handling before
            // dialing. Use real DNS answers to exercise the dual-stack dialer.
            ["dns"] = new JsonObject { ["enable"] = true, ["ipv6"] = true,
                ["use-hosts"] = false, ["use-system-hosts"] = false,
                ["nameserver"] = new JsonArray($"udp://127.0.0.1:{dnsPort}") },
        };
        var path = Path.Combine(root, "config.json"); File.WriteAllText(path, config.ToJsonString());
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-d", root, "-f", path }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
        try
        {
            for (var i = 0; ; i++)
            {
                try { using var check = new TcpClient(); await check.ConnectAsync(IPAddress.Loopback, proxyPort, stop.Token); break; }
                catch (SocketException) when (i < 40 && !process.HasExited) { await Task.Delay(50, stop.Token); }
            }
            async Task Expect(string host, string expected)
            {
                using var http = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"), UseProxy = true });
                var actual = await http.GetStringAsync($"http://{host}:{port}/", stop.Token);
                if (actual != expected) throw new Exception($"IP family: {host} expected {expected}, got {actual}");
            }
            for (var i = 0; i < 8; i++) await Expect("dual.test", "4");
            await Expect("v6.test", "6");
            await Expect("[::1]", "6");
            v4.Stop();
            await Expect("dual.test", "6");
            Console.WriteLine("MIHOMO-IP-FAMILY real core: IPv4 preferred, IPv4 refusal falls back to IPv6, IPv6-only name and IPv6 literal PASS");
        }
        finally
        {
            stop.Cancel(); v4.Stop(); v6.Stop();
            if (!process.HasExited) process.Kill(true);
            await process.WaitForExitAsync();
            try { await Task.WhenAll(server4, server6, dnsServer); } catch (Exception) when (stop.IsCancellationRequested) { }
            await Task.WhenAll(output, errors);
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
