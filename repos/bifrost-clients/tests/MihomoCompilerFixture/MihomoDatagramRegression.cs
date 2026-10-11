using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

// Exercise the shipped core's actual UDP path: REJECT accepts a SOCKS UDP
// association but drops its datagrams, so a config-text assertion cannot prove
// that Chromium gets an immediate transport failure. No Internet/TUN is used.
internal static class MihomoDatagramRegression
{
    internal static void Run(string executable, MihomoCompiledPackage package, string? fixedCandidate = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-datagram-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "providers"));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var socks = new TcpListener(IPAddress.Loopback, 0);
        socks.Start();
        var relayPort = ((IPEndPoint)echo.Client.LocalEndPoint!).Port;
        var socksPort = ((IPEndPoint)socks.LocalEndpoint).Port;
        var controls = new List<Task>();
        var accept = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var client = await socks.AcceptTcpClientAsync(stop.Token);
                    controls.Add(ServeAssociation(client, relayPort, stop.Token));
                }
            }
            catch (OperationCanceledException) { }
        });
        var echoLoop = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var packet = await echo.ReceiveAsync(stop.Token);
                    await echo.SendAsync(packet.Buffer, packet.RemoteEndPoint, stop.Token);
                }
            }
            catch (OperationCanceledException) { }
        });
        Process? core = null;
        try
        {
            var main = JsonNode.Parse(package.MainConfig)!.AsObject();
            var port = FreePort();
            var controllerPort = FreePort();
            main["mixed-port"] = port;
            main.Remove("interface-name");
            main["external-controller"] = $"127.0.0.1:{controllerPort}";
            main["tun"] = new JsonObject { ["enable"] = false };
            main["sniffer"] = new JsonObject { ["enable"] = false };
            main["log-level"] = "silent";
            main["hosts"] = new JsonObject { ["files.oaiusercontent.com"] = "203.0.113.7" };
            main["dns"] = new JsonObject
            {
                ["enable"] = true, ["ipv6"] = false,
                ["nameserver"] = new JsonArray("127.0.0.1:1"), ["use-system-hosts"] = false,
            };
            var provider = JsonNode.Parse(package.Provider)!.AsObject();
            foreach (var proxy in provider["proxies"]!.AsArray().OfType<JsonObject>())
            {
                var name = proxy["name"]!.GetValue<string>();
                proxy.Clear(); proxy["name"] = name; proxy["type"] = "socks5";
                proxy["server"] = "127.0.0.1"; proxy["port"] = socksPort; proxy["udp"] = true;
            }
            main["proxy-providers"]![package.ProviderName]!["health-check"]!["enable"] = false;
            foreach (var group in main["proxy-groups"]!.AsArray().OfType<JsonObject>())
            {
                if (fixedCandidate is not null) continue;
                // Selection is tested separately. Keep the compiled rules and
                // group membership, without background Internet health probes.
                var name = group["name"]!.GetValue<string>();
                group.Clear(); group["name"] = name; group["type"] = "select";
                group["use"] = new JsonArray(package.ProviderName);
            }
            File.WriteAllText(Path.Combine(root, "config.json"), main.ToJsonString());
            File.WriteAllText(Path.Combine(root, "providers", "source-A.json"), provider.ToJsonString());
            var geodata = Environment.GetEnvironmentVariable("BIFROST_MIHOMO_GEODATA_DIR")
                ?? throw new InvalidOperationException("Pinned geodata is required for the UDP regression.");
            File.Copy(Path.Combine(geodata, "geosite.dat"), Path.Combine(root, "GeoSite.dat"));
            File.Copy(Path.Combine(geodata, "geoip.metadb"), Path.Combine(root, "geoip.metadb"));
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("-d"); start.ArgumentList.Add(root);
            start.ArgumentList.Add("-f"); start.ArgumentList.Add(Path.Combine(root, "config.json"));
            core = Process.Start(start) ?? throw new InvalidOperationException("Core did not start.");
            using var client = ConnectWhenReady(port, core);
            // The listener opens before file-provider initialization completes.
            // Production waits for its committed group; this fixture must do
            // the same before asserting the very first application datagram.
            WaitForGroup(controllerPort, main["secret"]!.GetValue<string>(), package.ActiveGroup,
                fixedCandidate is null ? package.AllowedCandidates : new HashSet<string> { fixedCandidate });
            if (package.ChatGptGroupName is { } affinity)
                WaitForGroup(controllerPort, main["secret"]!.GetValue<string>(), affinity, package.AllowedCandidates);
            if (fixedCandidate is not null)
            {
                using var controller = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(3) };
                controller.DefaultRequestHeaders.Authorization = new("Bearer", main["secret"]!.GetValue<string>());
                var state = JsonNode.Parse(controller.GetStringAsync($"http://127.0.0.1:{controllerPort}/proxies/{package.ActiveGroup}").GetAwaiter().GetResult())!;
                if (state["all"] is not JsonArray { Count: 1 } members || members[0]!.GetValue<string>() != fixedCandidate ||
                    state["now"]!.GetValue<string>() != fixedCandidate)
                    throw new InvalidOperationException("Fixed mode exposed an unselected provider candidate.");
                Console.WriteLine("MIHOMO-FIXED-CANDIDATE exact runtime membership PASS");
            }
            var stream = client.GetStream();
            stream.ReadTimeout = 3000; stream.WriteTimeout = 3000;
            stream.Write(new byte[] { 5, 1, 0 });
            var greeting = new byte[2]; stream.ReadExactly(greeting);
            if (!greeting.SequenceEqual(new byte[] { 5, 0 })) throw new InvalidOperationException("SOCKS greeting failed.");
            stream.Write(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 });
            var reply = new byte[10]; stream.ReadExactly(reply);
            if (reply[1] != 0 || reply[3] != 1) throw new InvalidOperationException("UDP association failed.");
            var endpoint = new IPEndPoint(new IPAddress(reply.AsSpan(4, 4)), (reply[8] << 8) | reply[9]);
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            udp.Client.ReceiveTimeout = 2000;
            var host = Encoding.ASCII.GetBytes("files.oaiusercontent.com");
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var payload = Encoding.ASCII.GetBytes("BIFROST-UPLOAD-DATAGRAM-" + attempt);
                var datagram = new byte[] { 0, 0, 0, 3, (byte)host.Length }.Concat(host)
                    .Concat(new byte[] { 1, 187 }).Concat(payload).ToArray(); // port 443
                udp.Send(datagram, endpoint);
                IPEndPoint sender = new(IPAddress.Any, 0);
                var response = udp.Receive(ref sender);
                if (!response.AsSpan().EndsWith(payload)) throw new InvalidOperationException("UDP payload was changed.");
            }
            Console.WriteLine("MIHOMO-UPLOAD-DATAGRAM first and repeated packets PASS");
        }
        finally
        {
            if (core is not null)
            {
                if (!core.HasExited) core.Kill(entireProcessTree: true);
                core.WaitForExit(3000); core.Dispose();
            }
            stop.Cancel();
            accept.GetAwaiter().GetResult();
            Task.WhenAll(controls.Append(echoLoop)).GetAwaiter().GetResult();
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task ServeAssociation(TcpClient client, int relayPort, CancellationToken token)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var header = new byte[2]; await stream.ReadExactlyAsync(header, token);
                var methods = new byte[header[1]]; await stream.ReadExactlyAsync(methods, token);
                await stream.WriteAsync(new byte[] { 5, 0 }, token);
                var request = new byte[4]; await stream.ReadExactlyAsync(request, token);
                if (request[1] != 3 || request[3] != 1) return;
                await stream.ReadExactlyAsync(new byte[6], token);
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, (byte)(relayPort >> 8), (byte)relayPort }, token);
                await stream.ReadExactlyAsync(new byte[1], token);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static void WaitForGroup(int port, string secret, string group, IReadOnlySet<string> expected)
    {
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromMilliseconds(500) };
        http.DefaultRequestHeaders.Authorization = new("Bearer", secret);
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var state = JsonNode.Parse(http.GetStringAsync($"http://127.0.0.1:{port}/proxies/{Uri.EscapeDataString(group)}")
                    .GetAwaiter().GetResult())!;
                if (state["all"] is JsonArray members &&
                    members.Select(item => item!.GetValue<string>()).ToHashSet(StringComparer.Ordinal).SetEquals(expected) &&
                    state["now"]?.GetValue<string>() is { } selected && expected.Contains(selected)) return;
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) { }
            Thread.Sleep(25);
        }
        throw new InvalidOperationException("Compiled provider group did not become ready before the datagram test.");
    }

    private static TcpClient ConnectWhenReady(int port, Process core)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            if (core.HasExited) throw new InvalidOperationException("Core exited before UDP regression.");
            var client = new TcpClient();
            try { client.Connect(IPAddress.Loopback, port); return client; }
            catch (SocketException) { client.Dispose(); Thread.Sleep(50); }
        }
        throw new InvalidOperationException("Core listener timeout.");
    }
}
