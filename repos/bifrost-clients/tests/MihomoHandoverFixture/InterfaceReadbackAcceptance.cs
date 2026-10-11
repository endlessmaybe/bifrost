using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using Bifrost.ClientService;

static partial class Fixture
{
    private static void InterfaceReadbackAcceptance()
    {
        var managed = NetworkInterface.GetAllNetworkInterfaces();
        var native = WindowsInterfaceReadback.Read();
        Assert(managed.Length == native.Length, "live native adapter count matches managed readback");
        foreach (var adapter in managed)
        {
            var actual = native.Single(item => item.Id == adapter.Id);
            var properties = adapter.GetIPProperties();
            Assert(actual.Name == adapter.Name && actual.Description == adapter.Description &&
                actual.OperationalStatus == adapter.OperationalStatus, "live native identity and status parity");
            if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                Assert(actual.InterfaceIndex == properties.GetIPv4Properties()!.Index, "live IPv4 interface index parity");
            Assert(actual.UnicastAddresses.Select(item => item.ToString()).Order().SequenceEqual(
                properties.UnicastAddresses.Select(item => item.Address.ToString()).Order()), "live IPv4/IPv6 unicast and scope parity");
            // The managed DNS collection drops IPv6 scope IDs. Compare address
            // bytes here; the native reader retains the scope supplied by Windows.
            Assert(actual.DnsAddresses.Select(item => Convert.ToHexString(item.GetAddressBytes())).Order().SequenceEqual(
                properties.DnsAddresses.Select(item => Convert.ToHexString(item.GetAddressBytes())).Order()), "live IPv4/IPv6 DNS parity");
        }

        var buffer = Marshal.AllocHGlobal(1024);
        try
        {
            void Reset() => Marshal.Copy(new byte[1024], 0, buffer, 1024);
            void Reject(Action action)
            {
                try { action(); }
                catch (InvalidDataException) { return; }
                throw new Exception("malformed native address buffer must fail closed");
            }
            Reset();
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1));
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024)); // missing Length
            var row = new TestAdapter { Length = (uint)Marshal.SizeOf<TestAdapter>(), IfIndex = 66, OperStatus = 1 };
            Marshal.StructureToPtr(row, buffer, false);
            var parsed = WindowsInterfaceReadback.Parse(buffer, 1024).Single();
            Assert(parsed.InterfaceIndex == 66 && parsed.OperationalStatus == OperationalStatus.Up && parsed.DnsAddresses.Length == 0,
                "minimal adapter preserves state without inventing DNS");
            row.Next = IntPtr.Add(buffer, 1024);
            Marshal.StructureToPtr(row, buffer, false);
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024));
            row.Next = buffer;
            Marshal.StructureToPtr(row, buffer, false);
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024)); // cyclic list
            row.Next = IntPtr.Zero;
            row.FriendlyName = IntPtr.Add(buffer, 1023);
            Marshal.StructureToPtr(row, buffer, false);
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024)); // truncated UTF-16
            row.FriendlyName = IntPtr.Zero;
            row.Dns = IntPtr.Add(buffer, 512);
            Marshal.StructureToPtr(row, buffer, false);
            var dns = new TestAddress { Length = (uint)Marshal.SizeOf<TestAddress>(), Address = IntPtr.Add(buffer, 768), AddressLength = 16 };
            Marshal.StructureToPtr(dns, row.Dns, false);
            Marshal.WriteInt16(dns.Address, 2);
            Marshal.Copy(new byte[] { 198, 18, 0, 1 }, 0, IntPtr.Add(dns.Address, 4), 4);
            Assert(WindowsInterfaceReadback.Parse(buffer, 1024).Single().DnsAddresses.Single().Equals(IPAddress.Parse("198.18.0.1")),
                "current DNS server is read from the snapshot");
            Marshal.WriteByte(dns.Address, 7, 2);
            Assert(WindowsInterfaceReadback.Parse(buffer, 1024).Single().DnsAddresses.Single().Equals(IPAddress.Parse("198.18.0.2")),
                "changed DNS is observed by the next snapshot");
            dns.AddressLength = 4;
            Marshal.StructureToPtr(dns, row.Dns, false);
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024));
            dns.Address = IntPtr.Add(buffer, 1024);
            dns.AddressLength = 16;
            Marshal.StructureToPtr(dns, row.Dns, false);
            Reject(() => WindowsInterfaceReadback.Parse(buffer, 1024));
        }
        finally { Marshal.FreeHGlobal(buffer); }

        using var process = Process.GetCurrentProcess();
        var cpu = process.TotalProcessorTime;
        var timer = Stopwatch.StartNew();
        for (var iteration = 0; iteration < 30; iteration++) _ = WindowsInterfaceReadback.Read();
        Console.WriteLine(JsonSerializer.Serialize(new { check = "native-interface-readback", adapters = native.Length,
            iterations = 30, elapsedMs = timer.Elapsed.TotalMilliseconds, cpuMs = (process.TotalProcessorTime - cpu).TotalMilliseconds }));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TestAdapter
    {
        public uint Length, IfIndex;
        public IntPtr Next, AdapterName, Unicast, Anycast, Multicast, Dns, DnsSuffix, Description, FriendlyName;
        public uint PhysicalLow, PhysicalHigh, PhysicalLength, Flags, Mtu, IfType, OperStatus;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TestAddress { public uint Length, Flags; public IntPtr Next, Address; public int AddressLength; }
}
