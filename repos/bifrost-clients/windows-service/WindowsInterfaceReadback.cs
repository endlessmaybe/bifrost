using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Bifrost.ClientService;

internal sealed record WindowsInterfaceSnapshot(string Id, string Name, string Description,
    int InterfaceIndex, OperationalStatus OperationalStatus, IPAddress[] UnicastAddresses, IPAddress[] DnsAddresses);

// A synchronous health observation checks both the boundary and DNS owner.
// Share only that observation's live address snapshot, never a cached health
// result. GetAdaptersAddresses supplies everything these checks need without
// .NET's additional GetPerAdapterInfo call for every installed adapter.
internal static class WindowsInterfaceReadback
{
    [ThreadStatic] private static Scope? _current;
    internal static IDisposable Begin() => new Scope();
    internal static WindowsInterfaceSnapshot[] Read() => _current?.Read() ?? ReadFresh();

    private static WindowsInterfaceSnapshot[] ReadFresh()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        uint size = 16 * 1024;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (size is 0 or > 4 * 1024 * 1024) throw new InvalidDataException("BF-INTERFACE-READBACK");
            var capacity = checked((int)size);
            var buffer = Marshal.AllocHGlobal(capacity);
            try
            {
                // AF_UNSPEC, SKIP_ANYCAST | SKIP_MULTICAST | INCLUDE_ALL_INTERFACES.
                // Keep unicast, DNS, friendly names and disabled adapters so an
                // ambiguous interface name still fails the ownership checks.
                var error = GetAdaptersAddresses(0, 0x106, IntPtr.Zero, buffer, ref size);
                if (error == 111) continue; // topology may grow between calls
                if (error == 232) return []; // ERROR_NO_DATA
                if (error != 0) throw new NetworkInformationException(checked((int)error));
                return Parse(buffer, capacity);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidDataException("BF-INTERFACE-READBACK");
    }

    internal static WindowsInterfaceSnapshot[] Parse(IntPtr buffer, int capacity)
    {
        var reader = new BufferReader(buffer, capacity);
        var result = new List<WindowsInterfaceSnapshot>();
        for (var current = buffer; current != IntPtr.Zero;)
        {
            if (result.Count >= 4096) throw new InvalidDataException("BF-INTERFACE-READBACK");
            var adapter = reader.Structure<AdapterPrefix>(current);
            if (adapter.Length < Marshal.SizeOf<AdapterPrefix>() || adapter.IfIndex > int.MaxValue)
                throw new InvalidDataException("BF-INTERFACE-READBACK");
            result.Add(new(reader.String(adapter.AdapterName, unicode: false),
                reader.String(adapter.FriendlyName, unicode: true), reader.String(adapter.Description, unicode: true),
                (int)adapter.IfIndex, (OperationalStatus)adapter.OperStatus,
                reader.Addresses(adapter.FirstUnicastAddress), reader.Addresses(adapter.FirstDnsServerAddress)));
            current = adapter.Next;
        }
        return result.ToArray();
    }

    private readonly struct BufferReader(IntPtr buffer, int capacity)
    {
        private void Require(IntPtr pointer, int length)
        {
            var offset = pointer.ToInt64() - buffer.ToInt64();
            if (capacity <= 0 || length < 0 || offset < 0 || offset > capacity || length > capacity - offset)
                throw new InvalidDataException("BF-INTERFACE-READBACK");
        }

        internal T Structure<T>(IntPtr pointer) where T : struct
        {
            Require(pointer, Marshal.SizeOf<T>());
            return Marshal.PtrToStructure<T>(pointer);
        }

        internal string String(IntPtr pointer, bool unicode)
        {
            if (pointer == IntPtr.Zero) return "";
            var width = unicode ? 2 : 1;
            for (var length = 0; length < 32768; length++)
            {
                var character = IntPtr.Add(pointer, checked(length * width));
                Require(character, width);
                if ((unicode ? Marshal.ReadInt16(character) : Marshal.ReadByte(character)) == 0)
                    return (unicode ? Marshal.PtrToStringUni(pointer, length) : Marshal.PtrToStringAnsi(pointer, length)) ?? "";
            }
            throw new InvalidDataException("BF-INTERFACE-READBACK");
        }

        internal IPAddress[] Addresses(IntPtr pointer)
        {
            var addresses = new List<IPAddress>();
            var count = 0;
            while (pointer != IntPtr.Zero)
            {
                if (++count > 4096) throw new InvalidDataException("BF-INTERFACE-READBACK");
                var address = Structure<AddressPrefix>(pointer);
                if (address.Length < Marshal.SizeOf<AddressPrefix>()) throw new InvalidDataException("BF-INTERFACE-READBACK");
                Require(address.Address.Pointer, address.Address.Length);
                if (address.Address.Length < 2) throw new InvalidDataException("BF-INTERFACE-READBACK");
                var family = Marshal.ReadInt16(address.Address.Pointer);
                var byteCount = family == 2 ? 4 : family == 23 ? 16 : 0;
                if (byteCount != 0)
                {
                    var required = family == 2 ? 16 : 28;
                    if (address.Address.Length < required) throw new InvalidDataException("BF-INTERFACE-READBACK");
                    var bytes = new byte[byteCount];
                    Marshal.Copy(IntPtr.Add(address.Address.Pointer, family == 2 ? 4 : 8), bytes, 0, byteCount);
                    addresses.Add(family == 2 ? new IPAddress(bytes) : new IPAddress(bytes,
                        unchecked((uint)Marshal.ReadInt32(address.Address.Pointer, 24))));
                }
                pointer = address.Next;
            }
            return addresses.ToArray();
        }
    }

    // Prefixes of IP_ADAPTER_ADDRESSES_LH and IP_ADAPTER_*_ADDRESS.
    // Only the documented fields used here are marshalled; Length guards the
    // prefix and every pointer/string/socket address stays inside its buffer.
    [StructLayout(LayoutKind.Sequential)]
    private struct AdapterPrefix
    {
        public uint Length, IfIndex;
        public IntPtr Next, AdapterName, FirstUnicastAddress, FirstAnycastAddress, FirstMulticastAddress,
            FirstDnsServerAddress, DnsSuffix, Description, FriendlyName;
        public uint PhysicalAddressLow, PhysicalAddressHigh, PhysicalAddressLength, Flags, Mtu, IfType, OperStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SocketAddress { public IntPtr Pointer; public int Length; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AddressPrefix { public uint Length, Flags; public IntPtr Next; public SocketAddress Address; }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetAdaptersAddresses(uint family, uint flags, IntPtr reserved, IntPtr buffer, ref uint size);

    private sealed class Scope : IDisposable
    {
        private readonly Scope? _previous = _current;
        private WindowsInterfaceSnapshot[]? _interfaces;
        internal Scope() { _current = this; }
        internal WindowsInterfaceSnapshot[] Read() => _interfaces ??= ReadFresh();
        public void Dispose() { _current = _previous; }
    }
}
