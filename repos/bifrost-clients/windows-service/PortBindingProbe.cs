using System.Net;
using System.Net.Sockets;

namespace Bifrost.ClientService;

/// <summary>
/// Windows can retain wildcard TCP bindings for a terminating core even when
/// Process.HasExited has already become true.  A loopback-only TcpListener can
/// therefore report a port as available while Mihomo later fails to bind the
/// same port with WSAEACCES.  Probe with an exclusive wildcard socket so every
/// local address participates in the availability check.
/// </summary>
internal static class PortBindingProbe
{
    internal static bool CanBindTcpExclusive(int port)
    {
        if (port is < 1 or > 65535) return false;
        try
        {
            using var socket = CreateExclusiveTcpSocket();
            socket.Bind(new IPEndPoint(IPAddress.Any, port));
            socket.Listen(1);
            return true;
        }
        catch (SocketException) { return false; }
    }

    internal static int AllocateEphemeralTcpExclusive(params int[] excludedPorts)
    {
        var excluded = excludedPorts is { Length: > 0 }
            ? excludedPorts.ToHashSet()
            : null;
        for (var attempt = 0; attempt < 32; attempt++)
        {
            try
            {
                using var socket = CreateExclusiveTcpSocket();
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                socket.Listen(1);
                var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
                if (excluded is null || !excluded.Contains(port)) return port;
            }
            catch (SocketException) { }
        }
        throw new ServiceFailure("BF-CORE-PORT-IN-USE");
    }

    private static Socket CreateExclusiveTcpSocket()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ExclusiveAddressUse = true,
        };
        return socket;
    }
}
