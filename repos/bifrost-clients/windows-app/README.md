# Windows client

The WPF UI talks to `BifrostClientService` through its authenticated named
pipe. It never claims a connection until the signed Mihomo package, controller,
provider group, TUN and route handover all report the expected release
generation. The service does not set a system proxy and does not modify other
proxy applications.

Windows ships exactly one data-plane core: the release-pinned Mihomo binary.
Smart routing, global proxy and SmartGate remain separate policies compiled
into Mihomo; automatic selection uses the provider health-check group rather
than walking candidates in source order.

Builds consume the fixed .NET toolchain named and hashed by the release
source/build manifest. Real Windows SCM, TUN, sleep/resume and uninstall tests
remain PENDING-EXTERNAL and are never substituted by this repository's
loopback/fake-adapter tests.
