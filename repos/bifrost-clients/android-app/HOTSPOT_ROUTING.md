# Android hotspot routing

The settings entry is **Settings → Connection and routing → Hotspot network**.
The default is `smart`, which follows the current phone configuration and
selected upstream. `direct` uses Android's ordinary tether forwarding and a
separate direct DNS ingress. These options apply while Root mode is connected.
Android VPN mode continues to leave tether forwarding to the system.

Phone application lists cannot identify applications on a tether client. The
hotspot follows domain/IP rules and the selected exit; it does not inherit
phone UID inclusion/exclusion lists. Existing sockets and DNS answers may
survive a mode change; reconnect tether clients after switching modes.

## Root cause fixed

On the user's REDMI K80 (Android 16), `ip route get 1.1.1.1 from <client> iif
wlan2` selected `bfr10403` under the previous BFR12 UID policy. Forwarded
IPv4 packets can match UID 0, so the rule covering `0-10402` accidentally
captured hotspot traffic. Android's `tetherctrl_FORWARD` only permitted the
real upstream, and dropped the resulting hotspot-to-TUN forwarding. A
temporary ingress-specific physical route restored connectivity, confirmed
by the user before building this change.

BFR13 adds `iif lo` to phone UID capture. BFR1–12 journals retain their exact
original selectors during cleanup. DNS refresh retains the BFR13 generation
and hotspot mode instead of silently falling back to an older journal.

## Hotspot ingress

The helper discovers tether interfaces from netd's priority-21000 ingress
rules, rather than guessing that every `wlan*` interface is a hotspot. It
refreshes discovery while the Root daemon runs, including while the UI is
absent. It never starts or stops Android tethering or changes system VPNs.

Dedicated, app-owned mangle chains redirect hotspot TCP/UDP through TProxy:

| Mode | Data | DNS |
| --- | --- | --- |
| smart | Same libbox routing rules and upstream as the phone | Same smart DNS and fake-IP reverse mapping |
| direct | System tether route and NAT | Dedicated ingress using `direct-dns`; no fake-IP answers |

Listeners use loopback addresses, protected reply sockets and ports 15357/15358
for IPv4 and IPv6. Only discovered tether interfaces receive the matching
kernel hooks. A separate routing mark and table keep hotspot delivery apart
from phone/VPN DNS. DHCP and multicast retain their system handling.
Startup/recovery fences smart hotspot TCP/UDP and the direct hotspot DNS
ingress until the core is ready. Mode switching atomically replaces the dispatch rule, verifies both
families, and journals the result before the app saves the preference.

Teardown reconstructs only exact app-owned hooks and chains from their names,
including recovery after a crash or after a tether interface disappears. It
does not flush Android's forwarding/NAT chains, change offload settings, or
change Tailscale's VPN slot.

## Validation

- `src/test/cpp/BifrostRootPolicyTest.cpp`: BFR13 selectors, legacy cleanup,
  interface discovery, mode validation and DNS journal refresh. Compile with
  the pinned NDK, then run the ARM64 fixture on the authorized phone.
- `BifrostHotspotRoutingTest`: dedicated real-address DNS, inherited smart
  fake-IP mapping, protected loopback listeners and preserved routing rules.
- Run `testDebugUnitTest`, `lintRelease`, `assembleRelease` with temporary
  Gradle outputs and caches directed to H: on this user's machine.
- On the phone, verify actual kernel rules and counters, both hotspot modes,
  normal phone connectivity and Tailscale access. A build or local JSON test
  alone is not evidence that a tether client can use the proxy.
