# Bifrost Clients

This repository contains the GPLv3 Android and Windows clients, their public
protocol/configuration contracts, and the reproducible build inputs. The
private Control plane, Node Agent, administration UI and node operations are
not part of the corresponding GPL client source bundle.

## License and source delivery

`COPYING` is the complete official GNU GPLv3 text. The full third-party texts
are in `licenses/`; `THIRD_PARTY_NOTICES.md` records version, source and local
modification provenance. Nothing in this repository limits the GPL rights to
copy, modify or redistribute the clients. Each binary release is bound to an
exact source/build bundle by the signed release/source manifest, including
generated sources, build/install scripts, interface definitions, lock and
verification files, core source/patch provenance and Installation Information.

## Reproducible local build

Use the pinned Android SDK/NDK, JDK, Gradle and .NET toolchains recorded by the
release manifest. A local unsigned build is for testing only and is never a
release trust root. The release script fails closed when the real signing
ceremony inputs are unavailable.

```powershell
Set-Location '<workspace>\repos\bifrost-clients'
android-app\gradlew.bat testDebugUnitTest lintDebug assembleRelease --offline
```

For an offline source verification, build a temporary `SOURCE-BUNDLE.tar` with
`repos\bifrost-infra\scripts\source-bundle.mjs`, then verify and unpack it in
a fresh temporary directory. Production verification additionally requires the
signed RELEASE-ENVELOPE and protected ceremony root; a draft/status field is
never authority. The verifier rejects path traversal, links,
duplicate/colliding entries, changed bytes, extra/missing files and private
Control/Node source.

## Client boundary

Android `VpnService` and the Windows service compile the signed client
configuration and use the selected sing-box/Xray core through their platform
adapters. Proxy-classified traffic fails closed when the core, DNS or boundary
is unavailable. No client build or test changes the host proxy, routes, WFP,
TUN, DNS or certificate store.
