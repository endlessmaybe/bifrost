# Bifrost client source and corresponding release build

The Android and Windows client code in this repository is GPLv3. Every client
release is accompanied by the exact corresponding source/build bundle listed
by its signed source-build manifest. That bundle contains this source tree,
`COPYING`, the complete `licenses/` texts, `THIRD_PARTY_NOTICES.md`, generated
bindings, lock/verification files, build and installation scripts, pinned core
provenance, and Installation Information. The control plane and node agent are
proprietary and are excluded from the GPL client source boundary.

The GPL grant is unmodified: recipients may copy, modify and redistribute the
client and corresponding source under GPLv3. No “internal only”, no-resale or
no-modification condition is added. `COPYING` is the complete official GPLv3
text; the notices file is an index only and is not a substitute for the full
license texts.

## Android

Use the pinned Android SDK/NDK and JDK 17 recorded by the release ledger. The
official sing-box `libbox.aar` (version 1.13.16) is built from the pinned
upstream source with `cmd/internal/build_libbox`; the resulting AAR is copied
to `android-app/libs/libbox.aar`. Xray-core 26.3.27 is copied per ABI into
`android-app/src/main/assets/core/xray` with a SHA-256 sidecar. No runtime
download is required for a release APK.

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-17'
$env:ANDROID_HOME = '<workspace>\build-work\toolchains\android-sdk'
$env:ANDROID_NDK_HOME = '<workspace>\build-work\toolchains\android-sdk\ndk\28.0.13004108'
.\gradlew.bat assembleRelease --offline
```

Production signing is supplied only through the explicit release ceremony
inputs. A local lab build is marked `unsigned-local` and must not be treated as
a production trust anchor. Missing ceremony inputs fail the release build.

## Windows

Build the WPF app and service self-contained for `win-x64` with the pinned
.NET SDK. The installer script validates the signed manifest and hashes before
staging. `-WhatIf` is the safe validation mode; it does not register a service
or modify proxy, route, DNS, WFP, TUN, or v2rayN state.

Every release manifest uses paths relative to `releases/`, SHA-256 digests,
and an independent Bifrost Ed25519 signature. Rebuilds must regenerate the
SBOM, complete license inventory, source/build-input manifest and verify the
signature before distribution. `source-bundle.mjs verify` performs an offline
path/link/hash/allowlist check in a new temporary directory; it never reads
the developer workspace as a fallback.

## Android signed distribution

Set `BIFROST_RELEASE_SEQUENCE` to the positive sequence of the release envelope before compiling the APK. This value is inside the signed APK and anchors the first update without relying on mutable preferences. Supply the permanent Android signing key through the four existing BIFROST_ANDROID signing environment variables. Do not generate a new key for an update. The local operator can import the DPAPI-protected credential with `Import-AndroidSigningEnvironment.ps1`.

Gradle dependency locking and checksum verification are enabled. Release packaging reuses the exact native archive only when `core-adapters/android-runtime.lock.json` validates it and its corresponding sources. The source rebuild path remains `build-unified-libbox.ps1` with Go/gomobile, Android NDK 28 and the archived sing-box/Xray source checkouts. Runtime modifications require rebuilding and reviewing a new lock.
