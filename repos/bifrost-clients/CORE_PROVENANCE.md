# Core provenance (release input)

The Windows release embeds the official Mihomo v1.19.30
`windows-amd64-compatible` binary and binds all of the following into the
release evidence:

- the pinned upstream binary archive and extracted executable SHA-256 values;
- the official `v1.19.30` source archive SHA-256 value;
- the upstream repository/tag reference; and
- an explicit no-local-patch attestation.

Smart-routing data is the official `GeoSite.dat` and `geoip.metadb` pair from
MetaCubeX/meta-rules-dat release `376037117`, commit
`4178770badecb1b349fbcd62c737e0d7a2079729`. The lock records both asset IDs,
byte lengths and SHA-256 values, and the corresponding source archive is bound
into the same release evidence.

The source bundle, CycloneDX/SPDX SBOMs, dependency license manifest and signed
release manifest are generated from the same pinned inputs. A binary selected
by file name or size alone is not an acceptable production release input.

Windows releases use one Mihomo-only artifact profile; no legacy core profile
is accepted by the release verifier or installer.

## Android first formal release

Android uses the existing unified sing-box v1.13.16 / Xray 26.3.27 libbox runtime, built with Go 1.26.5. `core-adapters/android-runtime.lock.json` binds the AAR, both upstream source archives and the Bifrost Xray bridge by byte length and SHA-256. Native ELF build information was inspected before this first formal Android release. No new native networking changes are included in 2.1.62.

The signed source bundle includes both native source archives, the bridge overlay and the runtime lock. Maven POM license metadata, the Gradle dependency lock and SHA-256 verification metadata accompany the app sources. Cached native reuse fails on any mismatched input; rebuilding uses `build-unified-libbox.ps1` without `-ReusePinnedRuntime`, with the pinned source and Android NDK toolchain.
