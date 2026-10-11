# Bifrost client third-party notices

This file is part of the corresponding client source/build bundle. The
complete texts, rather than this index, are shipped under `licenses/`.

| Component | Version/source | License text | Modification/provenance |
| --- | --- | --- | --- |
| Bifrost Android and Windows client | release source tree | `COPYING` / `licenses/GPL-3.0-only.txt` | Bifrost client code; generated protocol bindings and build scripts are included in the source bundle. |
| Mihomo Windows core | v1.19.30, `windows-amd64-compatible`, <https://github.com/MetaCubeX/mihomo/tree/v1.19.30> | `licenses/GPL-3.0-only.txt` | The unmodified official stable binary is verified by the URL, archive SHA-256 and executable SHA-256 in `core-adapters/mihomo.lock.json`. It is the only network core accepted by the Windows release. |
| Mihomo GeoSite/GeoIP data | release 376037117, commit `4178770badecb1b349fbcd62c737e0d7a2079729`, <https://github.com/MetaCubeX/meta-rules-dat> | `licenses/GPL-3.0-only.txt` | `GeoSite.dat` and `geoip.metadb` asset IDs, byte lengths and SHA-256 values are pinned in `core-adapters/mihomo-geodata.lock.json`; the corresponding source archive is release-bound. |
| AndroidX, Kotlin, Gradle plugins and other Apache components | versions resolved from Gradle lock/verification metadata | `licenses/Apache-2.0.txt` | Resolved graph, purl, hash and source are emitted by the SBOM generator; no `META-INF` notice is silently discarded. |
| Client-side MIT components (when present) | versions resolved from the client lock/assets | `licenses/MIT.txt` | Only components resolved by the client build are included; private Control/Node service dependencies are excluded. |
| Bifrost rainbow-bridge icon | `windows-app/Assets/bifrost.ico`, Android vector drawable | Bifrost-generated artwork; project copyright | The source vector/drawing and generated raster are included in the corresponding source bundle; no external icon license is asserted. |

The private Control plane, Node Agent, web-admin and infrastructure operations
code are excluded from the GPL corresponding-source bundle. Public protocol
schemas and generated language bindings may be included because they are
interface definitions, not private service implementation.

Nothing in this notice limits the GPLv3 rights to copy, modify or redistribute
the client source or corresponding binaries. Installation Information and
build inputs are delivered by the signed source/build-input manifest when a
release is published.

## Android native and Maven components

Android's packaged `assets/routing` source rule sets are converted from the same
MetaCubeX/meta-rules-dat Windows assets pinned at commit
`4178770badecb1b349fbcd62c737e0d7a2079729`, under GPL-3.0-only.
Copyright MetaCubeX/meta-rules-dat contributors and upstream rule-data contributors.
`tools/export-android-routing.py` records the conversion, while the packaged
`routing/manifest.json` binds the input and output hashes. No remote rule download
is required at runtime. Source: https://github.com/MetaCubeX/meta-rules-dat/tree/4178770badecb1b349fbcd62c737e0d7a2079729.

The Android app includes sing-box v1.13.16 under GPL-3.0-only and Xray 26.3.27 under MPL-2.0. Bifrost's bridge is an overlay to sing-box; the corresponding source archives and overlay are included in the signed source bundle. Native components retain their upstream copyright notices and module source references. The generated dependency license manifest and CycloneDX/SPDX inventory record these native components and the locked Android dependencies, backed by exact Maven POM license metadata.


## Root IPC and service domain classifications (2026-09-14)

libsu 6.0.0, copyright John Wu, Apache-2.0: https://github.com/topjohnwu/libsu. Its core/service artifacts are version-locked and SHA-256 verified.

The factual service-domain classifications are cross-checked against v2fly/domain-list-community (MIT), MetaCubeX/meta-rules-dat (generated distribution; source dependencies documented upstream), and blackmatrix7/ios_rule_script (GPL-2.0). Individual source revisions, URLs, content hashes, excluded advertising records and domain-level provenance are recorded in routing-policy/service-routing-v1.json. Original license notices are in licenses/domain-list-community-MIT.txt and licenses/ios-rule-script-GPL-2.0.txt. No upstream rule implementation code is included in generated client classes.
