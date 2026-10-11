# Android / Windows parity — 2.1.65

## Account activation

An account recovery code is a cross-platform activation credential. A Windows
recovery code activates an available Android device slot, and an Android code
activates an available Windows slot. Both use `POST /v1/enrollment/redeem`.
The original account, original active device and recovery code are preserved.
The server seals the unchanged recovery code to the new device's encryption key.

Android: Settings → Device and account → Account recovery code → Activate.
Windows: Settings → Device and account → Activate using recovery code.
Older Windows clients may paste the recovery code into their invitation-code
activation field; no new endpoint or response schema is required.

The existing per-platform account limits still apply. This is not a silent
replacement of an active device on the same platform. Sign out that device or
use the existing administrator device-replacement workflow when its slot is full.

Recovery codes are stored with Android Keystore-backed encrypted preferences,
not ordinary preferences or saved Compose state. Users can reveal/copy their
saved code or explicitly rotate it. Rotating does not revoke active devices;
the old code stops activating new devices. A code previously saved on the
other device is not silently overwritten and may be stale after rotation.

## Navigation and controls

Both clients have five sections in the same order: Connection, Routes, Routing,
Activity, Settings. Android uses touch-sized bottom navigation instead of a
desktop sidebar. Its single dark aurora appearance replaces the retired A/B/C
style picker. The obsolete stored style choices are removed during migration.

- Connection: activate/select a route when prerequisites are absent; connect,
  cancel a pending connection, disconnect, or release an owned blocked state.
- Routes: A/B source selection, current-source candidates and measurements,
  automatic/manual selection, core selection; country exit only in SmartGate.
- Routing: truthful current-mode description and searchable installed Android
  application rules. Global/manual and SmartGate cannot retain hidden app rules.
- Activity: existing runtime-derived traffic and connection state.
- Settings: activation, recovery, pairing, sign-out, real Android VPN/notification
  settings, fixed appearance information, update/config progress and licenses.

"Smart" currently means source-scoped automatic node selection/failover. This
change does not pretend that it implements Windows Mihomo GeoSite/GeoIP routing
on Android. Android package rules control Android apps; they cannot enumerate
Windows processes, and desktop rules do not enumerate phone applications.

## Compatibility and verification

Android application ID remains `com.bifrost.client`. Version code increases to
`20165`; a distribution APK must use the permanent release signing certificate
so an existing installation can upgrade without uninstalling its encrypted state.
No private control-plane or node-agent sources belong in the GPL client bundle.

Regression tests cover recovery activation in both directions, shared account
identity, continued original-device sessions, unchanged recovery credentials,
encrypted delivery to the companion, invalid/rotated codes and platform limits.
JVM tests cover active-state cancellation and removal of hidden application
policy on mode changes. Installed-device layout and OEM-specific VPN settings
require Android runtime verification; a JVM build is not that verification.

The control storage change must be deployed before recovery-code activation
works against a previously running control server. A newly built APK alone
cannot change the old server. Updating local source is not a global update push.
