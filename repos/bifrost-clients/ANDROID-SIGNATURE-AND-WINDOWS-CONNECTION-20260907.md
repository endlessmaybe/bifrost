# Android recovery signature fix and Windows connection assessment


Publication update (2026-09-07 15:17 +08:00): Android 2.1.70 is now published to the formal Android channel after explicit user authorization. Canonical and protected-runtime pointers match generation seq-1788763048-57636; both verify active/downloadable. All five mirror artifacts passed upload/hash and public full-length checks; an independent full ARM64 public download matched SHA-256. Direct APK: https://bifrostlog.com/downloads/Bifrost-2.1.70-Android-arm64-v8a.apk . Windows channel remains unchanged. This supersedes the candidate-only publication statements below; the Windows assessment and real-phone validation limits still apply.

## Android recovery — fixed candidate 2.1.70, not promoted

Android framework `JSONObject.quote` escapes every `/`. Control signs the sorted
JSON object using `JSON.stringify`, which leaves `/` unescaped. The generation-3
production config-key state has `/` in both signing-leaf PEM values. Reconstructing
that payload with Android's writer invalidates its Ed25519 signature before the
recovery delivery can be accepted. Host tests previously used Maven org.json,
which has different escaping behavior and masked this failure.

`BifrostJsonString` now supplies deterministic JSON.stringify-compatible string
escaping for config-key signatures, recovery/config envelopes and digests,
request digests, and release delegation/key-state/envelope verification. It
also handles control characters and lone UTF-16 surrogates. The independent
locally persisted release-bootstrap record retains its existing encoding.
Signature verification, root anchoring and rollback checks remain enforced.

Validation:

- JVM tests: 213 passed.
- The same 213 tests passed with the actual AOSP JSON implementation ahead of
  the host JSON library on the test classpath. Six unmodified AOSP JSON source
  files from `android-4.2.2_r1` were compiled on JDK 17. The relevant slash
  escaping behavior was also checked against the published Android 35 source.
- The production public-key-state fixture explicitly demonstrates that the old
  framework reconstruction fails Ed25519 verification and the fixed path
  succeeds. Altering the signed generation is still rejected.
- The Control-generated recovery envelope decrypts; altered AAD, expiry,
  version, signature and private key are rejected.
- Host/shared tests cover slash-bearing request paths, release serialization,
  Unicode, HTML closing tags, controls and unpaired surrogates.
- Android instrumented tests compile, but did not run: this machine lacks an
  available emulator accelerator; the software attempt produced no adb device.
  No real-phone activation or long-running VPN acceptance is claimed.
- Client contract tests: 14 passed. Release compilation and lint passed.
- All three release APK signatures verify against the existing Android
  certificate, and the signed release/source envelope verifies offline.

Deliverables: `../../dist/Android-2.1.70` (ARM64, ARMv7, x86-64, corresponding
source, notices and signed release evidence). Generation
`seq-1788763048-57636`, sequence `1788763048`. Certificate SHA-256 remains
`257c6eb5f0444a5c77c9f355638773f774723fdd2f023077dd5522e77bd5b160`.
The production Android channel still points to 2.1.69. These are local signed
installation candidates; publication and real-phone success are separate.

Scratch, source snapshot and test/build logs:
`H:\CodexTemp\work\bifrost-android-signature-20260907`.

## Windows long-session / stale connected state — not fully resolved

The user's long-session connectivity report concerns Windows, not Android.
The Windows assessment below is read-only; the Android findings must not be
used to describe Windows runtime behavior.

The Windows implementation does have real failover: ordinary smart/per-app
routing uses Mihomo URLTest, SmartGate uses ordered Fallback, and fixed global
routing uses a fixed selector. Provider and group probes use a 30-second
cadence, a 5-second timeout, and the same HTTPS 204 endpoint. SmartGate favors
the configured source order rather than always selecting the lowest latency.
The service also performs an HTTPS 204 exchange through the running data plane
when status is queried, with bounded transient-failure tolerance.

Confirmed unresolved gaps:

1. `UiShellViewModel.TryAutomaticCandidateFailoverAsync` suppresses recovery
   after one failed attempt using source and config version. An upstream outage
   ending without a local network/config/source change does not automatically
   lift that suppression. A failed attempt may also leave Error/Idle rather
   than Blocked, while the polling trigger only recovers Blocked. Existing
   `--smartgate-recovery` coverage proves the first successful recovery and
   healthy no-op, not eventual recovery after repeated failures.
2. `PollServiceStatusAsync` updates only the status text on IPC failure and
   leaves the previous protected presentation in place. There is no freshness
   deadline in this path, so an unreadable service can leave stale connected
   presentation visible.
3. The service's end-to-end check is invoked by `CoreRuntime.Status()`; the
   inspected service has no independent periodic invocation of this check.
   Client-driven status polling and UI-owned recovery therefore do not provide
   a complete autonomous service recovery loop when the UI is unavailable.
4. A successful check of one HTTPS 204 target does not establish connectivity
   to every routed application, domain, DNS path or existing long-lived stream.
   No evidence from this report establishes a scoring bug as the sole cause.

Local evidence: the installed BifrostClientService was running from the Windows
2.1.70 generation. Searches of the two existing service trace files found no
matching data-plane-failure / transient-unhealthy events, so those logs cannot
identify the user's reported failing connection. No customer network, runtime,
service, account, Windows executable or Windows release pointer was changed.

The next Windows correction needs persistent connection intent, bounded retry
backoff across temporary failures, cancellation on manual disconnect, explicit
stale-status presentation, and service-owned health/recovery execution. Its
acceptance must include outage/recovery without network/config changes,
several failed recoveries before success, stale IPC, UI exit/restart, and
candidate transitions under real traffic. This assessment is not a claim
that Windows long-session connectivity has been fixed.
