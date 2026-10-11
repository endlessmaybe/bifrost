// Explicit offline/tool-only surface.  Never import this module from a
// shipping updater, service or client entry point.
export {
  RELEASE_CONTRACT,
  RELEASE_TRUST_ROOT,
  strictUtf8,
  assertNoDuplicateKeys,
  canonicalReleaseJson,
  RELEASE_CONTRACT_FINGERPRINT,
  assertCanonicalReleaseNumbers,
  releaseManifestDigest,
  canonicalReleaseKeyDelegation,
  validateReleaseKeyState,
  releaseKeyStateDigest,
  validateReleaseTransition,
  parseReleaseEnvelope,
  safeReleasePath,
  validateReleaseManifest,
  verifyReleaseEnvelope,
  verifyReleaseEnvelopeOfflineInternal,
  canonicalReleaseEnvelopeBytes,
  fullReleaseEnvelopeDigest,
  classifyReleaseState,
  buildVerifiedReleasePlan,
  isVerifiedReleasePlan,
  validateReleaseState,
  releaseStateChecksum
} from './release-contract-internal.mjs';
