// Shipping release-contract surface.  This module intentionally exposes only
// the compiled-trust-root verifier and immutable state/plan readers.  Offline
// root descriptors, delegation construction and TEST-ONLY authority adapters
// live in release-contract-tool.mjs and are not imported by client updaters.
export {
  RELEASE_CONTRACT,
  RELEASE_TRUST_ROOT,
  strictUtf8,
  assertNoDuplicateKeys,
  canonicalReleaseJson,
  RELEASE_CONTRACT_FINGERPRINT,
  assertCanonicalReleaseNumbers,
  releaseManifestDigest,
  parseReleaseEnvelope,
  safeReleasePath,
  validateReleaseManifest,
  verifyReleaseEnvelope,
  canonicalReleaseEnvelopeBytes,
  fullReleaseEnvelopeDigest,
  classifyReleaseState,
  isVerifiedReleasePlan,
  validateReleaseState,
  releaseStateChecksum
} from './release-contract-internal.mjs';
