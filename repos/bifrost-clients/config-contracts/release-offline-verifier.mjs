// Tool-only release verification boundary.
//
// This module is intentionally not imported by the updater/client runtime. It
// is used by the offline signer and TEST-ONLY corpus fixtures after a protected
// ceremony-file loader has produced a branded descriptor. Keeping this boundary
// separate prevents ordinary update callers from supplying a PEM or authority
// object to the production verifier.
import { verifyReleaseEnvelopeOfflineInternal } from './release-contract-internal.mjs';

export function verifyOfflineReleaseEnvelope(envelope, options = {}) {
  if (!options || !options.rootDescriptor) throw new Error('BF-RELEASE-TRUST-ROOT');
  return verifyReleaseEnvelopeOfflineInternal(envelope, options);
}
