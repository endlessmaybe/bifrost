import { createHash, createPublicKey, sign, verify } from 'node:crypto';

const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const PURPOSE = 'config-signing-key-state';
const MAX_KEYS = 4;

function fail(code = 'BF-CONFIG-KEY-STATE') {
  throw Object.assign(new Error(code), { code });
}

export function canonicalConfigKeyState(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail();
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalConfigKeyState).join(',')}]`;
  if (!value || typeof value !== 'object') fail();
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalConfigKeyState(value[key])}`).join(',')}}`;
}

function exactObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail();
}

function keyFingerprint(publicKeyPem) {
  let key;
  try { key = createPublicKey(publicKeyPem); } catch { fail(); }
  if (key.asymmetricKeyType !== 'ed25519') fail();
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}

function validateTrustedKey(value) {
  exactObject(value, ['key_id', 'public_key_pem', 'fingerprint', 'activation_floor', 'retirement_floor']);
  if (!KEY_ID.test(String(value.key_id || '')) || typeof value.public_key_pem !== 'string' || value.public_key_pem.length > 2048 || !HEX64.test(String(value.fingerprint || ''))) fail();
  if (!Number.isSafeInteger(value.activation_floor) || value.activation_floor < 1) fail();
  if (value.retirement_floor !== null && (!Number.isSafeInteger(value.retirement_floor) || value.retirement_floor <= value.activation_floor)) fail();
  if (keyFingerprint(value.public_key_pem) !== value.fingerprint) fail('BF-CONFIG-KEY-MISMATCH');
  return Object.freeze({ ...value });
}

function unsignedState(state) {
  const { signature: _signature, ...unsigned } = state;
  return unsigned;
}

export function configKeyStateDigest(state) {
  return createHash('sha256').update(canonicalConfigKeyState(state), 'utf8').digest('hex');
}

export function signConfigKeyState(value, rootPrivateKey) {
  exactObject(value, ['version', 'purpose', 'root_key_id', 'root_fingerprint', 'generation', 'active_key_id', 'trusted_keys', 'previous_state_digest']);
  const bytes = Buffer.from(canonicalConfigKeyState(value), 'utf8');
  try {
    return Object.freeze({ ...value, signature: sign(null, bytes, rootPrivateKey).toString('base64url') });
  } finally { bytes.fill(0); }
}

export function verifyConfigKeyState(state, {
  rootKeyPem,
  rootKeyId = 'bifrost-root-v1',
  rootFingerprint = null,
  previousGeneration = 0,
  previousDigest = null,
  currentConfigVersion = 0,
} = {}) {
  exactObject(state, ['version', 'purpose', 'root_key_id', 'root_fingerprint', 'generation', 'active_key_id', 'trusted_keys', 'previous_state_digest', 'signature']);
  if (state.version !== 1 || state.purpose !== PURPOSE || state.root_key_id !== rootKeyId || !HEX64.test(String(state.root_fingerprint || '')) || !SIG.test(String(state.signature || ''))) fail();
  if (!Number.isSafeInteger(state.generation) || state.generation < 1 || !KEY_ID.test(String(state.active_key_id || ''))) fail();
  if (!Array.isArray(state.trusted_keys) || state.trusted_keys.length < 1 || state.trusted_keys.length > MAX_KEYS) fail();
  if (state.previous_state_digest !== null && !HEX64.test(String(state.previous_state_digest || ''))) fail();
  if (state.generation === 1 && state.previous_state_digest !== null) fail('BF-CONFIG-KEY-ROLLBACK');
  if (state.generation > 1 && state.previous_state_digest === null) fail('BF-CONFIG-KEY-ROLLBACK');

  let root;
  try { root = createPublicKey(rootKeyPem); } catch { fail('BF-CONFIG-TRUST-ROOT'); }
  if (root.asymmetricKeyType !== 'ed25519') fail('BF-CONFIG-TRUST-ROOT');
  const actualRootFingerprint = createHash('sha256').update(root.export({ type: 'spki', format: 'der' })).digest('hex');
  if (state.root_fingerprint !== actualRootFingerprint || (rootFingerprint !== null && rootFingerprint !== actualRootFingerprint)) fail('BF-CONFIG-TRUST-ROOT');

  const bytes = Buffer.from(canonicalConfigKeyState(unsignedState(state)), 'utf8');
  let signature;
  try {
    signature = Buffer.from(state.signature, 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== state.signature || !verify(null, bytes, root, signature)) fail('BF-CONFIG-KEY-SIGNATURE');
  } finally {
    bytes.fill(0);
    signature?.fill(0);
  }

  const keys = state.trusted_keys.map(validateTrustedKey);
  const ids = keys.map((entry) => entry.key_id);
  if (new Set(ids).size !== ids.length || ids.some((id, index) => index > 0 && ids[index - 1].localeCompare(id) >= 0) || !ids.includes(state.active_key_id)) fail();

  const digest = configKeyStateDigest(state);
  if (!Number.isSafeInteger(previousGeneration) || previousGeneration < 0 || (previousDigest !== null && !HEX64.test(String(previousDigest || '')))) fail('BF-CONFIG-KEY-ROLLBACK');
  if (previousGeneration > 0) {
    if (state.generation < previousGeneration) fail('BF-CONFIG-KEY-ROLLBACK');
    if (state.generation === previousGeneration) {
      if (!previousDigest || digest !== previousDigest) fail('BF-CONFIG-KEY-EQUIVOCATION');
    } else {
      if (state.generation !== previousGeneration + 1 || !previousDigest || state.previous_state_digest !== previousDigest) fail('BF-CONFIG-KEY-ROLLBACK');
    }
  }

  if (!Number.isSafeInteger(currentConfigVersion) || currentConfigVersion < 0) fail();
  if (currentConfigVersion > 0) selectConfigSigningKey({ state, keys, digest }, state.active_key_id, currentConfigVersion);
  return Object.freeze({ state: Object.freeze({ ...state, trusted_keys: Object.freeze(keys) }), keys: Object.freeze(keys), digest });
}

export function selectConfigSigningKey(verified, keyId, configVersion) {
  if (!verified || !Array.isArray(verified.keys) || !KEY_ID.test(String(keyId || '')) || !Number.isSafeInteger(configVersion) || configVersion < 1) fail();
  const entry = verified.keys.find((candidate) => candidate.key_id === keyId);
  if (!entry) fail('BF-CONFIG-KEY-UNKNOWN');
  if (configVersion < entry.activation_floor) fail('BF-CONFIG-KEY-NOT-ACTIVE');
  if (entry.retirement_floor !== null && configVersion >= entry.retirement_floor) fail('BF-CONFIG-KEY-RETIRED');
  return entry;
}

// Older operation snapshots persisted the sealed config/recovery envelope but
// omitted its public trust evidence. Restore only that missing field, never
// replace a saved trust state or regenerate a credential/config on retry.
export function withConfigKeyState(response, verified) {
  if (!verified || !response || typeof response !== 'object' || Array.isArray(response) ||
    Object.hasOwn(response, 'config_key_state') || (!response.config_package && !response.recovery_delivery)) return response;
  const version = response.config_version;
  // A current state must still authorize the original envelope at its bound
  // version. A retired/unknown key is not made trusted by replay enrichment.
  selectConfigSigningKey(verified, verified.state.active_key_id, version);
  if (response.config_package) selectConfigSigningKey(verified, response.config_package.key_id, version);
  if (response.recovery_delivery) selectConfigSigningKey(verified, response.recovery_delivery.signing_key_id, version);
  return { ...response, config_key_state: verified.state };
}

export const CONFIG_KEY_STATE_PURPOSE = PURPOSE;
