// TOOL-ONLY updater library.  Windows/Android shipping update paths use their
// compiled trust bindings; this Node module is retained for offline release
// tooling and deliberately stays disabled when the ceremony root is absent.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { validateReleaseManifest, verifyReleaseEnvelope as verifyCanonicalReleaseEnvelope, parseReleaseEnvelope as parseCanonicalReleaseEnvelope, assertCanonicalReleaseNumbers, safeReleasePath, validateReleaseState, canonicalReleaseJson, canonicalReleaseEnvelopeBytes, fullReleaseEnvelopeDigest, RELEASE_TRUST_ROOT, isVerifiedReleasePlan } from '../config-contracts/release-contract.mjs';

const FORMAT = 'BIFROST-RELEASE-MANIFEST-2';
const MAX_ARTIFACTS = 64;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1 * 1024 * 1024;
function safeRelativePath(value) {
  try { return safeReleasePath(value); } catch { throw new Error('release artifact path escapes root'); }
}

function strictUtf8(bytes) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const text = decoder.decode(bytes);
  if (!Buffer.from(text, 'utf8').equals(Buffer.from(bytes))) throw new Error('release manifest is not canonical UTF-8');
  return text;
}

function assertNoDuplicateKeys(text) {
  let index = 0;
  const skip = () => { while (/\s/.test(text[index] || '')) index += 1; };
  const stringEnd = () => {
    if (text[index] !== '"') throw new Error('release JSON string expected');
    const start = index++;
    while (index < text.length) {
      const ch = text[index++];
      if (ch === '\\') { if (index >= text.length) throw new Error('release JSON escape truncated'); index += text[index] === 'u' ? 5 : 1; }
      else if (ch === '"') return index;
      else if (ch < ' ') throw new Error('release JSON control character');
    }
    throw new Error('release JSON string truncated');
  };
  const value = () => {
    skip();
    if (text[index] === '"') { stringEnd(); return; }
    if (text[index] === '{') { object(); return; }
    if (text[index] === '[') { index++; skip(); if (text[index] === ']') { index++; return; } while (true) { value(); skip(); if (text[index] === ']') { index++; return; } if (text[index++] !== ',') throw new Error('release JSON array delimiter'); } }
    const start = index;
    while (index < text.length && !',]}'.includes(text[index]) && ![' ', '\t', '\r', '\n'].includes(text[index])) index += 1;
    if (index === start) throw new Error('release JSON value expected');
  };
  const object = () => {
    index++; skip(); const seen = new Set();
    if (text[index] === '}') { index++; return; }
    while (true) {
      const keyStart = index; stringEnd(); const key = JSON.parse(text.slice(keyStart, index));
      if (seen.has(key)) throw new Error('release JSON duplicate property');
      seen.add(key); skip(); if (text[index++] !== ':') throw new Error('release JSON object delimiter'); value(); skip();
      if (text[index] === '}') { index++; return; }
      if (text[index++] !== ',') throw new Error('release JSON object delimiter'); skip();
    }
  };
  value(); skip(); if (index !== text.length) throw new Error('release JSON trailing data');
}

function exactKeys(object, allowed, required = []) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw new Error('release JSON object expected');
  const keys = Object.keys(object);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !keys.includes(key))) throw new Error('release manifest schema mismatch');
}

export function parseReleaseEnvelope(envelopeText) {
  const bytes = Buffer.isBuffer(envelopeText) ? envelopeText : Buffer.from(String(envelopeText), 'utf8');
  const text = strictUtf8(bytes); assertNoDuplicateKeys(text); const value = JSON.parse(text);
  return parseCanonicalReleaseEnvelope(value);
}

export function verifyReleaseEnvelope(input, { previousSequence = 0, minimumSequence = 0, channel } = {}) {
  previousSequence = Number(input?.previousSequence ?? previousSequence) || 0;
  const result = verifyCanonicalReleaseEnvelope({ manifest_text: input.manifestText ?? input.manifest_text, signature: input.signatureText ?? input.signature, delegation: input.delegation, root_signature: input.rootSignature ?? input.root_signature, key_state: input.key_state, transition_signature: input.transition_signature }, { previousSequence, minimumSequence, channel });
  return { ...result, payload: Buffer.from(result.manifest_text, 'utf8') };
}

export function verifyArtifact(bytes, metadata) {
  const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (data.byteLength !== Number(metadata.bytes)) throw new Error(`release artifact size mismatch: ${metadata.path}`);
  const digest = createHash('sha256').update(data).digest('hex');
  if (digest !== String(metadata.sha256).toLowerCase()) throw new Error(`release artifact digest mismatch: ${metadata.path}`);
  return data;
}

export function readSequence(statePath) {
  if (!existsSync(statePath)) return 0;
  try {
    const text = strictUtf8(readFileSync(statePath)); assertNoDuplicateKeys(text); const state = JSON.parse(text);
    exactKeys(state, new Set(['last_sequence', 'updated_at']), ['last_sequence', 'updated_at']);
    if (!Number.isSafeInteger(state.last_sequence) || state.last_sequence < 0) throw new Error('bad sequence');
    if (typeof state.updated_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(state.updated_at)) throw new Error('bad timestamp');
    const parsed = Date.parse(state.updated_at);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== state.updated_at) throw new Error('bad timestamp');
    return state.last_sequence;
  } catch { throw new Error('BF-RELEASE-STATE-CORRUPT'); }
}

export function readReleaseState(statePath, { allowMissing = false } = {}) {
  let pointerState = false;
  let pointerSlot = null; let pointerGeneration = null;
  if (existsSync(statePath)) {
    try {
      const pointerText = strictUtf8(readFileSync(statePath)); assertNoDuplicateKeys(pointerText); const pointer = JSON.parse(pointerText);
      if (pointer && pointer.active_slot !== undefined) {
        exactKeys(pointer, new Set(['active_slot', 'state_generation']), ['active_slot', 'state_generation']);
        if (!['a', 'b'].includes(pointer.active_slot) || !Number.isSafeInteger(pointer.state_generation) || pointer.state_generation < 1) throw new Error('pointer');
        pointerState = true; pointerSlot = pointer.active_slot; pointerGeneration = pointer.state_generation;
      }
    } catch { throw new Error('BF-RELEASE-STATE-CORRUPT'); }
  }
  const candidates = [...(pointerState ? [] : [statePath]), `${statePath}.a`, `${statePath}.b`].filter((candidate) => existsSync(candidate));
  if (candidates.length === 0) { if (allowMissing) return null; throw new Error('BF-RELEASE-STATE-CORRUPT'); }
  const valid = []; let invalid = false;
  for (const candidate of candidates) {
    try { const text = strictUtf8(readFileSync(candidate)); assertNoDuplicateKeys(text); const state = JSON.parse(text); validateReleaseState(state); valid.push(state); } catch { invalid = true; }
  }
  // A damaged peer is not silently ignored: a torn double-record is an
  // explicit corruption state, never a reason to reset the authority to zero.
  if (invalid || valid.length === 0) throw new Error('BF-RELEASE-STATE-CORRUPT');
  const selected = valid.sort((a, b) => b.state_generation - a.state_generation)[0];
  if (pointerState && (selected.slot !== pointerSlot || selected.state_generation !== pointerGeneration)) throw new Error('BF-RELEASE-STATE-CORRUPT');
  return selected;
}

export function writeSequence(statePath, sequence) {
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('invalid release sequence');
  mkdirSync(path.dirname(statePath), { recursive: true }); const temporary = `${statePath}.${process.pid}.tmp`;
  let handle = null;
  try {
    handle = openSync(temporary, 'w', 0o600);
    const data = Buffer.from(JSON.stringify({ last_sequence: sequence, updated_at: new Date().toISOString() }), 'utf8');
    writeFileSync(handle, data);
    fsyncSync(handle);
    closeSync(handle); handle = null;
    renameSync(temporary, statePath);
  } catch (error) {
    if (handle !== null) { try { closeSync(handle); } catch {} }
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

export function releaseStateChecksum(state) {
  const { state_checksum: _ignoredChecksum, ...unsigned } = state || {};
  return createHash('sha256').update(canonicalReleaseJson(unsigned)).digest('hex');
}

export function writeReleaseState(statePath, state) {
  validateReleaseState(state); const expectedSlot = Number(state.state_generation % 2) === 0 ? 'a' : 'b'; if (state.slot !== expectedSlot) throw new Error('BF-RELEASE-STATE-CORRUPT'); mkdirSync(path.dirname(statePath), { recursive: true }); const temporary = `${statePath}.${process.pid}.tmp`;
  let handle = null;
  try {
    handle = openSync(temporary, 'w', 0o600); const data = Buffer.from(JSON.stringify(state), 'utf8'); writeFileSync(handle, data); fsyncSync(handle); closeSync(handle); handle = null;
    const slot = Number(state.state_generation % 2) === 0 ? `${statePath}.a` : `${statePath}.b`;
    renameSync(temporary, slot);
    const pointer = `${statePath}.${process.pid}.pointer`; writeFileSync(pointer, JSON.stringify({ active_slot: slot.endsWith('.a') ? 'a' : 'b', state_generation: state.state_generation }), { mode: 0o600 }); const pointerFd = openSync(pointer, 'r+'); fsyncSync(pointerFd); closeSync(pointerFd); renameSync(pointer, statePath);
  } catch (error) { if (handle !== null) { try { closeSync(handle); } catch {} } try { unlinkSync(temporary); } catch {} throw error; }
}

export async function stageRelease({ plan, envelopeBytes, installRoot, fetchArtifact, statePath = path.join(installRoot, '.bifrost-release-state.json') }) {
  if (!plan || !isVerifiedReleasePlan(plan) || !Buffer.isBuffer(envelopeBytes)) throw new Error('BF-RELEASE-PLAN');
  const parsedEnvelope = parseReleaseEnvelope(envelopeBytes);
  if (!Buffer.from(canonicalReleaseEnvelopeBytes(parsedEnvelope)).equals(envelopeBytes) || fullReleaseEnvelopeDigest(parsedEnvelope) !== plan.envelope_digest) throw new Error('BF-RELEASE-PLAN');
  const sequence = plan.sequence; const previousState = readReleaseState(statePath, { allowMissing: true }); const previous = previousState?.last_sequence ?? 0;
  if (previousState) {
    if (!Number.isSafeInteger(plan.authority_generation) || plan.authority_generation < previousState.authority_generation || (plan.authority_generation === previousState.authority_generation && plan.authority_digest !== previousState.authority_digest)) throw new Error(plan.authority_generation === previousState.authority_generation ? 'BF-RELEASE-AUTHORITY-EQUIVOCATION' : 'BF-RELEASE-AUTHORITY-ROLLBACK');
    if (plan.authority_generation > previousState.authority_generation && (plan.signing_key_id !== previousState.key_id || plan.signing_key_fingerprint !== previousState.signing_key_fingerprint) && !plan.transition_signature) throw new Error('BF-RELEASE-TRANSITION');
    if (plan.transition_signature && plan.transition_signature.old_key_id !== previousState.key_id) throw new Error('BF-RELEASE-TRANSITION');
  }
  if (sequence === previous && previousState?.last_manifest_digest === plan.manifest_digest) return { sequence, installRoot, backup: null, idempotent: true, plan };
  if (sequence === previous) throw new Error('BF-RELEASE-EQUIVOCATION');
  // A missing state is only initialized by the protected installer.  The
  // ordinary updater has no runtime bootstrap-object escape hatch; it must
  // fail closed until that installer transaction has committed a full state.
  if (!previousState) throw new Error('BF-RELEASE-STATE-CORRUPT');
  if (sequence < previous || sequence < plan.floor) throw new Error('BF-RELEASE-ROLLBACK');
  const parent = path.dirname(installRoot); mkdirSync(parent, { recursive: true });
  const staging = `${installRoot}.staging-${process.pid}-${Date.now()}`; const backup = `${installRoot}.backup-${sequence}-${process.pid}`; let moved = false;
  try {
    mkdirSync(staging, { recursive: true });
    for (const metadata of plan.artifacts) {
      const bytes = verifyArtifact(await fetchArtifact(metadata.path), metadata); const target = path.resolve(staging, metadata.install_path);
      if (!target.startsWith(`${path.resolve(staging)}${path.sep}`)) throw new Error('release install path escapes staging');
      mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, bytes, { mode: 0o755 });
    }
    if (existsSync(installRoot)) { renameSync(installRoot, backup); moved = true; }
    try { renameSync(staging, installRoot); } catch (error) { if (moved && existsSync(backup) && !existsSync(installRoot)) renameSync(backup, installRoot); throw error; }
    try {
      {
        const generation = plan.delegation_generation;
        if (!Number.isSafeInteger(generation) || generation < 1) throw new Error('BF-RELEASE-KEY');
        const next = { last_sequence: sequence, last_manifest_digest: plan.manifest_digest, envelope_digest: plan.envelope_digest, authority_digest: plan.authority_digest, authority_generation: plan.authority_generation, root_key_id: plan.root_key_id, root_fingerprint: plan.root_fingerprint, delegation_generation: generation, key_id: plan.signing_key_id, signing_key_fingerprint: plan.signing_key_fingerprint, channel: plan.channel, floor: plan.floor, state_generation: Number(previousState?.state_generation || 0) + 1, slot: ((Number(previousState?.state_generation || 0) + 1) % 2 === 0 ? 'a' : 'b'), state_checksum: '', updated_at: new Date().toISOString() };
        if (!/^[0-9a-f]{64}$/.test(String(next.envelope_digest || '')) || !/^[0-9a-f]{64}$/.test(String(next.authority_digest || '')) || !Number.isSafeInteger(next.authority_generation) || next.authority_generation < 1 || !/^[0-9a-f]{64}$/.test(String(next.root_fingerprint || ''))) throw new Error('BF-RELEASE-STATE-CORRUPT');
        const { state_checksum: _ignoredChecksum, ...unsignedState } = next;
        next.state_checksum = createHash('sha256').update(canonicalReleaseJson(unsignedState)).digest('hex'); writeReleaseState(statePath, next);
      }
    } catch (error) { rmSync(installRoot, { recursive: true, force: true }); if (moved && existsSync(backup)) renameSync(backup, installRoot); throw error; }
    return { sequence, installRoot, backup };
  } catch (error) { if (existsSync(staging)) rmSync(staging, { recursive: true, force: true }); throw error; }
}
