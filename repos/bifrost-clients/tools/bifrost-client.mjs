#!/usr/bin/env node
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, createSecretKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rootDir = process.env.BIFROST_ROOT || path.resolve(repoDir, '..', '..');
const controlUrl = process.env.BIFROST_CONTROL_URL || 'http://127.0.0.1:17880';
const nodeUrl = process.env.BIFROST_NODE_URL || 'http://127.0.0.1:17881';
// The isolated PowerShell E2E harness opts into the same loopback and
// idempotency headers a browser/client integration normally supplies.  This
// explicit TEST-ONLY switch is never enabled by a normal client invocation.
const e2eTestMode = process.env.BIFROST_E2E_TEST === '1';
const stateDir = path.join(rootDir, 'runtime', 'client-sim');
mkdirSync(stateDir, { recursive: true });
const statePath = path.join(stateDir, 'device.json');

const b64 = (v) => Buffer.from(v).toString('base64url');
const fromB64 = (v) => Buffer.from(v, 'base64url');
const sha256 = (v) => createHash('sha256').update(v).digest('hex');
const stableStringify = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(stableStringify).join(',')}]` : `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
const messageForSession = ({ challenge, timestamp, nonce, requestDigest }) => `${challenge}|${timestamp}|${nonce}|${requestDigest}`;

function aesDecrypt(envelope, key) {
  const decipher = createDecipheriv('aes-256-gcm', createSecretKey(key), fromB64(envelope.iv));
  decipher.setAuthTag(fromB64(envelope.tag));
  return Buffer.concat([decipher.update(fromB64(envelope.ciphertext)), decipher.final()]);
}

function decryptPackage(envelope, privatePem, signingPem) {
  const signature = envelope.signature;
  const unsigned = { ...envelope }; delete unsigned.signature;
  if (!verify(null, Buffer.from(stableStringify(unsigned)), createPublicKey(signingPem), fromB64(signature))) throw new Error('配置签名验证失败');
  const recipient = createPrivateKey(privatePem);
  const ephemeral = createPublicKey({ key: fromB64(envelope.ephemeral_public_key), format: 'der', type: 'spki' });
  const shared = diffieHellman({ privateKey: recipient, publicKey: ephemeral });
  const key = Buffer.from(hkdfSync('sha256', shared, fromB64(envelope.salt), Buffer.from('bifrost-config-v1'), 32));
  return JSON.parse(aesDecrypt(envelope, key).toString('utf8'));
}

async function api(base, route, options = {}) {
  const testHeaders = e2eTestMode && base === controlUrl && route === '/v1/enrollment/redeem'
    ? { Origin: base, 'X-Bifrost-Idempotency-Key': 'TEST-ONLY-client-enroll' }
    : {};
  const response = await fetch(`${base}${route}`, { ...options, headers: { 'content-type': 'application/json', ...testHeaders, ...(options.headers || {}) } });
  const json = await response.json();
  if (!response.ok) throw new Error(`${json.error?.code || response.status}: ${json.error?.message || '请求失败'}`);
  return json;
}

function loadState() { if (!existsSync(statePath)) throw new Error('尚未登记设备，请先运行 enroll'); return JSON.parse(readFileSync(statePath, 'utf8')); }
function saveState(state) { writeFileSync(statePath, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 }); }
function readInvite() { const file = process.env.BIFROST_INVITE_FILE || path.join(rootDir, 'runtime', 'control', 'dev-invite.txt'); if (!existsSync(file)) throw new Error(`邀请码文件不存在：${file}`); return readFileSync(file, 'utf8').trim(); }

async function enroll() {
  const invite = process.argv[3] || readInvite();
  const signing = generateKeyPairSync('ed25519'); const encryption = generateKeyPairSync('x25519');
  const state = {
    // The protocol device-id grammar is lower-case.  Keep the historical
    // shape for normal clients, while the isolated E2E switch uses a
    // deterministic lower-case hex suffix so synthetic enrollment can never
    // fail because random base64 happened to contain an uppercase byte.
    device_id: e2eTestMode ? `sim-${sha256(randomBytes(10)).slice(0, 20)}` : `sim-${b64(randomBytes(10))}`,
    platform: process.env.BIFROST_SIM_PLATFORM || 'windows',
    signing_private_key_pem: signing.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    encryption_private_key_pem: encryption.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    signing_public_key: signing.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    encryption_public_key: encryption.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
  };
  const result = await api(controlUrl, '/v1/enrollment/redeem', { method: 'POST', body: JSON.stringify({ invite_code: invite, platform: state.platform, device_id: state.device_id, signing_public_key: state.signing_public_key, encryption_public_key: state.encryption_public_key, key_level: 'software' }) });
  state.account_id = result.account_id; state.public_id = result.public_id; state.recovery_delivery = result.recovery_delivery || null; state.config_version = result.config_version; state.config_package = result.config_package; state.config = decryptPackage(result.config_package, state.encryption_private_key_pem, readFileSync(path.join(rootDir, 'secrets', 'config-signing-public.pem'), 'utf8')); saveState(state);
  console.log(JSON.stringify({ ok: true, public_id: state.public_id, device_id: state.device_id, recovery_delivery: Boolean(state.recovery_delivery), config_version: state.config_version, state_file: statePath }, null, 2));
}

async function session() {
  const state = loadState(); const challenge = await api(nodeUrl, '/edge/v1/challenge', { method: 'POST', body: JSON.stringify({ device_id: state.device_id }) }); const timestamp = Date.now(); const nonce = b64(randomBytes(16)); const requestDigest = sha256('bifrost-client-session'); const signature = sign(null, Buffer.from(messageForSession({ challenge: challenge.challenge, timestamp, nonce, requestDigest })), createPrivateKey(state.signing_private_key_pem)); const result = await api(nodeUrl, '/edge/v1/session', { method: 'POST', body: JSON.stringify({ device_id: state.device_id, challenge: challenge.challenge, timestamp, nonce, request_digest: requestDigest, signature: b64(signature) }) }); state.session_token = result.session_token; state.session_expires_at = result.expires_at; saveState(state); console.log(JSON.stringify({ ok: true, node_id: result.node_id, expires_at: result.expires_at }, null, 2));
}

async function probe() { const state = loadState(); if (!state.session_token || Date.parse(state.session_expires_at || 0) <= Date.now()) await session(); const current = loadState(); const result = await api(nodeUrl, '/edge/v1/probe', { headers: { 'x-bifrost-session': current.session_token } }); console.log(JSON.stringify(result, null, 2)); }
function showConfig() { const state = loadState(); const c = state.config; console.log(JSON.stringify({ schema_version: c.schema_version, config_version: c.config_version, account: c.account, sources: c.sources.map((s) => ({ code: s.code, display_name: s.display_name, candidates: s.candidates.map((x) => x.label) })), countries: c.countries, routing: c.routing, core_policy: c.core_policy }, null, 2)); }

const command = process.argv[2] || 'help';
try { if (command === 'enroll') await enroll(); else if (command === 'session') await session(); else if (command === 'probe') await probe(); else if (command === 'show-config') showConfig(); else { console.log('用法：node tools/bifrost-client.mjs enroll [邀请码]\n      node tools/bifrost-client.mjs session\n      node tools/bifrost-client.mjs probe\n      node tools/bifrost-client.mjs show-config'); process.exitCode = 1; } } catch (error) { console.error(`Bifrost 客户端：${error.message}`); process.exitCode = 1; }
