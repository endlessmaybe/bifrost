import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readProvisionedReleaseRoot } from '../config-contracts/release-root-provision.mjs';

const argument = (name) => { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; };
const input = argument('--input');
const kotlinOutput = argument('--kotlin-output');
const csharpOutput = argument('--csharp-output');
const javascriptOutput = argument('--javascript-output');
const absolute = (value, code) => { if (!value || !path.isAbsolute(value) || value.includes('\0')) throw new Error(code); return value; };

function kotlinString(value) {
  return JSON.stringify(value).replace(/\\u2028|\\u2029/g, (match) => match === '\\u2028' ? '\\u2028' : '\\u2029');
}

try {
  const rootFile = absolute(input, 'BF-KEYS-PATH');
  const root = readProvisionedReleaseRoot(rootFile, { testOnly: process.argv.includes('--test-only') });
  const pem = root.public_key_pem.trim();
  if (kotlinOutput) {
    const out = absolute(kotlinOutput, 'BF-KEYS-OUTPUT');
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, `package com.bifrost.client\n\n/** Generated only from an explicit offline ceremony artifact. */\ninternal object ReleaseTrustBinding {\n    const val TRUST_ROOT_KEY_ID = ${kotlinString(root.key_id)}\n    val TRUST_ROOT_PEM: String? = ${kotlinString(pem)}\n    const val TRUST_ROOT_PROVISIONED = true\n    val TRUST_ROOT_FINGERPRINT: String? = ${kotlinString(root.fingerprint)}\n    const val BUILD_MARKER = ${kotlinString(process.argv.includes('--test-only') ? 'TEST-ONLY-RELEASE-TRUST-BINDING' : 'CEREMONY-RELEASE-TRUST-BINDING')}\n}\n`, 'utf8');
  }
  if (csharpOutput) {
    const out = absolute(csharpOutput, 'BF-KEYS-OUTPUT');
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, `namespace Bifrost.Release;\n\n/** Generated only from an explicit offline ceremony artifact. */\ninternal static class ReleaseTrustBinding\n{\n    internal const string TrustRootKeyId = ${JSON.stringify(root.key_id)};\n    internal const string TrustRootPem = ${JSON.stringify(pem)};\n    internal const bool TrustRootProvisioned = true;\n    internal const string TrustRootFingerprint = ${JSON.stringify(root.fingerprint)};\n    internal const string BuildMarker = ${JSON.stringify(process.argv.includes('--test-only') ? 'TEST-ONLY-RELEASE-TRUST-BINDING' : 'CEREMONY-RELEASE-TRUST-BINDING')};\n}\n`, 'utf8');
  }
  if (javascriptOutput) {
    const out = absolute(javascriptOutput, 'BF-KEYS-OUTPUT');
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, `// Generated only from an explicit offline ceremony artifact.\nexport const COMPILED_RELEASE_TRUST_ROOT = Object.freeze(${JSON.stringify({ key_id: root.key_id, purpose: root.purpose, algorithm: root.algorithm, public_key_pem: pem, fingerprint: root.fingerprint, provenance: 'compiled-trust-binding', status: process.argv.includes('--test-only') ? 'TEST-ONLY' : 'CEREMONY-PROVISIONED' }, null, 2)});\n`, 'utf8');
  }
  process.stdout.write(JSON.stringify({ key_id: root.key_id, purpose: root.purpose, algorithm: root.algorithm, fingerprint: root.fingerprint }) + '\n');
} catch (error) {
  process.stderr.write(`${error?.message || 'BF-KEYS-PROVISION'}\n`);
  process.exitCode = 1;
}
